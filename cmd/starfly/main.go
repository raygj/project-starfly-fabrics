// Package main is the entrypoint for the Starfly Fabrics binary.
//
// Starfly is a Kubernetes-native NHI identity broker and shared signals
// aggregator. It is not an IDP — it is an identity router that lets
// workloads and AI agents cross trust boundaries safely.
//
// Usage:
//
//	starfly [flags]
//	starfly --dev          # Development mode (embedded NATS, dev unlock)
//	starfly --config FILE  # Production mode with config file
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"net/http"

	"github.com/dgraph-io/badger/v4"

	"github.com/starfly-fabrics/starfly/pkg/api"
	"github.com/starfly-fabrics/starfly/pkg/audit"
	"github.com/starfly-fabrics/starfly/pkg/boot"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/exchange"
	"github.com/starfly-fabrics/starfly/pkg/federation"
	"github.com/starfly-fabrics/starfly/pkg/identity"
	agentidentity "github.com/starfly-fabrics/starfly/pkg/identity/agent"
	"github.com/starfly-fabrics/starfly/pkg/identity/apikey"
	"github.com/starfly-fabrics/starfly/pkg/identity/aws"
	"github.com/starfly-fabrics/starfly/pkg/identity/azure"
	"github.com/starfly-fabrics/starfly/pkg/identity/gcp"
	"github.com/starfly-fabrics/starfly/pkg/identity/kerberos"
	"github.com/starfly-fabrics/starfly/pkg/identity/mtls"
	"github.com/starfly-fabrics/starfly/pkg/identity/oauth2"
	"github.com/starfly-fabrics/starfly/pkg/identity/oidc"
	"github.com/starfly-fabrics/starfly/pkg/identity/saml"
	"github.com/starfly-fabrics/starfly/pkg/identity/spiffe"
	"github.com/starfly-fabrics/starfly/pkg/jwks"
	"github.com/starfly-fabrics/starfly/pkg/mcp"
	"github.com/starfly-fabrics/starfly/pkg/lifecycle"
	"github.com/starfly-fabrics/starfly/pkg/lock"
	"github.com/starfly-fabrics/starfly/pkg/operator"
	"github.com/starfly-fabrics/starfly/pkg/signals"
	"github.com/starfly-fabrics/starfly/pkg/policy"
	"github.com/starfly-fabrics/starfly/pkg/secrets"
	"github.com/starfly-fabrics/starfly/pkg/soul"
	"github.com/starfly-fabrics/starfly/pkg/store"
	starflysync "github.com/starfly-fabrics/starfly/pkg/sync"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
)

// Version is set at build time via -ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func main() {
	// Route subcommands before flag.Parse() to avoid flag conflicts.
	if len(os.Args) >= 2 && os.Args[1] == "operator" {
		os.Exit(runOperator(os.Args[2:]))
	}
	if len(os.Args) >= 3 && os.Args[1] == "lock" && os.Args[2] == "migrate" {
		os.Exit(runLockMigrate(os.Args[3:]))
	}
	if len(os.Args) >= 3 && os.Args[1] == "soul" && os.Args[2] == "diff" {
		os.Exit(runSoulDiff(os.Args[3:]))
	}
	if len(os.Args) >= 2 && os.Args[1] == "doc" {
		os.Exit(runDoc(os.Args[2:]))
	}
	if len(os.Args) >= 2 && os.Args[1] == "status" {
		os.Exit(runStatus(os.Args[2:]))
	}
	if len(os.Args) >= 2 && os.Args[1] == "watch" {
		os.Exit(runWatch(os.Args[2:]))
	}
	if len(os.Args) >= 3 && os.Args[1] == "federation" && os.Args[2] == "signals" {
		os.Exit(runFederationSignals(os.Args[3:]))
	}

	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	// ── Parse flags ──────────────────────────────────────────────────
	var (
		configPath string
		devMode    bool
		listenAddr string
	)
	flag.StringVar(&configPath, "config", "", "path to config file (default: none)")
	flag.BoolVar(&devMode, "dev", false, "enable development mode (dev lock, relaxed defaults)")
	flag.StringVar(&listenAddr, "listen-addr", "", "override listen address (e.g. :8693)")
	flag.Parse()

	// ── Boot timer ─────────────────────────────────────────────────
	bootStart := time.Now()

	// ── Load configuration (defaults → file → env) ──────────────────
	stepStart := time.Now()
	cfg, err := core.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Layer 4: CLI flag overrides.
	if listenAddr != "" {
		cfg.ListenAddr = listenAddr
	}

	// Dev mode: only available in binaries built with -tags dev.
	if devMode || cfg.DevMode {
		if !DevModeAvailable {
			return fmt.Errorf("dev mode requested but binary was built without -tags dev; rebuild with: go build -tags dev")
		}
		applyDevMode(cfg)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// ── Configure logger from loaded config ─────────────────────────
	logLevel := parseLogLevel(cfg.LogLevel)
	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: logLevel}
	if cfg.LogFormat == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))

	// ── Generate shared unit ID ───────────────────────────────────
	unitID := core.GenerateUnitID()

	// Derive fabric ID from the primary trust domain.
	fabricID := ""
	if len(cfg.TrustDomains) > 0 {
		fabricID = cfg.TrustDomains[0].Name
	}
	if fabricID == "" {
		fabricID = os.Getenv("STARFLY_FABRIC_ID")
	}
	if fabricID == "" {
		fabricID = "prod"
	}

	// ── Print boot banner ───────────────────────────────────────────
	_, _ = fmt.Fprint(os.Stdout, boot.Banner(boot.BannerConfig{
		Version:  Version,
		FabricID: fabricID,
		UnitID:   unitID,
		Port:     extractPort(cfg.ListenAddr),
	}))
	_, _ = fmt.Fprint(os.Stdout, boot.Step("config loaded", time.Since(stepStart)))

	slog.Debug("starfly starting",
		"version", Version,
		"commit", Commit,
		"build_date", BuildDate,
	)
	slog.Debug("configuration loaded",
		"listen_addr", cfg.ListenAddr,
		"log_level", cfg.LogLevel,
		"dev_mode", cfg.DevMode,
		"lock_type", cfg.Lock.Type,
		"storage_type", cfg.Storage.Type,
		"storage_path", cfg.Storage.Path,
		"policy_bundle", cfg.Policy.BundlePath,
		"trust_domains", len(cfg.TrustDomains),
	)

	// ── Initialize telemetry (OTel tracing) ─────────────────────────
	telemetryProviders, err := telemetry.Init(context.Background(), telemetry.Config{
		OTLPEndpoint: cfg.Telemetry.OTLPEndpoint,
		ServiceName:  "starfly",
	})
	if err != nil {
		return fmt.Errorf("initializing telemetry: %w", err)
	}

	slog.Debug("unit identity generated", "unit_id", unitID)

	// ── Signal-aware context ────────────────────────────────────────
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── Initialize lock provider ────────────────────────────────────
	stepStart = time.Now()
	locker, err := lock.New(cfg.Lock)
	if err != nil {
		_, _ = fmt.Fprint(os.Stdout, boot.Failed("lock opened", err))
		return fmt.Errorf("initializing lock: %w", err)
	}
	lockLabel := fmt.Sprintf("lock opened (%s)", cfg.Lock.Type)
	if cfg.Lock.Type == "dev" {
		_, _ = fmt.Fprint(os.Stdout, boot.StepWarn(lockLabel, time.Since(stepStart), "dev mode"))
		slog.Warn("using DEV lock — data is NOT encrypted, do not use in production")
	} else {
		_, _ = fmt.Fprint(os.Stdout, boot.Step(lockLabel, time.Since(stepStart)))
	}

	// ── Initialize store ────────────────────────────────────────────
	stepStart = time.Now()
	dataStore, err := store.New(cfg.Storage.Path, locker)
	if err != nil {
		_, _ = fmt.Fprint(os.Stdout, boot.Failed("store ready", err))
		return fmt.Errorf("initializing store: %w", err)
	}
	_ = dataStore // passed to engines in later tickets
	_, _ = fmt.Fprint(os.Stdout, boot.Step("store ready", time.Since(stepStart)))

	// ── Initialize audit logger ──────────────────────────────────
	auditor := audit.New(os.Stdout)

	// ── Initialize policy engine ─────────────────────────────────
	stepStart = time.Now()
	policyEngine := policy.New(auditor, cfg.Policy)
	if err := policyEngine.LoadBundle(ctx, cfg.Policy.BundlePath); err != nil {
		_, _ = fmt.Fprint(os.Stdout, boot.Failed("policy loaded", err))
		slog.Warn("loading policy bundle", "error", err, "path", cfg.Policy.BundlePath)
	} else {
		_, _ = fmt.Fprint(os.Stdout, boot.Step("policy loaded", time.Since(stepStart)))
	}

	// ── Initialize JWKS resolver (shared cache for all providers) ────
	stepStart = time.Now()
	jwksCache := jwks.New(jwks.Config{Prefetch: true})
	defer jwksCache.Close()

	// Prefetch trust domain JWKS URLs.
	var jwksIssuers []string
	for _, td := range cfg.TrustDomains {
		if td.Enabled && td.JWKSURL != "" {
			jwksIssuers = append(jwksIssuers, td.JWKSURL)
		}
	}
	if len(jwksIssuers) > 0 {
		if err := jwksCache.Prefetch(ctx, jwksIssuers); err != nil {
			slog.Warn("JWKS prefetch", "error", err)
		}
		_, _ = fmt.Fprint(os.Stdout, boot.Step("jwks cache warmed", time.Since(stepStart)))
	}

	// ── Initialize identity providers + registry (ADR-0006) ─────
	stepStart = time.Now()
	k8sProvider, err := identity.New(ctx, cfg.TrustDomains, cfg.DevMode)
	if err != nil {
		return fmt.Errorf("initializing k8s identity provider: %w", err)
	}

	spiffeProvider, err := spiffe.NewProvider(
		spiffe.WithTrustDomains(cfg.TrustDomains),
		spiffe.WithJWKSResolver(jwksCache),
		spiffe.WithDevMode(cfg.DevMode),
	)
	if err != nil {
		return fmt.Errorf("initializing spiffe provider: %w", err)
	}

	oidcProvider, err := oidc.NewProvider(
		oidc.WithTrustDomains(cfg.TrustDomains),
		oidc.WithJWKSResolver(jwksCache),
		oidc.WithDevMode(cfg.DevMode),
	)
	if err != nil {
		return fmt.Errorf("initializing oidc provider: %w", err)
	}

	kerberosProvider, err := kerberos.NewProvider(
		kerberos.WithTrustDomains(cfg.TrustDomains),
		kerberos.WithDevMode(cfg.DevMode),
	)
	if err != nil {
		return fmt.Errorf("initializing kerberos provider: %w", err)
	}

	samlProvider, err := saml.NewProvider(
		saml.WithTrustDomains(cfg.TrustDomains),
		saml.WithDevMode(cfg.DevMode),
	)
	if err != nil {
		return fmt.Errorf("initializing saml provider: %w", err)
	}

	mtlsProvider, err := mtls.NewProvider(
		mtls.WithTrustDomains(cfg.TrustDomains),
		mtls.WithDevMode(cfg.DevMode),
	)
	if err != nil {
		return fmt.Errorf("initializing mtls provider: %w", err)
	}

	awsProvider, err := aws.NewProvider(
		aws.WithTrustDomains(cfg.TrustDomains),
		aws.WithDevMode(cfg.DevMode),
	)
	if err != nil {
		return fmt.Errorf("initializing aws provider: %w", err)
	}

	gcpProvider, err := gcp.NewProvider(
		gcp.WithTrustDomains(cfg.TrustDomains),
		gcp.WithJWKSResolver(jwksCache),
		gcp.WithDevMode(cfg.DevMode),
	)
	if err != nil {
		return fmt.Errorf("initializing gcp provider: %w", err)
	}

	azureProvider, err := azure.NewProvider(
		azure.WithTrustDomains(cfg.TrustDomains),
		azure.WithJWKSResolver(jwksCache),
		azure.WithDevMode(cfg.DevMode),
	)
	if err != nil {
		return fmt.Errorf("initializing azure provider: %w", err)
	}

	oauth2Provider, err := oauth2.NewProvider(
		oauth2.WithTrustDomains(cfg.TrustDomains),
		oauth2.WithJWKSResolver(jwksCache),
		oauth2.WithDevMode(cfg.DevMode),
	)
	if err != nil {
		return fmt.Errorf("initializing oauth2 provider: %w", err)
	}

	apikeyProvider, err := apikey.NewProvider(
		apikey.WithDevMode(cfg.DevMode),
	)
	if err != nil {
		return fmt.Errorf("initializing apikey provider: %w", err)
	}

	identityProvider := identity.NewRegistry()
	identityProvider.Register("k8s-sa", k8sProvider)
	identityProvider.Register("spiffe-svid", spiffeProvider)
	identityProvider.Register("oidc", oidcProvider)
	identityProvider.Register("kerberos", kerberosProvider)
	identityProvider.Register("saml", samlProvider)
	identityProvider.Register("mtls", mtlsProvider)
	identityProvider.Register("aws-sts", awsProvider)
	identityProvider.Register("gcp-wif", gcpProvider)
	identityProvider.Register("azure-mi", azureProvider)
	identityProvider.Register("oauth2", oauth2Provider)
	identityProvider.Register("api-key", apikeyProvider)
	_, _ = fmt.Fprint(os.Stdout, boot.Step("providers registered (11)", time.Since(stepStart)))

	// ── Initialize sync bus (NATS signal flash) ──────────────────
	stepStart = time.Now()
	primaryTrustDomain := ""
	if len(cfg.TrustDomains) > 0 {
		primaryTrustDomain = cfg.TrustDomains[0].Name
	}
	if primaryTrustDomain == "" {
		primaryTrustDomain = fabricID
	}
	syncBus, err := starflysync.New(cfg.NATS, unitID, primaryTrustDomain)
	if err != nil {
		_, _ = fmt.Fprint(os.Stdout, boot.Failed("nats connected", err))
		return fmt.Errorf("initializing sync bus: %w", err)
	}
	if cfg.DevMode {
		_, _ = fmt.Fprint(os.Stdout, boot.StepWarn("nats connected", time.Since(stepStart), "dev mode"))
	} else {
		_, _ = fmt.Fprint(os.Stdout, boot.Step("nats connected", time.Since(stepStart)))
	}

	// ── Replay missed signals from stream window ────────────────────
	stepStart = time.Now()
	replayStart := time.Now().Add(-72 * time.Hour)
	replayedSignals, err := syncBus.Replay(ctx, replayStart)
	if err != nil {
		slog.Warn("replaying signals from stream", "error", err)
	} else {
		_, _ = fmt.Fprint(os.Stdout, boot.Step(
			fmt.Sprintf("signals replayed (%d)", len(replayedSignals)),
			time.Since(stepStart),
		))
		slog.Debug("replayed signals from stream", "count", len(replayedSignals))
		for _, sig := range replayedSignals {
			slog.Debug("replayed signal",
				"type", sig.Type,
				"source", sig.Source,
				"timestamp", sig.Timestamp,
			)
		}
	}

	// ── Subscribe to live signals ───────────────────────────────────
	signalHandler := func(_ context.Context, sig *core.Signal) error {
		slog.Info("received signal",
			"type", sig.Type,
			"source", sig.Source,
			"timestamp", sig.Timestamp,
		)
		return nil
	}
	if err := syncBus.Subscribe(ctx, ">", signalHandler); err != nil {
		slog.Warn("subscribing to signals", "error", err)
	}

	// ── Initialize signal engine (SSF/CAEP) ──────────────────────
	revocationIndex := signals.NewRevocationIndex()

	signalTransmitter, err := signals.NewTransmitter(
		signals.WithTransmitterIssuer(unitID),
		signals.WithTransmitterAuditor(auditor),
		signals.WithTransmitterSyncBus(syncBus, unitID),
	)
	if err != nil {
		return fmt.Errorf("initializing signal transmitter: %w", err)
	}
	// onSignalBroadcast is wired to the SSE broadcaster after the API server is created.
	var onSignalBroadcast func(eventType, subject, result string)
	signalReceiver := signals.NewReceiver(
		signals.WithReceiverPolicy(policyEngine),
		signals.WithReceiverRevocation(revocationIndex),
		signals.WithReceiverAuditor(auditor),
		signals.WithReceiverSyncBus(syncBus, unitID),
		signals.WithReceiverDevMode(cfg.DevMode),
		signals.WithReceiverOnSignal(func(eventType, subject, result string) {
			if onSignalBroadcast != nil {
				onSignalBroadcast(eventType, subject, result)
			}
		}),
	)

	// ── Initialize exchange engine ───────────────────────────────
	stepStart = time.Now()
	encryptionKeyStore := secrets.NewInMemoryKeyStore()
	staticSecretsPath := os.Getenv("STARFLY_STATIC_SECRETS_PATH")
	if staticSecretsPath == "" {
		staticSecretsPath = "/etc/starfly/static-secrets.yaml"
	}
	secretRegistry, err := secrets.RegistryFromOptionalFile(staticSecretsPath)
	if err != nil {
		return fmt.Errorf("loading static secrets: %w", err)
	}
	// revocationErrorCounter is wired to metrics after the API server creates them.
	var revocationErrorCounter func()
	// onExchangeBroadcast is wired to the SSE broadcaster after the API server is created.
	var onExchangeBroadcast func(subject, target, result string, dur time.Duration)
	exchangeOpts := []exchange.Option{
		exchange.WithDevMode(cfg.DevMode),
		exchange.WithSyncBus(syncBus, unitID),
		exchange.WithRevocationChecker(revocationIndex),
		exchange.WithOnRevocationError(func() {
			if revocationErrorCounter != nil {
				revocationErrorCounter()
			}
		}),
		exchange.WithOnExchange(func(subject, target, result string, dur time.Duration) {
			if onExchangeBroadcast != nil {
				onExchangeBroadcast(subject, target, result, dur)
			}
		}),
		exchange.WithEncryptionKeyStore(encryptionKeyStore),
	}
	if secretRegistry != nil {
		exchangeOpts = append(exchangeOpts, exchange.WithSecretSource(secretRegistry))
		slog.Info("static secret source configured", "path", staticSecretsPath)
	}
	exchangeEngine, err := exchange.New(identityProvider, policyEngine, auditor, exchangeOpts...)
	if err != nil {
		_, _ = fmt.Fprint(os.Stdout, boot.Failed("exchange engine ready", err))
		return fmt.Errorf("initializing exchange engine: %w", err)
	}
	_, _ = fmt.Fprint(os.Stdout, boot.Step("exchange engine ready", time.Since(stepStart)))

	// ── Initialize lifecycle worker (Temporal, optional) ─────────
	var lifecycleClient *lifecycle.Client
	var lifecycleWorker *lifecycle.Worker
	if cfg.Lifecycle.Enabled {
		lcActivities := lifecycle.NewActivities(
			exchangeEngine,
			signalTransmitter,
			revocationIndex,
			unitID,
		)
		lcCfg := lifecycle.ClientConfig{
			HostPort:  cfg.Lifecycle.Temporal.HostPort,
			Namespace: cfg.Lifecycle.Temporal.Namespace,
		}
		var lcErr error
		lifecycleClient, lifecycleWorker, lcErr = lifecycle.StartFromConfig(lcCfg, lcActivities)
		if lcErr != nil {
			slog.Warn("lifecycle worker failed to start — continuing without lifecycle automation",
				"error", lcErr,
			)
		} else if lifecycleWorker != nil {
			// Register rotation workflow + activities with the exchange engine's keyring.
			rotActs := lifecycle.NewRotationActivities(exchangeEngine.Keyring(), lcActivities)
			lifecycleWorker.RegisterWorkflow(lifecycle.RotationWorkflow)
			lifecycleWorker.RegisterActivity(rotActs.GenerateAndPublishKey)
			lifecycleWorker.RegisterActivity(rotActs.SwapSigningKey)
			lifecycleWorker.RegisterActivity(rotActs.VerifyNewKey)
			lifecycleWorker.RegisterActivity(rotActs.RemoveKey)
			lifecycleWorker.RegisterActivity(rotActs.RollbackToKey)

			// Register compliance scan workflow + activities.
			lifecycleWorker.RegisterWorkflow(lifecycle.ComplianceScanWorkflow)

			if err := lifecycleWorker.Start(); err != nil {
				slog.Warn("lifecycle worker failed to start — continuing without lifecycle automation",
					"error", err,
				)
				lifecycleClient.Close()
				lifecycleClient = nil
				lifecycleWorker = nil
			}
		}
	} else {
		slog.Info("lifecycle worker disabled (lifecycle.enabled=false)")
	}

	// ── Initialize agent identity provider ────────────────────────
	agentProvider, err := agentidentity.NewProvider(
		agentidentity.WithTrustDomains(cfg.TrustDomains),
		agentidentity.WithAuditor(auditor),
		agentidentity.WithSyncBus(syncBus),
		agentidentity.WithDevMode(cfg.DevMode),
	)
	if err != nil {
		return fmt.Errorf("initializing agent identity provider: %w", err)
	}

	// ── Initialize API server ────────────────────────────────────
	stepStart = time.Now()
	mcpRegistry := mcp.NewRegistry()
	apiServer := api.New(cfg, Version, exchangeEngine,
		api.WithJWKS(exchangeEngine),
		api.WithUnitID(unitID),
		api.WithAgentIdentity(agentProvider),
		api.WithSignalReceiver(signalReceiver),
		api.WithSignalTransmitter(signalTransmitter),
		api.WithMCPRegistry(mcpRegistry),
		api.WithMCPDeps(jwksCache, revocationIndex, policyEngine, auditor),
		api.WithRevocationIndex(revocationIndex),
		api.WithEncryptionKeyStore(encryptionKeyStore),
		api.WithTrustDomains(cfg.TrustDomains),
	)

	// Wire the revocation error counter now that metrics are available.
	revocationErrorCounter = func() {
		apiServer.Metrics().RevocationCheckErrorsTotal.Inc()
	}

	// Wire the SSE event broadcaster so exchange and signal events stream to connected clients.
	onExchangeBroadcast = func(subject, target, result string, dur time.Duration) {
		apiServer.Broadcaster().Broadcast(api.FabricEvent{
			ID:        core.GenerateUnitID(),
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Type:      "exchange",
			Subject:   subject,
			Target:    target,
			Detail:    fmt.Sprintf("result=%s duration=%s", result, dur.Round(time.Microsecond)),
		})
	}
	onSignalBroadcast = func(eventType, subject, result string) {
		apiServer.Broadcaster().Broadcast(api.FabricEvent{
			ID:        core.GenerateUnitID(),
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Type:      "caep",
			Subject:   subject,
			Detail:    fmt.Sprintf("event=%s result=%s", eventType, result),
		})
	}

	go func() {
		slog.Debug("starting HTTP server", "addr", cfg.ListenAddr)
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server error", "error", err)
		}
	}()

	if apiServer.TLSEnabled() {
		go func() {
			slog.Debug("starting mTLS server", "addr", cfg.TLS.ListenAddr)
			if err := apiServer.ListenAndServeTLS(); err != nil && err != http.ErrServerClosed {
				slog.Error("mtls server error", "error", err)
			}
		}()
	} else {
		slog.Debug("mTLS listener disabled")
	}
	_, _ = fmt.Fprint(os.Stdout, boot.Step("metrics serving", time.Since(stepStart)))

	// ── Set startup gauges ──────────────────────────────────────────
	// Each pod is one fabric unit. Report itself as healthy at boot.
	apiServer.Metrics().FabricUnitsTotal.Set(1)
	apiServer.Metrics().FabricUnitsHealthy.Set(1)
	apiServer.Metrics().FabricTrustDomainsTotal.Set(float64(len(cfg.TrustDomains)))

	// ── Start Soul Keeper ────────────────────────────────────────────
	soulAnchorPath := "/var/lib/starfly/soul"
	if envPath := os.Getenv("STARFLY_SOUL_ANCHOR_PATH"); envPath != "" {
		soulAnchorPath = envPath
	}
	soulKeeper, soulErr := soul.NewKeeper(soul.KeeperConfig{
		FabricID: fabricID,
		Anchor:   soul.NewFSAnchor(soulAnchorPath),
		RevIndex: revocationIndex,
		Bus:      syncBus,
		Interval: 60 * time.Second,
		UnitID:   unitID,
		Metrics:  apiServer.Metrics(),
		OnSnapshot: func(fid string, seq uint64) {
			apiServer.Broadcaster().Broadcast(api.FabricEvent{
				ID:        core.GenerateUnitID(),
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				Type:      "soul",
				Subject:   fid,
				Detail:    fmt.Sprintf("sequence=%d", seq),
			})
		},
	})
	if soulErr != nil {
		slog.Warn("soul keeper init failed — soul metrics will stay at 0", "error", soulErr)
	} else {
		soulDomains := make([]soul.TrustDomainSpec, len(cfg.TrustDomains))
		for i, td := range cfg.TrustDomains {
			soulDomains[i] = soul.TrustDomainSpec{
				Name:    td.Name,
				Enabled: td.Enabled,
				JWKSURL: td.JWKSURL,
				Issuer:  td.Issuer,
			}
		}
		soulKeeper.SetIdentity(nil, soulDomains)
		soulKeeper.Start(ctx)
	}

	opOpts := []operator.InProcessOption{
		operator.WithKeyring(exchangeEngine.Keyring()),
		operator.WithTransmitter(signalTransmitter),
		operator.WithRevocationIndex(revocationIndex),
		operator.WithRegistry(identityProvider),
		operator.WithTrustDomains(cfg.TrustDomains),
	}
	if soulKeeper != nil {
		opOpts = append(opOpts, operator.WithKeeper(soulKeeper))
	}
	opConn := operator.NewInProcessConnection(fabricID, opOpts...)
	embeddedOperatorCfg := operator.EmbeddedConfig{
		Namespace:  os.Getenv("STARFLY_NAMESPACE"),
		Connection: opConn,
	}

	// ── Start federation relay + syncer (cross-fabric signal forwarding) ──
	// Only started when at least one peer is configured. ADR-0031.
	if len(cfg.Federation.Peers) > 0 {
		peers := make([]federation.PeerSignalConfig, len(cfg.Federation.Peers))
		for i, p := range cfg.Federation.Peers {
			peers[i] = federation.PeerSignalConfig{
				FabricID:   p.FabricID,
				Endpoint:   p.Endpoint,
				Transport:  p.Transport,
				MTLSSecret: p.MTLSSecret,
			}
		}
		sgCfg := federation.SignalGatewayConfig{Peers: peers}
		relay := federation.NewRelay(sgCfg, federation.WithRelayMetrics(apiServer.Metrics()))
		inbound := federation.NewInboundHandler(peers)
		syncer := federation.NewSyncer(sgCfg, revocationIndex, federation.WithSyncerMetrics(apiServer.Metrics()))
		gateway := federation.NewCompositeGateway(relay, inbound, syncer)
		if err := gateway.SubscribeToSyncBus(ctx, syncBus, fabricID); err != nil {
			slog.Warn("federation gateway sync bus subscription failed", "error", err)
		}
		if err := syncer.Start(); err != nil {
			slog.Warn("federation syncer start failed", "error", err)
		}
		slog.Info("federation gateway started", "peers", len(peers))
	}

	_, _ = fmt.Fprint(os.Stdout, boot.Ready(time.Since(bootStart)))

	startEmbeddedOperatorIfEnabled(ctx, embeddedOperatorCfg)

	// ── Block until shutdown signal ─────────────────────────────────
	<-ctx.Done()
	slog.Info("shutdown signal received, draining...")

	// ── Graceful shutdown with 30s drain timeout ────────────────────
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Soul keeper: final snapshot before shutdown.
	if soulKeeper != nil {
		if err := soulKeeper.Stop(); err != nil {
			slog.Error("soul keeper stop error", "error", err)
		}
	}

	// Lifecycle worker stops first — let in-progress activities finish.
	if lifecycleWorker != nil {
		lifecycleWorker.Stop()
	}
	if lifecycleClient != nil {
		lifecycleClient.Close()
	}

	if err := apiServer.ShutdownMTLS(shutdownCtx); err != nil {
		slog.Error("error shutting down mTLS server", "error", err)
	}
	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("error shutting down HTTP server", "error", err)
	}
	if err := syncBus.Drain(); err != nil {
		slog.Error("error draining sync bus", "error", err)
	}
	if err := dataStore.Close(); err != nil {
		slog.Error("error closing store", "error", err)
	}
	if err := auditor.Close(); err != nil {
		slog.Error("error closing auditor", "error", err)
	}
	if err := telemetryProviders.Shutdown(shutdownCtx); err != nil {
		slog.Error("error shutting down telemetry", "error", err)
	}
	// TODO: Close lock

	slog.Info("starfly shutdown complete")
	return nil
}

func runLockMigrate(args []string) int {
	fs := flag.NewFlagSet("lock migrate", flag.ExitOnError)
	var (
		configPath string
		fromType   string
		fromKey    string
		toType     string
		toKey      string
	)
	fs.StringVar(&configPath, "config", "", "path to config file")
	fs.StringVar(&fromType, "from-type", "", "source lock type (dev, awskms)")
	fs.StringVar(&fromKey, "from-key", "", "source lock key (e.g. KMS ARN)")
	fs.StringVar(&toType, "to-type", "", "destination lock type (dev, awskms)")
	fs.StringVar(&toKey, "to-key", "", "destination lock key (e.g. KMS ARN)")
	if err := fs.Parse(args); err != nil {
		slog.Error("parsing flags", "error", err)
		return 1
	}

	if fromType == "" || toType == "" {
		slog.Error("--from-type and --to-type are required")
		return 1
	}

	// Load config for storage path.
	cfg, err := core.LoadConfig(configPath)
	if err != nil {
		slog.Error("loading config", "error", err)
		return 1
	}

	src, err := lock.NewFromTypeAndKey(fromType, fromKey)
	if err != nil {
		slog.Error("creating source locker", "error", err)
		return 1
	}
	dst, err := lock.NewFromTypeAndKey(toType, toKey)
	if err != nil {
		slog.Error("creating destination locker", "error", err)
		return 1
	}

	// Open Badger directly (not through store, to avoid version side-effects).
	opts := badger.DefaultOptions(cfg.Storage.Path).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		slog.Error("opening database", "error", err)
		return 1
	}
	defer func() {
		if err := db.Close(); err != nil {
			slog.Error("closing database", "error", err)
		}
	}()

	auditor := audit.New(os.Stdout)
	defer func() {
		if err := auditor.Close(); err != nil {
			slog.Error("closing auditor", "error", err)
		}
	}()

	unitID := core.GenerateUnitID()
	logger := slog.Default()

	result, err := lock.Migrate(context.Background(), db, src, dst, auditor, unitID, logger)
	if err != nil {
		slog.Error("migration failed", "error", err)
		return 1
	}

	slog.Info("lock migration complete",
		"keys", result.KeyCount,
		"duration", result.Duration,
	)
	return 0
}

// extractPort pulls the port number from an address string like ":8693"
// or "0.0.0.0:8693". Returns the port without the leading colon.
func extractPort(addr string) string {
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		return addr[idx+1:]
	}
	return addr
}

// parseLogLevel converts a string level to slog.Level.
func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
