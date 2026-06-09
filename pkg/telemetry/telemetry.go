// Package telemetry provides OpenTelemetry tracing initialization for Starfly.
//
// When an OTLP endpoint is configured, Init creates a TracerProvider with an
// OTLP/HTTP exporter. When no endpoint is set, tracing is a no-op — existing
// Prometheus metrics continue to work unchanged.
package telemetry

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Config holds telemetry settings.
type Config struct {
	OTLPEndpoint string // OTLP HTTP endpoint (e.g. "localhost:4318"). Empty = no-op.
	ServiceName  string // OTel service name (default: "starfly").
}

// Providers holds initialized OTel providers and a Shutdown func for cleanup.
type Providers struct {
	tp *sdktrace.TracerProvider
}

// Shutdown drains and shuts down the TracerProvider. Safe to call on a no-op
// Providers (returns nil).
func (p *Providers) Shutdown(ctx context.Context) error {
	if p.tp == nil {
		return nil
	}
	return p.tp.Shutdown(ctx)
}

// Init initializes the global OTel TracerProvider and TextMapPropagator.
// If cfg.OTLPEndpoint is empty, a no-op provider is used and no exporter is
// created — tracing calls become zero-cost stubs.
func Init(ctx context.Context, cfg Config) (*Providers, error) {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "starfly"
	}

	// Always set W3C TraceContext + Baggage propagator so traceparent headers
	// are parsed even when the provider is no-op.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if cfg.OTLPEndpoint == "" {
		slog.Info("telemetry: no OTLP endpoint configured, tracing is no-op")
		return &Providers{}, nil
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.ServiceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating OTel resource: %w", err)
	}

	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(cfg.OTLPEndpoint),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("creating OTLP trace exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	slog.Info("telemetry: OTel tracing initialized", "endpoint", cfg.OTLPEndpoint)

	return &Providers{tp: tp}, nil
}

// SpanError records an error on a span and sets its status to Error.
// Use this instead of the 2-line span.RecordError + span.SetStatus pattern.
func SpanError(span trace.Span, err error) {
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}
