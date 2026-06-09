package telemetry

import (
	"context"
	"fmt"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestInit_NoEndpoint(t *testing.T) {
	providers, err := Init(context.Background(), Config{})
	if err != nil {
		t.Fatalf("Init with empty endpoint should not error: %v", err)
	}
	defer func() { _ = providers.Shutdown(context.Background()) }()

	// TracerProvider should be nil (no-op).
	if providers.tp != nil {
		t.Error("expected nil TracerProvider when no endpoint configured")
	}

	// Shutdown on no-op should be safe.
	if err := providers.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown on no-op providers should not error: %v", err)
	}
}

func TestInit_WithEndpoint(t *testing.T) {
	// Use a bogus endpoint — the exporter is created but won't connect in tests.
	providers, err := Init(context.Background(), Config{
		OTLPEndpoint: "localhost:4318",
		ServiceName:  "starfly-test",
	})
	if err != nil {
		t.Fatalf("Init with endpoint should not error: %v", err)
	}
	defer func() { _ = providers.Shutdown(context.Background()) }()

	if providers.tp == nil {
		t.Fatal("expected non-nil TracerProvider when endpoint configured")
	}

	// Global tracer provider should be set to our SDK provider.
	tp := otel.GetTracerProvider()
	if _, ok := tp.(*sdktrace.TracerProvider); !ok {
		t.Errorf("global TracerProvider should be *sdktrace.TracerProvider, got %T", tp)
	}
}

func TestSpanError(t *testing.T) {
	providers, err := Init(context.Background(), Config{
		OTLPEndpoint: "localhost:4318",
		ServiceName:  "starfly-test",
	})
	if err != nil {
		t.Fatalf("Init error: %v", err)
	}
	defer func() { _ = providers.Shutdown(context.Background()) }()

	tracer := otel.Tracer("test")
	_, span := tracer.Start(context.Background(), "test-span")

	testErr := fmt.Errorf("something went wrong")
	SpanError(span, testErr)

	span.End()
}

func TestInit_DefaultServiceName(t *testing.T) {
	providers, err := Init(context.Background(), Config{
		OTLPEndpoint: "localhost:4318",
	})
	if err != nil {
		t.Fatalf("Init should not error: %v", err)
	}
	defer func() { _ = providers.Shutdown(context.Background()) }()

	if providers.tp == nil {
		t.Fatal("expected non-nil TracerProvider")
	}
}
