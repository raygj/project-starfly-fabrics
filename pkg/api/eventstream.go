package api

import (
	"sync"
)

// FabricEvent represents a real-time event from the fabric.
type FabricEvent struct {
	ID        string  `json:"id"`
	Timestamp string  `json:"timestamp"`          // RFC3339Nano
	Type      string  `json:"type"`               // "exchange", "denial", "caep", "signal", "soul"
	Subject   string  `json:"subject"`
	Target    string  `json:"target,omitempty"`
	Duration  float64 `json:"duration_ms,omitempty"`
	Result    string  `json:"result"`             // "ok", "denied", "error"
	Detail    string  `json:"detail,omitempty"`
	UnitID    string  `json:"unit_id"`
}

// defaultBufferSize is the max channel buffer per subscriber.
const defaultBufferSize = 1000

// EventBroadcaster fans out FabricEvents to multiple SSE clients.
type EventBroadcaster struct {
	mu          sync.RWMutex
	subscribers map[chan FabricEvent]struct{}
	bufferSize  int
}

// NewEventBroadcaster creates a new EventBroadcaster with the default buffer size.
func NewEventBroadcaster() *EventBroadcaster {
	return &EventBroadcaster{
		subscribers: make(map[chan FabricEvent]struct{}),
		bufferSize:  defaultBufferSize,
	}
}

// Broadcast sends an event to all subscribers using a non-blocking send.
// If a subscriber's channel buffer is full, the event is dropped for that
// subscriber — slow clients lose events but never block the broadcaster.
func (b *EventBroadcaster) Broadcast(event FabricEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch := range b.subscribers {
		select {
		case ch <- event:
		default:
			// Subscriber buffer full; drop the event for this client.
		}
	}
}

// Subscribe registers a new subscriber and returns a buffered channel
// that will receive broadcast events.
func (b *EventBroadcaster) Subscribe() chan FabricEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan FabricEvent, b.bufferSize)
	b.subscribers[ch] = struct{}{}
	return ch
}

// Unsubscribe removes a subscriber and closes its channel.
func (b *EventBroadcaster) Unsubscribe(ch chan FabricEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
}

// SubscriberCount returns the current number of active subscribers.
func (b *EventBroadcaster) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return len(b.subscribers)
}
