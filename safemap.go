package main

import (
	"context"
	"maps"
	"sync"
	"time"
)

type safeMap[K comparable, V any] struct {
	m map[K]V

	mu sync.RWMutex
}

func newSafeMap[K comparable, V any]() *safeMap[K, V] {
	return &safeMap[K, V]{
		m: make(map[K]V),
	}
}

func (sf *safeMap[K, V]) len() int {
	return len(sf.m)
}

func (sf *safeMap[K, V]) load(k K) (V, bool) {
	sf.mu.RLock()
	defer sf.mu.RUnlock()

	v, ok := sf.m[k]

	return v, ok
}

func (sf *safeMap[K, V]) store(k K, v V) {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	sf.m[k] = v
}

func (sf *safeMap[K, V]) delete(k K) {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	delete(sf.m, k)
}

func (sf *safeMap[K, V]) upsert(k K, f func(old V) V) {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	sf.m[k] = f(sf.m[k])
}

func (sf *safeMap[K, V]) safeRange(f func(k K, v V)) {
	sf.mu.RLock()
	defer sf.mu.RUnlock()

	for k, v := range sf.m {
		f(k, v)
	}
}

func (sf *safeMap[K, V]) compact() {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	sf.m = maps.Clone(sf.m)
}

func (sf *safeMap[K, V]) periodicCompact(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sf.compact()
		}
	}
}
