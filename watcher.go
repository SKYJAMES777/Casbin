package casbin

// Watcher defines the interface for policy change watchers.
type Watcher interface {
	SetUpdateCallback(func(string)) error
	// ... other methods
}

// WatcherEx extends Watcher with additional capabilities.
type WatcherEx interface {
	Watcher
	// ... extended methods
}

// SetWatcher sets the watcher for the enforcer.
func (e *Enforcer) SetWatcher(watcher Watcher) error {
	e.watcher = watcher
	return watcher.SetUpdateCallback(func(s string) {
		// Invalidate cache if CachedEnforcer
		if ce, ok := e.(*CachedEnforcer); ok {
			ce.InvalidateCache()
		}
		// Reload policy from adapter
		e.LoadPolicy()
	})
}
