// Copyright 2020 The Casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package casbin

import (
	"sync"
	"sync/atomic"

	"github.com/Knetic/govaluate"
)

// CachedEnforcer wraps Enforcer and provides a decision cache.
type CachedEnforcer struct {
	*Enforcer
	// cache is a map from request string to decision (allow/deny).
	cache map[string]bool
	// mu protects the cache map.
	mu sync.RWMutex
	// enableCache indicates whether caching is enabled.
	enableCache bool
	// invalidated is an atomic flag to signal cache invalidation without full lock.
	invalidated int32
}

// NewCachedEnforcer creates a CachedEnforcer.
func NewCachedEnforcer(params ...interface{}) (*CachedEnforcer, error) {
	e, err := NewEnforcer(params...)
	if err != nil {
		return nil, err
	}

	ce := &CachedEnforcer{
		Enforcer:    e,
		cache:       make(map[string]bool),
		enableCache: true,
	}

	// Hook into policy mutation methods
	ce.wrapPolicyMethods()

	// Hook into LoadPolicy
	ce.wrapLoadPolicy()

	// Hook into watcher events
	ce.wrapWatcher()

	return ce, nil
}

// EnableCache enables or disables the cache.
func (ce *CachedEnforcer) EnableCache(enable bool) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.enableCache = enable
	if !enable {
		ce.cache = make(map[string]bool)
	}
}

// Enforce decides whether a subject is allowed to perform an action.
func (ce *CachedEnforcer) Enforce(rvals ...interface{}) (bool, error) {
	if !ce.enableCache {
		return ce.Enforcer.Enforce(rvals...)
	}

	// Check invalidation flag first (lock-free read)
	if atomic.LoadInt32(&ce.invalidated) == 1 {
		ce.mu.Lock()
		ce.cache = make(map[string]bool)
		atomic.StoreInt32(&ce.invalidated, 0)
		ce.mu.Unlock()
	}

	key := ce.getCacheKey(rvals...)

	ce.mu.RLock()
	res, ok := ce.cache[key]
	ce.mu.RUnlock()

	if ok {
		return res, nil
	}

	res, err := ce.Enforcer.Enforce(rvals...)
	if err != nil {
		return false, err
	}

	ce.mu.Lock()
	ce.cache[key] = res
	ce.mu.Unlock()

	return res, nil
}

// getCacheKey generates a string key from the request values.
func (ce *CachedEnforcer) getCacheKey(rvals ...interface{}) string {
	key := ""
	for _, v := range rvals {
		key += "/" + toString(v)
	}
	return key
}

// invalidateCache marks the cache as invalid and clears it lazily.
func (ce *CachedEnforcer) invalidateCache() {
	atomic.StoreInt32(&ce.invalidated, 1)
}

// wrapPolicyMethods overrides policy mutation methods to invalidate cache.
func (ce *CachedEnforcer) wrapPolicyMethods() {
	// AddPolicy
	origAddPolicy := ce.Enforcer.AddPolicy
	ce.Enforcer.AddPolicy = func(params ...interface{}) (bool, error) {
		res, err := origAddPolicy(params...)
		if err == nil && res {
			ce.invalidateCache()
		}
		return res, err
	}

	// AddPolicies
	origAddPolicies := ce.Enforcer.AddPolicies
	ce.Enforcer.AddPolicies = func(rules [][]string) (bool, error) {
		res, err := origAddPolicies(rules)
		if err == nil && res {
			ce.invalidateCache()
		}
		return res, err
	}

	// RemovePolicy
	origRemovePolicy := ce.Enforcer.RemovePolicy
	ce.Enforcer.RemovePolicy = func(params ...interface{}) (bool, error) {
		res, err := origRemovePolicy(params...)
		if err == nil && res {
			ce.invalidateCache()
		}
		return res, err
	}

	// RemovePolicies
	origRemovePolicies := ce.Enforcer.RemovePolicies
	ce.Enforcer.RemovePolicies = func(rules [][]string) (bool, error) {
		res, err := origRemovePolicies(rules)
		if err == nil && res {
			ce.invalidateCache()
		}
		return res, err
	}

	// UpdatePolicy
	origUpdatePolicy := ce.Enforcer.UpdatePolicy
	ce.Enforcer.UpdatePolicy = func(oldRule, newRule []string) (bool, error) {
		res, err := origUpdatePolicy(oldRule, newRule)
		if err == nil && res {
			ce.invalidateCache()
		}
		return res, err
	}

	// UpdatePolicies
	origUpdatePolicies := ce.Enforcer.UpdatePolicies
	ce.Enforcer.UpdatePolicies = func(oldRules, newRules [][]string) (bool, error) {
		res, err := origUpdatePolicies(oldRules, newRules)
		if err == nil && res {
			ce.invalidateCache()
		}
		return res, err
	}

	// RemoveFilteredPolicy
	origRemoveFilteredPolicy := ce.Enforcer.RemoveFilteredPolicy
	ce.Enforcer.RemoveFilteredPolicy = func(fieldIndex int, fieldValues ...string) (bool, error) {
		res, err := origRemoveFilteredPolicy(fieldIndex, fieldValues...)
		if err == nil && res {
			ce.invalidateCache()
		}
		return res, err
	}
}

// wrapLoadPolicy overrides LoadPolicy to invalidate cache.
func (ce *CachedEnforcer) wrapLoadPolicy() {
	origLoadPolicy := ce.Enforcer.LoadPolicy
	ce.Enforcer.LoadPolicy = func() error {
		err := origLoadPolicy()
		if err == nil {
			ce.invalidateCache()
		}
		return err
	}
}

// wrapWatcher hooks into the watcher to invalidate cache on update.
func (ce *CachedEnforcer) wrapWatcher() {
	if ce.Enforcer.GetWatcher() == nil {
		return
	}

	// For WatcherEx, we can set a callback
	if w, ok := ce.Enforcer.GetWatcher().(WatcherEx); ok {
		w.SetUpdateCallback(func(string) {
			ce.invalidateCache()
		})
	} else if w, ok := ce.Enforcer.GetWatcher().(Watcher); ok {
		// For basic Watcher, we wrap the callback if already set
		// Since we cannot override the callback directly, we assume the watcher
		// will call a function we can hook into. In practice, we set a new callback.
		w.SetUpdateCallback(func(string) {
			ce.invalidateCache()
		})
	}
}

// toString converts an interface to string for cache key.
func toString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case int:
		return string(rune(val))
	case float64:
		return string(rune(int(val)))
	default:
		return ""
	}
}
