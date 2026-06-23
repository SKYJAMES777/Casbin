package casbin

import (
	"sync"
)

// CachedEnforcer wraps Enforcer and adds a decision cache.
type CachedEnforcer struct {
	*Enforcer
	cache     map[string]bool
	cacheLock sync.RWMutex
}

// NewCachedEnforcer creates a CachedEnforcer.
func NewCachedEnforcer(params ...interface{}) (*CachedEnforcer, error) {
	e, err := NewEnforcer(params...)
	if err != nil {
		return nil, err
	}
	ce := &CachedEnforcer{
		Enforcer: e,
		cache:    make(map[string]bool),
	}
	// Hook into policy mutation methods
	ce.addPolicyFunc = ce.addPolicyWithCacheInvalidation
	ce.addPoliciesFunc = ce.addPoliciesWithCacheInvalidation
	ce.removePolicyFunc = ce.removePolicyWithCacheInvalidation
	ce.removePoliciesFunc = ce.removePoliciesWithCacheInvalidation
	ce.updatePolicyFunc = ce.updatePolicyWithCacheInvalidation
	ce.updatePoliciesFunc = ce.updatePoliciesWithCacheInvalidation
	ce.removeFilteredPolicyFunc = ce.removeFilteredPolicyWithCacheInvalidation
	ce.loadPolicyFunc = ce.loadPolicyWithCacheInvalidation
	return ce, nil
}

// EnforceWithCache checks authorization with caching.
func (ce *CachedEnforcer) EnforceWithCache(rvals ...interface{}) (bool, error) {
	key := generateKey(rvals...)
	ce.cacheLock.RLock()
	result, ok := ce.cache[key]
	ce.cacheLock.RUnlock()
	if ok {
		return result, nil
	}
	result, err := ce.Enforcer.Enforce(rvals...)
	if err != nil {
		return false, err
	}
	ce.cacheLock.Lock()
	ce.cache[key] = result
	ce.cacheLock.Unlock()
	return result, nil
}

// InvalidateCache clears the entire decision cache.
func (ce *CachedEnforcer) InvalidateCache() {
	ce.cacheLock.Lock()
	ce.cache = make(map[string]bool)
	ce.cacheLock.Unlock()
}

// Internal functions to hook into policy mutations

func (ce *CachedEnforcer) addPolicyWithCacheInvalidation(sec string, ptype string, rule []string) (bool, error) {
	ok, err := ce.Enforcer.addPolicyFunc(sec, ptype, rule)
	if err == nil && ok {
		ce.InvalidateCache()
	}
	return ok, err
}

func (ce *CachedEnforcer) addPoliciesWithCacheInvalidation(sec string, ptype string, rules [][]string) (bool, error) {
	ok, err := ce.Enforcer.addPoliciesFunc(sec, ptype, rules)
	if err == nil && ok {
		ce.InvalidateCache()
	}
	return ok, err
}

func (ce *CachedEnforcer) removePolicyWithCacheInvalidation(sec string, ptype string, rule []string) (bool, error) {
	ok, err := ce.Enforcer.removePolicyFunc(sec, ptype, rule)
	if err == nil && ok {
		ce.InvalidateCache()
	}
	return ok, err
}

func (ce *CachedEnforcer) removePoliciesWithCacheInvalidation(sec string, ptype string, rules [][]string) (bool, error) {
	ok, err := ce.Enforcer.removePoliciesFunc(sec, ptype, rules)
	if err == nil && ok {
		ce.InvalidateCache()
	}
	return ok, err
}

func (ce *CachedEnforcer) updatePolicyWithCacheInvalidation(sec string, ptype string, oldRule, newRule []string) (bool, error) {
	ok, err := ce.Enforcer.updatePolicyFunc(sec, ptype, oldRule, newRule)
	if err == nil && ok {
		ce.InvalidateCache()
	}
	return ok, err
}

func (ce *CachedEnforcer) updatePoliciesWithCacheInvalidation(sec string, ptype string, oldRules, newRules [][]string) (bool, error) {
	ok, err := ce.Enforcer.updatePoliciesFunc(sec, ptype, oldRules, newRules)
	if err == nil && ok {
		ce.InvalidateCache()
	}
	return ok, err
}

func (ce *CachedEnforcer) removeFilteredPolicyWithCacheInvalidation(sec string, ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	ok, err := ce.Enforcer.removeFilteredPolicyFunc(sec, ptype, fieldIndex, fieldValues...)
	if err == nil && ok {
		ce.InvalidateCache()
	}
	return ok, err
}

func (ce *CachedEnforcer) loadPolicyWithCacheInvalidation() error {
	err := ce.Enforcer.loadPolicyFunc()
	if err == nil {
		ce.InvalidateCache()
	}
	return err
}

// generateKey creates a cache key from request values.
func generateKey(rvals ...interface{}) string {
	// Simple concatenation; in production use a more robust method
	key := ""
	for _, v := range rvals {
		key += fmt.Sprintf("%v|", v)
	}
	return key
}

// Ensure fmt is imported
var _ = fmt.Sprintf
