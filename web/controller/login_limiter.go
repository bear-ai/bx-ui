package controller

import (
	"sync"
	"time"
)

type loginAttempt struct {
	count        int
	windowStart  time.Time
	blockedUntil time.Time
	lastSeen     time.Time
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]loginAttempt
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: make(map[string]loginAttempt)}
}

func (l *loginLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.attempts[key]
	if now.Before(a.blockedUntil) {
		return false
	}
	if a.windowStart.IsZero() || now.Sub(a.windowStart) > 10*time.Minute {
		delete(l.attempts, key)
		return true
	}
	return a.count < 5
}

func (l *loginLimiter) failure(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.attempts) >= 4096 {
		var oldestKey string
		var oldestTime time.Time
		for candidate, attempt := range l.attempts {
			if now.After(attempt.blockedUntil) && now.Sub(attempt.lastSeen) > 15*time.Minute {
				delete(l.attempts, candidate)
				continue
			}
			if oldestKey == "" || attempt.lastSeen.Before(oldestTime) {
				oldestKey, oldestTime = candidate, attempt.lastSeen
			}
		}
		if len(l.attempts) >= 4096 && oldestKey != "" {
			delete(l.attempts, oldestKey)
		}
	}
	a := l.attempts[key]
	if a.windowStart.IsZero() || now.Sub(a.windowStart) > 10*time.Minute {
		a = loginAttempt{windowStart: now}
	}
	a.count++
	a.lastSeen = now
	if a.count >= 5 {
		a.blockedUntil = now.Add(15 * time.Minute)
	}
	l.attempts[key] = a
}

func (l *loginLimiter) success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}
