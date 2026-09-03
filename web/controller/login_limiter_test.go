package controller

import (
	"testing"
	"time"
)

func TestLoginLimiterBlocksAndResets(t *testing.T) {
	limiter := newLoginLimiter()
	now := time.Now()
	for i := 0; i < 5; i++ {
		if !limiter.allow("192.0.2.1", now) {
			t.Fatalf("attempt %d was blocked too early", i+1)
		}
		limiter.failure("192.0.2.1", now)
	}
	if limiter.allow("192.0.2.1", now) {
		t.Fatal("sixth login attempt was not blocked")
	}
	limiter.success("192.0.2.1")
	if !limiter.allow("192.0.2.1", now) {
		t.Fatal("successful login did not reset limiter")
	}
}
