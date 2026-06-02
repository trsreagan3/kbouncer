package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFlagOrEnv_AuditEventsToken proves the #380 env-var fallback for
// --audit-events-token: the env var is used when the flag is empty, and
// the flag wins when both are set (so the token never has to appear in
// `ps` / process listings).
func TestFlagOrEnv_AuditEventsToken(t *testing.T) {
	t.Run("env used when flag empty", func(t *testing.T) {
		t.Setenv(envAuditEventsTokenVar, "tok-from-env")
		got := flagOrEnv("", envAuditEventsTokenVar)
		assert.Equal(t, "tok-from-env", got)
	})

	t.Run("flag wins over env", func(t *testing.T) {
		t.Setenv(envAuditEventsTokenVar, "tok-from-env")
		got := flagOrEnv("tok-from-flag", envAuditEventsTokenVar)
		assert.Equal(t, "tok-from-flag", got)
	})

	t.Run("empty when neither set", func(t *testing.T) {
		t.Setenv(envAuditEventsTokenVar, "")
		got := flagOrEnv("", envAuditEventsTokenVar)
		assert.Equal(t, "", got)
	})
}

// TestFlagOrEnv_UpstreamCABundle proves the #379 env-var fallback for
// --upstream-ca-bundle shares the exact same flag-wins precedence.
func TestFlagOrEnv_UpstreamCABundle(t *testing.T) {
	t.Run("env used when flag empty", func(t *testing.T) {
		t.Setenv(envUpstreamCABundleVar, "/etc/kube/ca.pem")
		got := flagOrEnv("", envUpstreamCABundleVar)
		assert.Equal(t, "/etc/kube/ca.pem", got)
	})

	t.Run("flag wins over env", func(t *testing.T) {
		t.Setenv(envUpstreamCABundleVar, "/etc/kube/ca.pem")
		got := flagOrEnv("/flag/ca.pem", envUpstreamCABundleVar)
		assert.Equal(t, "/flag/ca.pem", got)
	})
}
