package cli

import (
	"bytes"
	"strings"
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

// TestPrintAnomalyBanner_BlockModeArmed is the Fix-2 regression guard:
// when mode=block, the startup banner MUST say "enforcement ARMED" and
// MUST NOT say "does not block" (the old incorrect wording). For
// alert/disabled modes the neutral/observe wording must be preserved.
//
// Pre-fix: the banner always printed "surfaces a neutral signal for review,
// does not block by default" — even when mode=block was actively denying
// requests. Operators had no honest indication that enforcement was live.
// Post-fix: mode=block emits "enforcement ARMED: anomalous requests will
// be denied (403)"; alert mode emits the neutral observe-only wording.
func TestPrintAnomalyBanner_BlockModeArmed(t *testing.T) {
	t.Run("block mode — ARMED banner, no 'does not block' copy", func(t *testing.T) {
		var buf bytes.Buffer
		printAnomalyBanner(&buf, "block", "medium")
		got := buf.String()
		if !strings.Contains(got, "enforcement ARMED") {
			t.Errorf("Fix-2 REGRESSION: mode=block banner missing 'enforcement ARMED'; got: %q", got)
		}
		if strings.Contains(got, "does not block") {
			t.Errorf("Fix-2 REGRESSION: mode=block banner still says 'does not block'; got: %q", got)
		}
		if strings.Contains(got, "neutral signal for review") {
			t.Errorf("Fix-2 REGRESSION: mode=block banner still says 'neutral signal for review'; got: %q", got)
		}
	})

	t.Run("alert mode — observe-only banner, no ARMED copy", func(t *testing.T) {
		var buf bytes.Buffer
		printAnomalyBanner(&buf, "alert", "medium")
		got := buf.String()
		if strings.Contains(got, "enforcement ARMED") {
			t.Errorf("alert banner must not say 'enforcement ARMED'; got: %q", got)
		}
		if strings.Contains(got, "will be denied (403)") {
			t.Errorf("alert banner must not say denials happen; got: %q", got)
		}
		if !strings.Contains(got, "does not block") {
			t.Errorf("alert banner must say 'does not block'; got: %q", got)
		}
	})

	t.Run("block+high — ARMED banner + FP warning both present", func(t *testing.T) {
		var buf bytes.Buffer
		printAnomalyBanner(&buf, "block", "high")
		got := buf.String()
		if !strings.Contains(got, "enforcement ARMED") {
			t.Errorf("block+high banner missing 'enforcement ARMED'; got: %q", got)
		}
		if !strings.Contains(got, "WARNING") {
			t.Errorf("block+high banner missing high-sensitivity WARNING; got: %q", got)
		}
	})
}
