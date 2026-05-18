package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecurityLakeBucketRequiresRegion pins the parse-time validation:
// passing --security-lake-bucket without --security-lake-region is a
// misconfiguration and must fail-fast with a clear error.
func TestSecurityLakeBucketRequiresRegion(t *testing.T) {
	_, _, _, err := buildAuditManager(
		t.Context(),
		"", false,
		"", "", 1, false,
		"generic", "", "IamJitBouncer",
		"",
		0,
		"",
		"my-bucket", "", "", 0,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--security-lake-region",
		"the error must name the missing flag")
}

// TestSecurityLakeRegionRequiresBucket pins the symmetric validation:
// passing region without bucket has no effect and must fail-fast.
func TestSecurityLakeRegionRequiresBucket(t *testing.T) {
	_, _, _, err := buildAuditManager(
		t.Context(),
		"", false,
		"", "", 1, false,
		"generic", "", "IamJitBouncer",
		"",
		0,
		"",
		"", "us-east-1", "", 0,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--security-lake-bucket",
		"the error must name the missing flag")
}

// TestRunCmdRegistersSecurityLakeFlags confirms the four
// --security-lake-* flags are registered on `kbounce run`.
// Cross-product parity (ibounce + dbounce) ships the same names.
func TestRunCmdRegistersSecurityLakeFlags(t *testing.T) {
	cmd := newRunCmd()
	flags := cmd.Flags()
	for _, name := range []string{
		"security-lake-bucket",
		"security-lake-region",
		"security-lake-role-arn",
		"security-lake-rotation-seconds",
	} {
		require.NotNil(t, flags.Lookup(name),
			"--%s flag must be registered", name)
	}
}
