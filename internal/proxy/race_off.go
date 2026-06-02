//go:build !race

package proxy

import "time"

// hotPathBound is the maximum elapsed time allowed for
// TestAuditExport_HotPathNeverBlocks's 500-iteration loop. The
// invariant is "doesn't serialize behind the 30s wedged webhook"
// — 2s is strict enough to catch a real block without false-positives
// on an unloaded runner.
const hotPathBound = 2 * time.Second
