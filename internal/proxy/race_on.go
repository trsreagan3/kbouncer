//go:build race

package proxy

import "time"

// hotPathBound is the maximum elapsed time allowed for
// TestAuditExport_HotPathNeverBlocks's 500-iteration loop under the
// race detector. Race instrumentation adds ~10-20x overhead per
// synchronisation operation, so 500 iterations legitimately take
// longer than 2s on a loaded CI runner even when the hot path is
// correctly non-blocking. 15s is still well below the 30s wedge and
// proves the enqueue never serialises behind the wedged worker.
const hotPathBound = 15 * time.Second
