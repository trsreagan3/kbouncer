// Command kbouncer is the v1.0 deprecation shim for the renamed
// `kbounce` binary.
//
// The Bounce-suite rename (2026-05-17, [[bounce-suite-rename]])
// shortened the binary name from `kbouncer` to `kbounce`. Existing
// scripts + tutorial steps + container images that invoke `kbouncer`
// keep working for v1.0 — this shim prints a one-line deprecation
// warning to stderr and then runs the exact same code path the new
// binary would. The shim is removed in v1.1.
//
// All command wiring lives in `internal/cli`; this shim does NOT
// re-declare any subcommands. Calling cli.Main() guarantees the two
// binaries can never drift.
package main

import (
	"fmt"
	"os"

	"github.com/trsreagan3/kbouncer/internal/cli"
)

func main() {
	// One-line deprecation notice. stderr so it doesn't poison stdout
	// for any pipe consumers (kbouncer's MCP mode reserves stdout for
	// the JSON-RPC stream — the shim must respect that invariant).
	fmt.Fprintln(os.Stderr,
		"WARN: 'kbouncer' is deprecated; use 'kbounce'. Both work in v1.0; "+
			"the 'kbouncer' shim is removed in v1.1.")
	// Patch argv[0] so cobra prints `kbounce` in usage strings even
	// when the user invoked us via the legacy name. Keeps help output
	// pointing at the canonical binary.
	if len(os.Args) > 0 {
		os.Args[0] = "kbounce"
	}
	cli.Main()
}
