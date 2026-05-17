// Command kbounce is the local Kubernetes API-call gating proxy.
//
// Run it as a sidecar to kubectl / Helm / a coding agent that points
// at it instead of the real kube-apiserver; kbounce parses each call,
// matches it against gating rules, records the decision, and either
// forwards to the real apiserver or returns 403 to the client (when
// running in transparent mode).
//
// The binary was renamed from `kbouncer` to `kbounce` in the
// 2026-05-17 bounce-suite rename ([[bounce-suite-rename]]). The
// `kbouncer` binary is preserved as a deprecation-warning shim for
// v1.0 (see cmd/kbouncer/) and removed in v1.1. All command wiring
// lives in internal/cli so the two binaries can never drift.
package main

import "github.com/trsreagan3/kbouncer/internal/cli"

func main() { cli.Main() }
