// Package mcpinstall implements the `kbounce mcp install-*` commands +
// the `show-config` / `list-tools` helpers.
//
// Cross-product parity: this package mirrors dbounce's
// internal/mcpinstall + iam-jit's `ibounce mcp install-*` shape so
// an operator who learned one product gets the same shape on the
// other ([[cross-product-agent-parity]]). The MCP server entrypoint
// command differs (`kbounce` vs `dbounce` vs `ibounce`); the
// tool-name prefix differs (`kbounce_*` vs `dbounce_*` vs
// `ibounce_*`); everything else — flag names, path detection logic,
// atomic write pattern, `show-config` output structure,
// `list-tools` output format, agent-attribution env vars — is the
// same shape on all three sides.
//
// Audit-cadence notes (per [[audit-cadence-discipline]]):
//
//   (a) Merge-with-existing-config: every install path Reads the existing
//       config first, merges the kbounce entry into mcpServers, and
//       writes the WHOLE document back. Other agents' MCP server entries
//       are preserved; double-add of `kbounce` is avoided (the entry
//       under the kbounce key is REPLACED, not appended).
//
//   (b) Atomic write: writeJSONAtomic + writeBytesAtomic write to a
//       sibling tempfile in the SAME directory as the target, then
//       os.Rename. Cross-device tempfiles (e.g. /tmp on a different
//       filesystem) would break the rename guarantee. The tempfile is
//       cleaned up on any error before os.Rename. A partial overwrite
//       of the operator's existing config is therefore impossible.
//
//   (c) No elevation: every default path detection lands in the
//       operator's $HOME (or %APPDATA% on Windows). No /etc paths, no
//       sudo, no shell-elevation. An install that lands outside $HOME
//       is only possible if the operator passed --path pointing
//       somewhere they own.
package mcpinstall

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// ServerName is the key under mcpServers we install / merge.
// Matches the ServerName in internal/mcp so an agent that lists its
// MCP servers sees "kbounce".
const ServerName = "kbounce"

// ServerCommand is the binary the generated MCP config tells the agent
// to spawn. Stays "kbounce" (the post-rename canonical) so the install
// snippets line up with the documented binary name in the README.
const ServerCommand = "kbounce"

// ServerArgs are the argv passed to ServerCommand. We use the canonical
// `mcp serve` form (not bare `mcp`) so the generated agent config does
// not depend on the back-compat "bare `kbounce mcp` runs the server"
// shape. If we ever change that bare-default later, configs already
// written to operator laptops keep working.
var ServerArgs = []string{"mcp", "serve"}

// DefaultAgentName is the agent-attribution name stamped into the
// generated MCP entry when the caller doesn't pass one explicitly.
// "claude-code" matches the install-claude-code default; the cursor +
// codex installers override per [[cross-product-agent-parity]] + #308
// + #375 / §A35b (cross-bouncer agent-attribution env-var injection).
// Mirrors ibounce's _ibounce_mcp_config_dict(agent_name_default=...)
// default + dbounce's mcpinstall.DefaultAgentName.
const DefaultAgentName = "claude-code"

// AgentNameEnvVar is the env-var key the agent runtime reads to stamp
// the X-Agent-Name HTTP header. The KBOUNCE_ prefix keeps the env-var
// namespace consistent across the Bounce suite (IBOUNCE_AGENT_NAME /
// DBOUNCE_AGENT_NAME ship the same shape on the sibling products).
const AgentNameEnvVar = "KBOUNCE_AGENT_NAME"

// AgentSessionIDEnvVar is the env-var key the agent runtime reads to
// stamp the X-Agent-Session-Id HTTP header. Deliberately left EMPTY
// in the static snippet — the agent runtime mints a fresh UUID v7 per
// session. kbouncer itself never reads this env var; it's a hint to
// the AGENT runtime, not configuration kbouncer consumes.
const AgentSessionIDEnvVar = "KBOUNCE_AGENT_SESSION_ID"

// agentNameForClient returns the agent-name attribution value to
// stamp for the given install-* client. Names match ibounce + dbounce
// per [[cross-product-agent-parity]]:
//
//	claude-code  → "claude-code"
//	cursor       → "cursor"
//	codex        → "openai-codex"
//	devin        → "devin"
//	anything else → DefaultAgentName ("claude-code")
//
// Exposed (lowercase) for the cli wrapper; the JSON-merge path uses
// it to vary per-installer without duplicating snippet construction.
func agentNameForClient(clientName string) string {
	switch clientName {
	case "claude-code":
		return "claude-code"
	case "cursor":
		return "cursor"
	case "codex":
		return "openai-codex"
	case "devin":
		return "devin"
	default:
		return DefaultAgentName
	}
}

// ServerConfigDict is the canonical JSON snippet shape any MCP client
// ingests to use kbounce as an MCP server (stdio transport). Centralized
// so show-config, install-claude-code, install-cursor, install-codex,
// and any future installer emit the SAME shape. Mirrors the
// _ibounce_mcp_config_dict() helper on the ibounce side. Defaults
// agent-name attribution to DefaultAgentName; see
// ServerConfigDictForAgent for per-client overrides.
func ServerConfigDict() map[string]any {
	return ServerConfigDictForAgent(DefaultAgentName)
}

// ServerConfigDictForAgent is the per-agent variant of
// ServerConfigDict. The env block carries the #308 / §A35b agent-
// attribution hints (AgentNameEnvVar + AgentSessionIDEnvVar); the
// session id is deliberately empty in the static snippet because the
// agent runtime mints a fresh UUID v7 per session. kbouncer itself
// never reads these env vars — they're a hint to the AGENT runtime,
// not config kbouncer consumes. See iam-roles/docs/AGENT-ATTRIBUTION.md
// for the per-runtime header-injection patterns.
func ServerConfigDictForAgent(agentName string) map[string]any {
	if agentName == "" {
		agentName = DefaultAgentName
	}
	return map[string]any{
		"mcpServers": map[string]any{
			ServerName: ServerEntryForAgent(agentName),
		},
	}
}

// ServerEntry is the per-server portion of ServerConfigDict — the
// value most clients want to merge into their own existing
// mcpServers map. Uses DefaultAgentName; see ServerEntryForAgent for
// per-client overrides.
func ServerEntry() map[string]any {
	return ServerEntryForAgent(DefaultAgentName)
}

// ServerEntryForAgent is the per-agent variant of ServerEntry. See
// ServerConfigDictForAgent for the env-block design rationale.
func ServerEntryForAgent(agentName string) map[string]any {
	if agentName == "" {
		agentName = DefaultAgentName
	}
	return map[string]any{
		"command": ServerCommand,
		"args":    append([]string{}, ServerArgs...),
		"env": map[string]any{
			// #308 + #375 / §A35b — agent-attribution env-var
			// injection. The agent's MCP host inherits these into the
			// child process; the agent's HTTP client stamps them as
			// X-Agent-Name + X-Agent-Session-Id on every outbound
			// call back through the Bouncers' HTTP-shaped surfaces
			// (gbounce; ibounce's AWS-API proxy mode). The session
			// id is deliberately empty — the runtime mints a UUID
			// v7 per session.
			AgentNameEnvVar:      agentName,
			AgentSessionIDEnvVar: "",
		},
	}
}

// ---------------------------------------------------------------------
// Path detection — per supported client.
// ---------------------------------------------------------------------

// ClaudeCodeConfigCandidates returns the candidate config paths to try,
// in priority order. The installer picks the first that exists; if
// none exist, it falls back to the first candidate (so a fresh install
// still writes somewhere sensible).
//
// Both the Claude Desktop ("claude_desktop_config.json") and the
// Claude Code CLI (~/.claude.json) shapes are JSON objects with a
// top-level `mcpServers` key, so the same merge logic works for both.
func ClaudeCodeConfigCandidates() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var out []string
	switch runtime.GOOS {
	case "darwin":
		out = []string{
			filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, ".config", "claude-code", "mcp.json"),
			filepath.Join(home, ".claude.json"),
		}
	case "linux":
		out = []string{
			filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, ".config", "claude-code", "mcp.json"),
			filepath.Join(home, ".claude.json"),
		}
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			appdata = filepath.Join(home, "AppData", "Roaming")
		}
		out = []string{
			filepath.Join(appdata, "Claude", "claude_desktop_config.json"),
			filepath.Join(home, ".claude.json"),
		}
	default:
		out = []string{filepath.Join(home, ".claude.json")}
	}
	return out
}

// CursorConfigCandidates returns the candidate config paths for Cursor.
// Cursor stores MCP servers in ~/.cursor/mcp.json (global) and accepts
// a workspace-local .cursor/mcp.json. We default to the global one.
func CursorConfigCandidates() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".cursor", "mcp.json"),
	}
}

// CodexConfigCandidates returns the candidate config paths for Codex.
// OpenAI Codex CLI uses TOML config at ~/.codex/config.toml — we do NOT
// attempt to safely merge into TOML (third-party Go TOML libraries
// would balloon the dependency surface for one client). Instead, the
// `install-codex` command falls back to printing a manual snippet
// unless --path is provided and ends in .json (the operator
// explicitly opted into a JSON-shaped config).
func CodexConfigCandidates() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".codex", "config.toml"),
	}
}

// ---------------------------------------------------------------------
// Install logic.
// ---------------------------------------------------------------------

// InstallResult describes what an install operation did. Path is the
// resolved target path; Created is true when no file existed at Path
// before; Updated is true when we replaced an existing kbounce entry;
// Manual is true when we printed a manual snippet instead of writing
// (Codex with TOML config, or any time we couldn't safely merge).
type InstallResult struct {
	// Path is the resolved target config path. Empty when Manual=true
	// and the operator did not pass --path.
	Path string
	// Created is true when the file did not exist before install.
	Created bool
	// Updated is true when an existing kbounce mcpServers entry was
	// replaced (vs newly added).
	Updated bool
	// Manual is true when the installer printed a manual snippet
	// instead of writing the config file (Codex TOML; explicit
	// refusal due to non-JSON content; etc.).
	Manual bool
	// Snippet is the JSON snippet shown to the operator when Manual=true.
	Snippet string
	// Reason is a human-readable string explaining why Manual=true.
	Reason string
}

// Options are the shared install flags. Path overrides the default
// candidate detection. Force overwrites existing kbounce entries
// without complaint. Out is where the installer writes its user-facing
// success / hint output; defaults to os.Stdout. Stderr defaults to
// os.Stderr.
type Options struct {
	Path   string
	Force  bool
	Out    io.Writer
	Stderr io.Writer

	// DevinHost overrides the placeholder host:port in the
	// install-devin recipe (kubectl server address + kubeconfig
	// server field). Empty emits the <kbounce-host> placeholder +
	// a substitute note. Unused by the JSON-merge installers.
	// Mirrors gbounce + ibounce + dbounce per [[cross-product-agent-parity]].
	DevinHost string
}

func (o *Options) defaults() {
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
}

// InstallClaudeCode adds the kbounce MCP server to the Claude Code /
// Claude Desktop config file. Returns InstallResult on success.
func InstallClaudeCode(opts Options) (*InstallResult, error) {
	opts.defaults()
	target, err := resolveTarget(opts.Path, ClaudeCodeConfigCandidates())
	if err != nil {
		return nil, err
	}
	return installJSON(target, "claude-code", opts)
}

// InstallCursor adds the kbounce MCP server to Cursor's MCP config.
func InstallCursor(opts Options) (*InstallResult, error) {
	opts.defaults()
	target, err := resolveTarget(opts.Path, CursorConfigCandidates())
	if err != nil {
		return nil, err
	}
	return installJSON(target, "cursor", opts)
}

// InstallCodex installs into Codex. If the target path ends in .json,
// we install it as JSON. Otherwise we refuse to touch the TOML file
// (third-party TOML editing risks corrupting unrelated keys) and
// instead print a manual snippet for the operator to paste in.
func InstallCodex(opts Options) (*InstallResult, error) {
	opts.defaults()
	// Resolve target: --path wins, else first candidate.
	target := opts.Path
	if target == "" {
		cands := CodexConfigCandidates()
		if len(cands) == 0 {
			return nil, errors.New("kbounce mcp install-codex: cannot resolve home directory; pass --path")
		}
		target = cands[0]
	}

	if strings.HasSuffix(strings.ToLower(target), ".json") {
		return installJSON(target, "codex", opts)
	}

	// TOML or unknown extension — print a manual snippet.
	snippet, err := snippetTOML()
	if err != nil {
		return nil, err
	}
	res := &InstallResult{
		Manual:  true,
		Path:    target,
		Snippet: snippet,
		Reason: "Codex stores MCP config in TOML (~/.codex/config.toml). " +
			"kbounce refuses to edit TOML in place (risks corrupting unrelated keys). " +
			"Paste the snippet below into your Codex config, or pass --path FILE.json " +
			"if you keep an alternative JSON-shaped MCP config.",
	}
	fmt.Fprintln(opts.Out, "kbounce mcp install-codex: manual install required")
	fmt.Fprintln(opts.Out, res.Reason)
	fmt.Fprintln(opts.Out, "")
	fmt.Fprintln(opts.Out, "Target Codex config (for reference):")
	fmt.Fprintln(opts.Out, "  ", target)
	fmt.Fprintln(opts.Out, "")
	fmt.Fprintln(opts.Out, "TOML snippet to add:")
	fmt.Fprintln(opts.Out, snippet)
	return res, nil
}

// DefaultProxyPort is the loopback port kbounce listens on by default.
// Mirrors posture.DefaultPort + the proxy's --port default; duplicated
// here (rather than imported) to keep mcpinstall free of a proxy/posture
// import for one integer.
const DefaultProxyPort = 8766

// InstallDevin prints the Devin bouncer-wiring recipe. There is NO local
// config to write — Devin is a cloud-hosted agent (it runs in
// Cognition's sandboxed environment, not on the operator's laptop), so
// kbounce surfaces the wiring clearly rather than silently degrading
// (per [[ibounce-honest-positioning]]). Mirrors ibounce's
// `ibounce mcp install-devin` + gbounce's `gbounce mcp install-devin`
// per [[cross-product-agent-parity]].
//
// The load-bearing difference from the loopback installers: a cloud
// agent CANNOT reach a bouncer on 127.0.0.1. kbounce must be bound to a
// HOST address Devin's sandbox can route to (--host 0.0.0.0 +
// --i-know-this-binds-externally), and the kubeconfig / KUBECONFIG the
// agent uses must point at that host:port — NOT loopback.
//
// DevinHost overrides the <kbounce-host> placeholder in the recipe so
// an operator can bake in a concrete reachable address; --devin-host
// is the corresponding CLI flag.
//
// Always returns Manual=true with the recipe captured in Snippet so a
// caller / test can assert the host-address guidance is present.
func InstallDevin(opts Options) (*InstallResult, error) {
	opts.defaults()

	kbounceHost := opts.DevinHost
	noteSubstitute := false
	if kbounceHost == "" {
		kbounceHost = "<kbounce-host>"
		noteSubstitute = true
	}

	// Build the MCP entry stamped with the "devin" agent attribution so
	// the snippet matches the auto-install paths' shape.
	entry := ServerEntryForAgent(agentNameForClient("devin"))
	cfg := map[string]any{"mcpServers": map[string]any{ServerName: entry}}
	snippetBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	snippet := string(snippetBytes)

	res := &InstallResult{
		Manual:  true,
		Snippet: snippet,
		Reason: "Devin is a cloud-hosted agent — it runs in Cognition's " +
			"sandbox, not on your machine, so there is no local config " +
			"for kbounce to write. Wire kbounce via Devin's MCP settings " +
			"(PATH A) or by pointing Devin's kubectl/KUBECONFIG at a " +
			"host-reachable kbounce (PATH B). A kbounce on 127.0.0.1 is " +
			"NOT visible to Devin's sandbox.",
	}

	w := opts.Out
	fmt.Fprintln(w, "kbounce mcp install-devin: Devin is a cloud-hosted agent — no local config to write.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "PATH A: MCP server (when Devin's MCP support is enabled)")
	fmt.Fprintln(w, "  1. In the Devin UI, go to Settings > MCP Servers.")
	fmt.Fprintln(w, "  2. Add this entry (same shape as `kbounce mcp show-config`):")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, snippet)
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "  Note: Devin's MCP host must be able to spawn `%s` — bundle the\n", ServerCommand)
	fmt.Fprintln(w, "  binary into the Devin environment, or use PATH B for the transparent proxy.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "PATH B: Transparent proxy at a HOST address (supported today)")
	fmt.Fprintln(w, "  1. Generate TLS material whose server cert covers the host Devin")
	fmt.Fprintln(w, "     reaches (add it as a SAN — loopback alone is not enough):")
	fmt.Fprintf(w, "       kbounce init-tls --additional-san %s\n", kbounceHost)
	fmt.Fprintln(w, "  2. On that host, run kbounce bound off-loopback (loopback is")
	fmt.Fprintln(w, "     invisible to the cloud sandbox) with TLS:")
	fmt.Fprintf(w, "       kbounce run --host 0.0.0.0 --port %d --i-know-this-binds-externally \\\n", DefaultProxyPort)
	fmt.Fprintln(w, "         --tls-cert ~/.kbouncer/tls/server.crt --tls-key ~/.kbouncer/tls/server.key \\")
	fmt.Fprintln(w, "         --upstream https://<your-cluster-api>:6443 \\")
	fmt.Fprintln(w, "         --audit-events-token <secret>   # required when binding off-loopback")
	fmt.Fprintln(w, "  3. In Devin's task environment, point kubectl at the proxy host:port")
	fmt.Fprintln(w, "     (NOT 127.0.0.1) and trust the generated CA:")
	fmt.Fprintf(w, "       server: https://%s:%d\n", kbounceHost, DefaultProxyPort)
	fmt.Fprintln(w, "       certificate-authority: ~/.kbouncer/tls/ca.crt")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Limitation: Devin runs in Cognition's cloud sandbox; kbounce must be on")
	fmt.Fprintln(w, "a host Devin can reach over the network. A kbounce on 127.0.0.1 is NOT")
	fmt.Fprintln(w, "visible to Devin's sandbox.")
	if noteSubstitute {
		fmt.Fprintln(opts.Stderr,
			"  [note] substitute <kbounce-host> above with the host Devin can "+
				"reach (pass --devin-host HOST to bake it in).")
	}
	return res, nil
}

// ---------------------------------------------------------------------
// Shared JSON-merge install.
// ---------------------------------------------------------------------

func resolveTarget(explicit string, candidates []string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if len(candidates) == 0 {
		return "", errors.New("cannot resolve home directory; pass --path")
	}
	// Prefer the first existing candidate; otherwise fall back to the
	// first one (a fresh install still writes somewhere sensible).
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return candidates[0], nil
}

// installJSON does the shared JSON read → merge → atomic-write dance.
func installJSON(target, clientName string, opts Options) (*InstallResult, error) {
	res := &InstallResult{Path: target}

	// Read existing config if present.
	existing := map[string]any{}
	existed := false
	if data, err := os.ReadFile(target); err == nil {
		existed = true
		if len(data) > 0 {
			if jerr := json.Unmarshal(data, &existing); jerr != nil {
				if !opts.Force {
					return nil, fmt.Errorf(
						"kbounce mcp install-%s: %s is not valid JSON (%v); "+
							"pass --force to overwrite or --path to write elsewhere",
						clientName, target, jerr)
				}
				existing = map[string]any{}
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("kbounce mcp install-%s: read %s: %w", clientName, target, err)
	}

	// Merge mcpServers.
	serversRaw, ok := existing["mcpServers"]
	var servers map[string]any
	if ok {
		if cast, ok2 := serversRaw.(map[string]any); ok2 {
			servers = cast
		} else if !opts.Force {
			return nil, fmt.Errorf(
				"kbounce mcp install-%s: %s has a non-object mcpServers value; "+
					"refusing to overwrite (pass --force, or use `kbounce mcp show-config` "+
					"+ merge by hand)", clientName, target)
		} else {
			servers = map[string]any{}
		}
	}
	if servers == nil {
		servers = map[string]any{}
	}

	if _, hadKbounce := servers[ServerName]; hadKbounce {
		res.Updated = true
	}
	// #375 / §A35b — per-client agent-attribution. installJSON is the
	// single write-path for claude-code / cursor / codex JSON installs;
	// agentNameForClient varies the AgentNameEnvVar value per client
	// so the agent runtime stamps the correct X-Agent-Name on
	// outbound HTTP traffic. Mirrors dbounce + ibounce.
	servers[ServerName] = ServerEntryForAgent(agentNameForClient(clientName))
	existing["mcpServers"] = servers

	res.Created = !existed

	// Atomic write.
	if err := writeJSONAtomic(target, existing); err != nil {
		return nil, fmt.Errorf("kbounce mcp install-%s: write %s: %w", clientName, target, err)
	}

	// User-facing output.
	verb := "added"
	if res.Updated {
		verb = "updated"
	}
	fmt.Fprintf(opts.Out, "kbounce mcp install-%s: %s `kbounce` MCP server in %s\n",
		clientName, verb, target)
	fmt.Fprintln(opts.Out, "")
	fmt.Fprintln(opts.Out, "Restart your MCP client so it re-reads the config.")
	fmt.Fprintln(opts.Out, "Verify with `kbounce mcp list-tools` (shows the same tools the agent will see).")

	return res, nil
}

// writeJSONAtomic marshals payload with 2-space indent + a trailing
// newline and writes it to target via a sibling tempfile + os.Rename.
//
// audit-cadence (b): the tempfile lives in the SAME directory as the
// target so the os.Rename is a same-filesystem move (POSIX guarantees
// atomicity). A cross-device rename would fall back to copy+remove,
// which is not atomic — the operator's existing config could be
// half-written if the process crashed mid-copy.
func writeJSONAtomic(target string, payload any) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeBytesAtomic(target, data, 0o644)
}

func writeBytesAtomic(target string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".kbounce-mcp-install-*.tmp")
	if err != nil {
		return fmt.Errorf("create tempfile in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// snippetTOML returns the Codex-shaped TOML snippet (best-effort hand-
// emitted; tiny enough not to need a TOML library).
func snippetTOML() (string, error) {
	var b strings.Builder
	b.WriteString("[mcp_servers.")
	b.WriteString(ServerName)
	b.WriteString("]\n")
	b.WriteString("command = \"")
	b.WriteString(ServerCommand)
	b.WriteString("\"\n")
	b.WriteString("args = [")
	for i, a := range ServerArgs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("\"")
		b.WriteString(a)
		b.WriteString("\"")
	}
	b.WriteString("]\n")
	// #375 / §A35b — agent-attribution env vars. Codex install is the
	// "openai-codex" client; the TOML snippet matches the JSON shape
	// so an operator who hand-pastes gets the same agent attribution
	// as the auto-install paths.
	b.WriteString("\n[mcp_servers.")
	b.WriteString(ServerName)
	b.WriteString(".env]\n")
	b.WriteString(AgentNameEnvVar)
	b.WriteString(" = \"openai-codex\"\n")
	b.WriteString(AgentSessionIDEnvVar)
	b.WriteString(" = \"\"\n")
	return b.String(), nil
}

// ---------------------------------------------------------------------
// show-config + list-tools.
// ---------------------------------------------------------------------

// Shape is the output format selector for ShowConfig.
type Shape string

const (
	ShapeJSON Shape = "json"
	ShapeYAML Shape = "yaml"
)

// ShowConfig writes the canonical MCP server config snippet to w in
// the requested shape, plus a one-line pointer at the bottom toward
// the install-* commands for the common clients.
func ShowConfig(w io.Writer, shape Shape) error {
	cfg := ServerConfigDict()
	switch shape {
	case "", ShapeJSON:
		out, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		if _, err := w.Write(out); err != nil {
			return err
		}
		if _, err := w.Write([]byte("\n")); err != nil {
			return err
		}
	case ShapeYAML:
		// Hand-emit the YAML so we don't add a yaml dep just for this
		// short document. The shape is fixed by ServerConfigDict so
		// the output is deterministic. #375 / §A35b — env block
		// carries the agent-attribution hints; matches the JSON
		// branch above.
		yaml := "mcpServers:\n" +
			"  " + ServerName + ":\n" +
			"    command: " + ServerCommand + "\n" +
			"    args:\n"
		for _, a := range ServerArgs {
			yaml += "      - " + a + "\n"
		}
		yaml += "    env:\n" +
			"      " + AgentNameEnvVar + ": " + DefaultAgentName + "\n" +
			"      " + AgentSessionIDEnvVar + ": \"\"\n"
		if _, err := w.Write([]byte(yaml)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown shape %q (want json | yaml)", shape)
	}

	// Trailer: point at the install-* commands so an operator who ran
	// show-config because they thought their client wasn't supported
	// learns that it might be.
	footer := "\n# Or for the common MCP clients:\n" +
		"#   kbounce mcp install-claude-code\n" +
		"#   kbounce mcp install-cursor\n" +
		"#   kbounce mcp install-codex\n" +
		"#   kbounce mcp install-devin       (cloud agent; prints recipe)\n" +
		"#\n" +
		"# Agent attribution (#375 / §A35b): the " + AgentNameEnvVar + " +\n" +
		"# " + AgentSessionIDEnvVar + " env vars wire the agent's\n" +
		"# X-Agent-Name + X-Agent-Session-Id HTTP headers. See\n" +
		"# iam-roles/docs/AGENT-ATTRIBUTION.md for the per-runtime\n" +
		"# patterns (Claude Code / Cursor / Codex / custom).\n"
	if _, err := w.Write([]byte(footer)); err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------
// list-tools — render the tool descriptor list as a 2-column table.
// ---------------------------------------------------------------------

// ToolListEntry is the simplified shape ListTools emits per row.
type ToolListEntry struct {
	Name        string
	Description string
}

// FormatToolList renders the entries as a 2-column table:
//
//	NAME                              DESCRIPTION
//	kbounce_active_mode               Return kbouncer's current mode...
//
// Long descriptions are truncated to ~80 chars with an ellipsis so the
// output stays one-line-per-tool (this is the same shape ibounce's
// list-tools uses).
func FormatToolList(w io.Writer, entries []ToolListEntry) error {
	// Stable sort by name so output is diffable.
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	// Compute name column width (cap at 36 so a runaway long name
	// doesn't push descriptions off the screen).
	nameWidth := 0
	for _, e := range entries {
		if l := len(e.Name); l > nameWidth {
			nameWidth = l
		}
	}
	if nameWidth > 36 {
		nameWidth = 36
	}
	if nameWidth < 12 {
		nameWidth = 12
	}

	fmt.Fprintf(w, "%-*s  %s\n", nameWidth, "NAME", "DESCRIPTION")
	for _, e := range entries {
		desc := firstSentence(e.Description)
		if len(desc) > 80 {
			desc = desc[:77] + "..."
		}
		fmt.Fprintf(w, "%-*s  %s\n", nameWidth, e.Name, desc)
	}
	return nil
}

// firstSentence returns the first sentence (up to '.' or newline) of
// the given description so the table stays compact. Descriptions in
// tools.go are sometimes multi-paragraph; the first sentence is the
// signal the operator wants in a list view.
func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	// Newlines first — multi-line descriptions almost always start with
	// a one-line summary.
	if i := strings.IndexAny(s, "\n"); i > 0 {
		s = s[:i]
	}
	// Then sentence end. Skip the abbreviation "i.e." style traps —
	// none of our descriptions use them, so a plain '.' is safe.
	if i := strings.Index(s, ". "); i > 0 {
		s = s[:i+1]
	}
	return strings.TrimSpace(s)
}
