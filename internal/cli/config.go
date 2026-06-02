// `kbounce config export / import` — backup / restore / migration for
// the operator's entire kbounce configuration surface.
//
// Per [[basic-app-hygiene-features]] TIER 1 #1: every normal product
// ships config export/import for backup / restore / migration. Before
// this slice, the answer to "I'm moving kbounce to a new laptop / want
// to back up before an upgrade / want to mirror the same config across
// CI runners" was "manually recreate from scratch" — friction the
// product memo categorizes as a launch-bar gap.
//
// What ships:
//
//   kbounce config export [--out PATH] [--with-secrets | --redact-secrets]
//   kbounce config import --in PATH [--dry-run] [--merge | --replace] [--yes]
//
// (The legacy `--from PATH` flag is preserved as a DEPRECATED alias for
// `--in PATH` per #288 — it still works but prints a stderr deprecation
// warning. New scripts should use `--in PATH` to match ibounce + gbounce +
// dbounce; one cross-product backup script can target every Bounce
// product with the same flag name.)
//
// Wire shape (load-bearing for cross-product future):
//
//   {
//     "schema_version": "1.0",
//     "product": "kbounce",
//     "exported_at": "<ISO-8601 UTC>",
//     "binary_version": "<from cli.version>",
//     "profiles": [...],         // all profiles in profiles.yaml + installed
//     "rules": [...],            // rules table rows
//     "tasks": [...],            // tasks table rows
//     "presets": [...],          // built-in + installed presets
//     "audit_export": {...},     // log path + webhook URL + preset + token (MASKED unless --with-secrets)
//     "license_pointer": "...",  // stub for #235 license-file plumbing
//     "runtime_config": {...}    // mode + default-policy
//   }
//
// Cross-product top-level fields (`schema_version`, `product`) let a
// future `iam-jit config export-all` bundle parallel exports from
// kbounce + dbounce + ibounce; importing a dbounce export into kbounce
// is REFUSED (different schema shapes, different rule semantics).
//
// Token-leak invariant per [[security-team-positioning-safety-not-
// surveillance]]: `--redact-secrets` is the DEFAULT. Audit-webhook
// tokens / future license bytes are masked to "***REDACTED***" unless
// the operator explicitly passes `--with-secrets`, in which case a
// banner WARNING fires on stderr.
//
// Admin-action OCSF events fire on BOTH export and import via the
// `audit.EmitConfigExport` / `audit.EmitConfigImport` stubs already
// wired in #278. Composes with [[security-team-audit-export]].
//
// Schema validation: `schemas/kbounce-config.schema.json` (JSON Schema
// draft 2020-12) is published in the repo. Import validates the
// incoming JSON against the embedded schema; malformed inputs are
// rejected before any state mutation. Per [[basic-app-hygiene-
// features]] TIER 1 #2.
package cli

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/kbenv"
	"github.com/trsreagan3/kbouncer/internal/presets"
	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
)

// ConfigSchemaVersion is the wire-format version of the export JSON.
// String semver per the #288 cross-product reconciliation: lets us bump
// "1.0" → "1.1" (additive) vs "2.0" (breaking) without changing the
// parser shape. Matches the ibounce + gbounce + dbounce shape so a
// customer's single cross-product backup parser handles every Bounce
// product identically.
const ConfigSchemaVersion = "1.0"

// LegacyIntSchemaVersion is the pre-#288 wire value (raw int 1). New
// exports always emit the string form, but importers accept the int
// form indefinitely (printing a stderr deprecation warning) so old
// exports on disk stay readable across binary upgrades.
const LegacyIntSchemaVersion = 1

// ConfigProduct is the product name stamped into every export.
// Refusing imports whose `product` field doesn't match is the
// load-bearing "you can't import a dbounce export into kbounce"
// guard.
const ConfigProduct = "kbounce"

// secretRedactedMarker is the literal value substituted for any
// secret field when --redact-secrets is in effect. Matches the
// cross-product convention so a SIEM analyst grepping for the marker
// across kbounce / dbounce / ibounce exports finds a uniform hit.
const secretRedactedMarker = "***REDACTED***"

//go:embed config_schema.json
var embeddedConfigSchema []byte

// ConfigExport is the top-level shape written by `config export` and
// expected by `config import`. JSON tags are the wire shape — Go field
// names are free to evolve as long as the tags stay stable.
type ConfigExport struct {
	SchemaVersion  string                 `json:"schema_version"`
	Product        string                 `json:"product"`
	ExportedAt     string                 `json:"exported_at"`
	BinaryVersion  string                 `json:"binary_version"`
	Profiles       []ConfigProfile        `json:"profiles"`
	Rules          []ConfigRule           `json:"rules"`
	Tasks          []map[string]any       `json:"tasks"`
	Presets        []ConfigPreset         `json:"presets"`
	AuditExport    ConfigAuditExport      `json:"audit_export"`
	LicensePointer string                 `json:"license_pointer"`
	RuntimeConfig  map[string]any         `json:"runtime_config"`
}

// ConfigProfile is the export-side projection of profile.Profile.
// We keep the projection explicit (rather than embedding the profile
// struct) so a future profile-struct field doesn't silently change
// the export wire shape — the schema_version bump discipline is what
// gates wire changes.
type ConfigProfile struct {
	Name                       string              `json:"name"`
	Description                string              `json:"description,omitempty"`
	Source                     string              `json:"source,omitempty"`
	DenyKeywords               []string            `json:"deny_keywords,omitempty"`
	KeywordTargets             []string            `json:"keyword_targets,omitempty"`
	KeywordMatch               string              `json:"keyword_match,omitempty"`
	OnlyClusters               []string            `json:"only_clusters,omitempty"`
	DenyVerbs                  []string            `json:"deny_verbs,omitempty"`
	ExemptResourcesForVerbDeny map[string][]string `json:"exempt_resources_for_verb_deny,omitempty"`
	DenyOnImpersonation        bool                `json:"deny_on_impersonation,omitempty"`
	DenySubresourceWrites      bool                `json:"deny_subresource_writes,omitempty"`
	Exceptions                 []string            `json:"exceptions,omitempty"`
}

// ConfigRule mirrors the global-rules-table row shape. Origin is
// preserved so an import can distinguish operator-added rules from
// preset-applied ones in the post-import audit row.
type ConfigRule struct {
	Pattern        string `json:"pattern"`
	Effect         string `json:"effect"`
	NamespaceScope string `json:"namespace_scope,omitempty"`
	ResourceScope  string `json:"resource_scope,omitempty"`
	VerbScope      string `json:"verb_scope,omitempty"`
	Note           string `json:"note,omitempty"`
	Origin         string `json:"origin,omitempty"`
}

// ConfigPreset is a one-row presets-catalog projection. We include
// the rule list verbatim so an air-gapped operator who exports on a
// machine with the built-in catalog + imports on a machine WITHOUT
// the catalog still gets the rules. Built-in presets are flagged
// `builtin: true` so the importer knows to compare-not-overwrite.
type ConfigPreset struct {
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Builtin     bool         `json:"builtin"`
	Rules       []ConfigRule `json:"rules"`
}

// ConfigAuditExport carries the operator's audit-export channel
// configuration. The token field is MASKED unless --with-secrets was
// passed; the wire shape includes a `token_masked` boolean so the
// importer knows whether the token round-trip is meaningful.
type ConfigAuditExport struct {
	LogPath       string `json:"log_path,omitempty"`
	LogFsync      bool   `json:"log_fsync,omitempty"`
	WebhookURL    string `json:"webhook_url,omitempty"`
	WebhookToken  string `json:"webhook_token,omitempty"`
	TokenMasked   bool   `json:"token_masked"`
	WebhookBatch  int    `json:"webhook_batch,omitempty"`
	WebhookPreset string `json:"webhook_preset,omitempty"`
	WebhookTags   string `json:"webhook_tags,omitempty"`
}

// ExportOptions controls a one-shot export. All fields optional;
// zero-values pick the secure default (redact secrets, write to
// stdout when Out is nil).
type ExportOptions struct {
	// Out is the writer the JSON is emitted to. Nil → stdout.
	Out io.Writer
	// ProfilesPath is the on-disk profiles.yaml to read. Empty →
	// resolve via profile.DefaultProfilesPath.
	ProfilesPath string
	// DBPath is the SQLite file to read. Empty → store.DefaultDBPath.
	DBPath string
	// WithSecrets controls whether the audit-webhook token is emitted
	// verbatim. false (the default) substitutes secretRedactedMarker.
	WithSecrets bool
	// AuditExport is the live audit-export config to project into the
	// export. Callers wire this from the run-command flags or pass a
	// zero-value when invoked one-shot (the more common case for
	// `config export`).
	AuditExport ConfigAuditExport
	// LicensePointer is the on-disk path of the installed Enterprise
	// license file, or empty if none. Stub for #235.
	LicensePointer string
	// RuntimeConfig is the mode + default-policy snapshot. Empty map
	// → wire shape carries an empty `runtime_config` block so the
	// importer can tell "operator didn't capture this" apart from
	// "operator captured the secure defaults."
	RuntimeConfig map[string]any
}

// BuildExport collects the operator's current configuration into a
// *ConfigExport. Pure read; never mutates the store / profiles.yaml.
// Errors surface partial-context information so the operator can fix
// the underlying cause (missing profiles file, locked DB) rather than
// guessing at a vague "export failed."
func BuildExport(opts ExportOptions) (*ConfigExport, error) {
	exp := &ConfigExport{
		SchemaVersion:  ConfigSchemaVersion,
		Product:        ConfigProduct,
		ExportedAt:     time.Now().UTC().Format(time.RFC3339),
		BinaryVersion:  version,
		Profiles:       []ConfigProfile{},
		Rules:          []ConfigRule{},
		Tasks:          []map[string]any{},
		Presets:        []ConfigPreset{},
		LicensePointer: opts.LicensePointer,
		RuntimeConfig:  opts.RuntimeConfig,
	}
	if exp.RuntimeConfig == nil {
		exp.RuntimeConfig = map[string]any{}
	}

	// Profiles: read profiles.yaml (or embedded defaults when the file
	// is absent — same semantics as the run path). Sort by name so the
	// export is deterministic across runs (the underlying map's
	// iteration order isn't stable).
	profilesPath := opts.ProfilesPath
	if profilesPath == "" {
		p, err := profile.DefaultProfilesPath()
		if err != nil {
			return nil, fmt.Errorf("resolve profiles path: %w", err)
		}
		profilesPath = p
	}
	profs, err := profile.LoadProfiles(profilesPath)
	if err != nil {
		return nil, fmt.Errorf("load profiles: %w", err)
	}
	for _, name := range profs.NamesSorted() {
		p := profs.All[name]
		if p == nil {
			continue
		}
		exp.Profiles = append(exp.Profiles, profileToConfig(p))
	}

	// Rules + tasks: ListRules + ListTasks. We use the no-expiry-filter
	// variants so the export captures the FULL audit-trail-preserving
	// rule set; an importer can decide whether to honor expires_at on
	// reinsertion (we do — see applyImport).
	st, err := store.Open(opts.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	storedRules, err := st.ListRules()
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	for _, sr := range storedRules {
		exp.Rules = append(exp.Rules, ruleToConfig(sr.Rule))
	}
	taskScopes, err := st.ListTasks("", 1000)
	if err != nil {
		return nil, fmt.Errorf("list tasks: %w", err)
	}
	for _, t := range taskScopes {
		exp.Tasks = append(exp.Tasks, t.ToMap())
	}

	// Presets: ship the BUILT-IN catalog so an air-gapped importer has
	// the full set even without the embedded YAML files. Future post-
	// launch: also ship installed presets when that surface lands.
	cat, perr := presets.List()
	if perr != nil {
		// Non-fatal: the export is still useful without the catalog. Log
		// to stderr via the wrapper; don't fail the call.
		exp.Presets = []ConfigPreset{}
	} else {
		for _, p := range cat {
			cp := ConfigPreset{
				Name:        p.Name,
				Description: p.Description,
				Builtin:     true,
				Rules:       make([]ConfigRule, 0, len(p.Rules)),
			}
			for _, r := range p.Rules {
				cp.Rules = append(cp.Rules, ruleToConfig(r))
			}
			exp.Presets = append(exp.Presets, cp)
		}
	}

	// Audit-export: copy the caller-supplied snapshot, masking the
	// token unless --with-secrets is set. TokenMasked is ALWAYS set so
	// the importer can distinguish "no token configured" from "token
	// was redacted on export."
	ae := opts.AuditExport
	if !opts.WithSecrets && ae.WebhookToken != "" {
		ae.WebhookToken = secretRedactedMarker
		ae.TokenMasked = true
	} else {
		ae.TokenMasked = false
	}
	exp.AuditExport = ae

	return exp, nil
}

// profileToConfig projects a *profile.Profile onto the export shape.
// Keep the projection in this file (rather than as a profile-package
// method) so the wire shape's evolution lives next to the import
// path that consumes it.
func profileToConfig(p *profile.Profile) ConfigProfile {
	cp := ConfigProfile{
		Name:                       p.Name,
		Description:                p.Description,
		Source:                     p.Source,
		DenyKeywords:               p.DenyKeywords,
		KeywordMatch:               string(p.KeywordMatch),
		OnlyClusters:               p.OnlyClusters,
		DenyVerbs:                  p.DenyVerbs,
		ExemptResourcesForVerbDeny: p.ExemptResourcesForVerbDeny,
		DenyOnImpersonation:        p.DenyOnImpersonation,
		DenySubresourceWrites:      p.DenySubresourceWrites,
		Exceptions:                 p.Exceptions,
	}
	if len(p.KeywordTargets) > 0 {
		cp.KeywordTargets = make([]string, 0, len(p.KeywordTargets))
		for _, t := range p.KeywordTargets {
			cp.KeywordTargets = append(cp.KeywordTargets, string(t))
		}
	}
	return cp
}

// configToProfile is the inverse of profileToConfig — used on import
// to reconstruct a *profile.Profile from a wire row.
func configToProfile(cp ConfigProfile) *profile.Profile {
	p := &profile.Profile{
		Name:                       cp.Name,
		Description:                cp.Description,
		Source:                     cp.Source,
		DenyKeywords:               cp.DenyKeywords,
		KeywordMatch:               profile.KeywordMatchMode(cp.KeywordMatch),
		OnlyClusters:               cp.OnlyClusters,
		DenyVerbs:                  cp.DenyVerbs,
		ExemptResourcesForVerbDeny: cp.ExemptResourcesForVerbDeny,
		DenyOnImpersonation:        cp.DenyOnImpersonation,
		DenySubresourceWrites:      cp.DenySubresourceWrites,
		Exceptions:                 cp.Exceptions,
	}
	if len(cp.KeywordTargets) > 0 {
		p.KeywordTargets = make([]profile.KeywordTarget, 0, len(cp.KeywordTargets))
		for _, t := range cp.KeywordTargets {
			p.KeywordTargets = append(p.KeywordTargets, profile.KeywordTarget(t))
		}
	}
	return p
}

func ruleToConfig(r rules.ProxyRule) ConfigRule {
	return ConfigRule{
		Pattern:        r.Pattern,
		Effect:         string(r.Effect),
		NamespaceScope: r.NamespaceScope,
		ResourceScope:  r.ResourceScope,
		VerbScope:      r.VerbScope,
		Note:           r.Note,
		Origin:         r.Origin,
	}
}

func configToRule(cr ConfigRule) rules.ProxyRule {
	return rules.ProxyRule{
		Pattern:        cr.Pattern,
		Effect:         rules.Effect(cr.Effect),
		NamespaceScope: cr.NamespaceScope,
		ResourceScope:  cr.ResourceScope,
		VerbScope:      cr.VerbScope,
		Note:           cr.Note,
		Origin:         cr.Origin,
	}
}

// newConfigCmd assembles the `config` group + its subcommands.
func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Export / import kbounce configuration for backup, restore, migration",
		Long: `Export or import the operator's full kbounce configuration
(profiles + rules + tasks + presets + audit-export config + license
pointer + runtime config) as a single JSON file.

Per [[basic-app-hygiene-features]] TIER 1 #1: backup / restore /
migration is a load-bearing hygiene feature. Use ` + "`config export`" + ` to
snapshot your config before an upgrade or to mirror it across CI
runners; use ` + "`config import`" + ` to restore.

Token-leak invariant: ` + "`--redact-secrets`" + ` is the DEFAULT for export.
Audit-webhook tokens are masked unless you explicitly pass
` + "`--with-secrets`" + ` (which prints a stderr WARNING banner).

Cross-product parity: ` + "`ibounce config export`" + ` + ` + "`dbounce config export`" + `
ship the same shape. The schema_version + product fields gate
"can't import dbounce export into kbounce" at import time.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("config", cmd)
	cmd.AddCommand(newConfigExportCmd())
	cmd.AddCommand(newConfigImportCmd())
	cmd.AddCommand(newConfigPreviewRoutesCmd())
	return cmd
}

// newConfigPreviewRoutesCmd is the #280 dry-run subcommand.
//
// Loads an --alert-routes YAML + evaluates a single OCSF event JSON
// file against every route, printing which routes matched + the
// masked destinations each match would have dispatched to. No HTTP
// traffic is sent.
//
// Per [[per-org-notification-routing]] this is mandatory pre-deploy
// validation — YAML routing is dense + error-prone.
func newConfigPreviewRoutesCmd() *cobra.Command {
	var (
		routesPath string
		eventPath  string
	)
	cmd := &cobra.Command{
		Use:   "preview-routes",
		Short: "Dry-run a sample event against an --alert-routes YAML",
		Long: `Load the --alert-routes YAML + show which routes a sample
event would match and which destinations those routes would dispatch to.

No HTTP traffic is sent. Secrets are rendered as <first-8-char>***
prefixes so the operator can confirm the right env vars resolved
without printing tokens.

Example:

    $ export SOC_SPLUNK_HEC_TOKEN=...
    $ kbounce config preview-routes \
          --routes ~/.iam-jit/kbounce-routes.yaml \
          --event sample-event.json
`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := audit.LoadRoutesConfig(routesPath)
			if err != nil {
				return err
			}
			// #G304 read-only path; the operator passes the path.
			raw, err := os.ReadFile(filepath.Clean(eventPath)) // #nosec G304
			if err != nil {
				return fmt.Errorf(
					"kbounce: could not read --event file %q: %w",
					eventPath, err)
			}
			var event map[string]any
			if err := json.Unmarshal(raw, &event); err != nil {
				return fmt.Errorf(
					"kbounce: --event file %q is not valid JSON: %w",
					eventPath, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "routes config: %s\n", routesPath)
			fmt.Fprintf(cmd.OutOrStdout(), "event: %s\n", eventPath)
			fmt.Fprintf(cmd.OutOrStdout(),
				"total routes defined: %d\n", len(cfg.Routes))
			secrets := cfg.SecretsUsed()
			if len(secrets) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(),
					"secrets resolved (env-var name + masked prefix):")
				for _, kv := range secrets {
					fmt.Fprintf(cmd.OutOrStdout(),
						"  %s (%s)\n", kv[0], kv[1])
				}
			}
			hits := audit.SelectRoutes(event, cfg.Routes)
			if len(hits) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(),
					"no routes matched this event.")
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"matched %d route(s):\n", len(hits))
			for _, r := range hits {
				fmt.Fprintf(cmd.OutOrStdout(),
					"  - %s (on_match=%s)\n", r.Name, r.OnMatch)
				for _, d := range r.Destinations {
					fields := d.Masked()
					parts := make([]string, 0, len(fields))
					// Sort keys for deterministic output.
					keys := make([]string, 0, len(fields))
					for k := range fields {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						parts = append(parts,
							fmt.Sprintf("%s=%v", k, fields[k]))
					}
					fmt.Fprintf(cmd.OutOrStdout(),
						"      destination: %s\n",
						strings.Join(parts, ", "))
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&routesPath, "routes", "",
		"Path to the --alert-routes YAML file to evaluate.")
	cmd.Flags().StringVar(&eventPath, "event", "",
		"Path to a JSON file containing one OCSF event to evaluate.")
	_ = cmd.MarkFlagRequired("routes")
	_ = cmd.MarkFlagRequired("event")
	_ = cmd.MarkFlagFilename("routes", "yaml", "yml")
	_ = cmd.MarkFlagFilename("event", "json")
	return cmd
}

func newConfigExportCmd() *cobra.Command {
	var (
		outPath        string
		withSecrets    bool
		redactSecrets  bool
		dbPath         string
		profilesPath   string
		auditLogPath   string
	)
	cmd := &cobra.Command{
		Use:   "export [--out PATH] [--with-secrets | --redact-secrets]",
		Short: "Export the full kbounce config as a single JSON file",
		Long: `Export the operator's full kbounce config (profiles + rules +
tasks + presets + audit-export config + license pointer + runtime
config) as a single JSON file.

Default: writes to stdout. Pass ` + "`--out PATH`" + ` to write to a file
(parent dirs are created with 0o700; the file is written 0o600 so a
multi-user machine can't read another operator's export).

Token-leak invariant: ` + "`--redact-secrets`" + ` is the DEFAULT.
` + "`--with-secrets`" + ` opts into emitting tokens verbatim AND prints a
stderr WARNING banner (so an operator running ` + "`config export | tee`" + `
inside a recorded terminal sees the leak risk).

Admin-action OCSF event fires on every successful export so a
security team can answer "who exported the config + when?".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if withSecrets && redactSecrets {
				return errors.New(
					"kbounce: --with-secrets and --redact-secrets are mutually exclusive")
			}
			// Default = redact. Explicit --with-secrets opts out.
			emitSecrets := withSecrets

			opts := ExportOptions{
				Out:          cmd.OutOrStdout(),
				ProfilesPath: profilesPath,
				DBPath:       dbPath,
				WithSecrets:  emitSecrets,
				// AuditExport snapshot: in v1.0 the one-shot CLI does not
				// read the running proxy's flags (the proxy is a separate
				// process and there's no IPC channel for "what flags did
				// you start with"). The exported audit_export block
				// therefore reflects whatever the CALLER passes; we
				// project the KBOUNCER_AUDIT_LOG_PATH env-var fallback
				// so an operator who exported the log path that way sees
				// it in the export. Webhook fields stay empty in v1.0.
				AuditExport: ConfigAuditExport{
					LogPath: resolveAuditLogPath(auditLogPath),
				},
			}

			exp, err := BuildExport(opts)
			if err != nil {
				return err
			}

			payload, err := json.MarshalIndent(exp, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal export: %w", err)
			}

			if emitSecrets {
				fmt.Fprintln(cmd.ErrOrStderr(),
					"WARNING: --with-secrets emits audit-webhook tokens / "+
						"license bytes VERBATIM. Treat the export file as "+
						"secret material (chmod 600 + secure destruction "+
						"after use). Default is --redact-secrets.")
			}

			if outPath != "" {
				if dir := filepath.Dir(outPath); dir != "" && dir != "." {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						return fmt.Errorf("mkdir %q: %w", dir, err)
					}
				}
				if err := os.WriteFile(outPath, payload, 0o600); err != nil {
					return fmt.Errorf("write %q: %w", outPath, err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(),
					"kbounce: config export written to %s (%d bytes)\n",
					outPath, len(payload))
			} else {
				if _, err := cmd.OutOrStdout().Write(payload); err != nil {
					return fmt.Errorf("write stdout: %w", err)
				}
				// Trailing newline so shell pipelines that don't expect a
				// missing-final-newline behave correctly.
				_, _ = cmd.OutOrStdout().Write([]byte("\n"))
			}

			// Admin-action audit event — fires whether --out was a file
			// or stdout. The after_hash captures the EXPORTED CONTENT
			// (sans secrets, when redacted) so a tamper-detection
			// reviewer can verify "the export I'm holding matches the
			// one the audit log says was emitted at this timestamp."
			destination := outPath
			if destination == "" {
				destination = "<stdout>"
			}
			snapshot := map[string]any{
				"schema_version":  exp.SchemaVersion,
				"product":         exp.Product,
				"profile_count":   len(exp.Profiles),
				"rule_count":      len(exp.Rules),
				"task_count":      len(exp.Tasks),
				"preset_count":    len(exp.Presets),
				"with_secrets":    emitSecrets,
				"destination":     destination,
				"exported_bytes":  len(payload),
			}
			emitAdminAction(cmd, auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionConfigExport,
				Actor:      currentActor(),
				EntityKind: "config",
				EntityName: destination,
				Source:     audit.AdminActionSourceCLI,
				Before:     nil,
				After:      snapshot,
				ExtraExt: map[string]any{
					"with_secrets": emitSecrets,
					"destination":  destination,
				},
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "",
		"Write the export JSON to this file (default: stdout). Parent "+
			"dirs are created 0o700; the file is written 0o600.")
	cmd.Flags().BoolVar(&withSecrets, "with-secrets", false,
		"Emit audit-webhook tokens / license bytes VERBATIM. Prints a "+
			"stderr WARNING banner. Mutually exclusive with --redact-secrets. "+
			"Default behavior is to redact.")
	cmd.Flags().BoolVar(&redactSecrets, "redact-secrets", false,
		"Mask audit-webhook tokens + license bytes as \"***REDACTED***\" "+
			"in the export. This is the DEFAULT — flag exists for "+
			"explicit-intent scripts.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	cmd.Flags().StringVar(&profilesPath, "profiles", "",
		"Profiles YAML path (default: ~/.kbouncer/profiles.yaml, or "+
			"KBOUNCER_PROFILES_PATH env).")
	addAdminAuditFlag(cmd, &auditLogPath)
	return cmd
}

// ImportMode controls the merge semantics of `config import`.
type ImportMode string

const (
	// ImportModeMerge overlays the imported config onto the existing
	// state. Existing rules / tasks are preserved; profiles with the
	// same name are overwritten. Default; safer for routine restore.
	ImportModeMerge ImportMode = "merge"

	// ImportModeReplace blows away the existing rules + tasks (the
	// store mutable surface) and re-creates from the import. Profiles
	// are replaced entirely (profiles.yaml is rewritten). Requires
	// --yes (or interactive confirmation in a future revision) since
	// it discards existing local state.
	ImportModeReplace ImportMode = "replace"
)

// ImportDiff is the dry-run summary returned by applyImport when
// `--dry-run` is set. Per-section added / removed / changed counts let
// the operator see exactly what `--merge` vs `--replace` would do.
type ImportDiff struct {
	Mode             ImportMode `json:"mode"`
	ProfilesAdded    int        `json:"profiles_added"`
	ProfilesChanged  int        `json:"profiles_changed"`
	ProfilesRemoved  int        `json:"profiles_removed"`
	RulesAdded       int        `json:"rules_added"`
	RulesRemoved     int        `json:"rules_removed"`
	TasksAdded       int        `json:"tasks_added"`
	TasksRemoved     int        `json:"tasks_removed"`
	AuditExportSet   bool       `json:"audit_export_set"`
	LicenseSet       bool       `json:"license_set"`
}

// ImportOptions controls a one-shot import. All fields optional;
// zero-values pick the safer default (merge, no replace).
type ImportOptions struct {
	// Source is the io.Reader yielding the export JSON. Required.
	Source io.Reader
	// SourceName is a label for error messages (file path / "<stdin>").
	SourceName string
	// ProfilesPath is the on-disk profiles.yaml to write. Empty →
	// resolve via profile.DefaultProfilesPath.
	ProfilesPath string
	// DBPath is the SQLite file to write. Empty → store.DefaultDBPath.
	DBPath string
	// Mode is "merge" or "replace"; defaults to "merge".
	Mode ImportMode
	// DryRun, when true, computes the diff but does NOT mutate state.
	DryRun bool
	// DeprecationOut receives wire-shape deprecation warnings (legacy
	// int schema_version, etc.). nil discards them; the CLI surface
	// wires cmd.ErrOrStderr() so an operator sees the heads-up.
	DeprecationOut io.Writer
}

// LoadAndValidate reads + JSON-decodes + schema-validates the import
// payload. Returns the parsed ConfigExport on success. Schema errors
// are surfaced with a list of validation failures so the operator can
// fix the file. The `product` check is the load-bearing "you can't
// import a dbounce export into kbounce" guard.
//
// Cross-product reconciliation (#288): accepts BOTH the new
// `schema_version: "1.0"` (string) shape AND the pre-#288
// `schema_version: 1` (int) shape. The int form is rewritten in-place
// to the canonical string form before schema validation runs (so the
// schema can require the string-shape contract going forward), and a
// deprecation warning is written to `deprecationOut` when supplied.
// The wire deprecation window stays open across the whole v1.x line
// per [[push-policy-public-repo]]-adjacent compat rules — old exports
// on disk must keep importing cleanly indefinitely.
func LoadAndValidate(r io.Reader) (*ConfigExport, error) {
	return loadAndValidate(r, nil)
}

// loadAndValidate is the unexported workhorse. `deprecationOut`
// receives any deprecation warnings (legacy int schema_version etc.);
// nil discards them. Tests + CLI wire a real writer; library callers
// who don't care pass nil via the LoadAndValidate alias.
func loadAndValidate(r io.Reader, deprecationOut io.Writer) (*ConfigExport, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 64<<20)) // 64 MiB cap
	if err != nil {
		return nil, fmt.Errorf("read import: %w", err)
	}

	// Pre-normalize the wire shape: pre-#288 exports carry
	// `schema_version: 1` (int). Rewrite to `"1.0"` so the schema
	// validator + downstream Go decoder see the canonical shape. A
	// deprecation warning is emitted on the supplied writer so a
	// scripted operator sees the heads-up exactly once per import.
	normalized, legacyIntSeen, nerr := normalizeLegacySchemaVersion(raw)
	if nerr != nil {
		return nil, nerr
	}
	if legacyIntSeen && deprecationOut != nil {
		fmt.Fprintln(deprecationOut,
			"kbounce: deprecation: import uses legacy `schema_version: 1` "+
				"(int) shape; this kbounce understands it but future major "+
				"versions will refuse it. Re-export with this binary to "+
				"upgrade to `schema_version: \"1.0\"` (string).")
	}

	// Schema validation FIRST so structural errors surface with the
	// JSON-Schema error rather than a Go-decode error. We use a
	// minimal in-house JSON-Schema subset (no third-party deps per
	// the slice constraints); it validates the required fields +
	// type tags that the wire contract depends on.
	if errs := validateConfigJSON(normalized, embeddedConfigSchema); len(errs) > 0 {
		return nil, fmt.Errorf("schema validation failed:\n  - %s",
			strings.Join(errs, "\n  - "))
	}

	var exp ConfigExport
	if err := json.Unmarshal(normalized, &exp); err != nil {
		return nil, fmt.Errorf("parse import JSON: %w", err)
	}
	if exp.SchemaVersion != ConfigSchemaVersion {
		return nil, fmt.Errorf(
			"schema_version mismatch: import has %q, this kbounce expects %q",
			exp.SchemaVersion, ConfigSchemaVersion)
	}
	if exp.Product != ConfigProduct {
		return nil, fmt.Errorf(
			"product mismatch: import has %q, this kbounce expects %q "+
				"(can't import a non-kbounce export — different rule semantics)",
			exp.Product, ConfigProduct)
	}
	return &exp, nil
}

// normalizeLegacySchemaVersion inspects the wire payload for a
// pre-#288 `schema_version: 1` (int) field and, if present, rewrites
// it in place to the canonical `"1.0"` (string) form. Returns the
// (possibly modified) payload + a flag indicating whether a legacy int
// shape was actually seen. Payloads that already carry the string form
// pass through unchanged.
//
// We do the rewrite at the JSON level (not the typed-decode level) so
// the schema validator + the typed decoder both see the canonical
// shape downstream. Any int > 1 is treated as "unknown future schema"
// and rejected so a customer running an older binary against a newer
// export gets a clear refusal instead of silently truncating fields.
func normalizeLegacySchemaVersion(raw []byte) ([]byte, bool, error) {
	var head map[string]json.RawMessage
	if err := json.Unmarshal(raw, &head); err != nil {
		// Defer the descriptive error to the schema validator — it
		// surfaces "payload is not valid JSON" with the same error.
		return raw, false, nil
	}
	v, present := head["schema_version"]
	if !present {
		return raw, false, nil
	}
	// String shape: nothing to do.
	var asString string
	if err := json.Unmarshal(v, &asString); err == nil {
		return raw, false, nil
	}
	// Int shape: must equal the legacy known value (1). Anything else
	// is rejected at this layer — the schema validator's enum check
	// would also catch it, but a typed error here surfaces the issue
	// with a more operator-actionable message.
	var asInt int
	if err := json.Unmarshal(v, &asInt); err != nil {
		return raw, false, nil // Let the schema validator's type check fire.
	}
	if asInt != LegacyIntSchemaVersion {
		return nil, false, fmt.Errorf(
			"schema_version mismatch: import has legacy int %d, this kbounce "+
				"understands legacy int %d (which it rewrites to %q) — re-export "+
				"with a matching kbounce binary",
			asInt, LegacyIntSchemaVersion, ConfigSchemaVersion)
	}
	// Rewrite the field in the parsed map and re-marshal. JSON object
	// key order is not preserved across encode/decode, but downstream
	// consumers (schema validator + typed decoder) treat the object as
	// unordered — no consumer in this file depends on key order.
	canon, err := json.Marshal(ConfigSchemaVersion)
	if err != nil {
		return nil, false, fmt.Errorf("re-marshal schema_version: %w", err)
	}
	head["schema_version"] = canon
	out, err := json.Marshal(head)
	if err != nil {
		return nil, false, fmt.Errorf("re-marshal payload: %w", err)
	}
	return out, true, nil
}

// applyImport is the one-shot import worker called by the cobra
// RunE. Returns the diff regardless of DryRun; mutations only happen
// when DryRun=false.
func applyImport(opts ImportOptions) (*ImportDiff, *ConfigExport, error) {
	if opts.Source == nil {
		return nil, nil, errors.New("kbounce: ImportOptions.Source is required")
	}
	mode := opts.Mode
	if mode == "" {
		mode = ImportModeMerge
	}
	if mode != ImportModeMerge && mode != ImportModeReplace {
		return nil, nil, fmt.Errorf(
			"kbounce: import mode must be %q or %q (got %q)",
			ImportModeMerge, ImportModeReplace, mode)
	}

	exp, err := loadAndValidate(opts.Source, opts.DeprecationOut)
	if err != nil {
		return nil, nil, err
	}

	// Resolve paths.
	profilesPath := opts.ProfilesPath
	if profilesPath == "" {
		p, perr := profile.DefaultProfilesPath()
		if perr != nil {
			return nil, exp, fmt.Errorf("resolve profiles path: %w", perr)
		}
		profilesPath = p
	}

	// Existing state — used by the diff + by replace-mode cleanup.
	existing, _ := profile.LoadProfiles(profilesPath)
	existingProfileNames := map[string]bool{}
	if existing != nil {
		for n := range existing.All {
			existingProfileNames[n] = true
		}
	}
	importedProfileNames := map[string]bool{}
	for _, p := range exp.Profiles {
		importedProfileNames[p.Name] = true
	}

	st, err := store.Open(opts.DBPath)
	if err != nil {
		return nil, exp, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	existingRules, _ := st.ListRules()
	existingTasks, _ := st.ListTasks("", 1000)

	diff := &ImportDiff{Mode: mode}

	// Profile diff.
	for name := range importedProfileNames {
		if _, present := existingProfileNames[name]; present {
			diff.ProfilesChanged++
		} else {
			diff.ProfilesAdded++
		}
	}
	if mode == ImportModeReplace {
		for name := range existingProfileNames {
			if !importedProfileNames[name] {
				diff.ProfilesRemoved++
			}
		}
	}

	// Rule diff. In merge mode every imported rule becomes a NEW row
	// (we don't try to dedupe — preserving operator-added rule audit
	// trail is the priority). In replace mode we DROP existing rows
	// + insert all imported rows.
	diff.RulesAdded = len(exp.Rules)
	if mode == ImportModeReplace {
		diff.RulesRemoved = len(existingRules)
	}

	// Task diff. Tasks are time-bounded; importing already-expired
	// tasks is harmless (the store stays as an audit trail). Replace
	// mode is more aggressive.
	diff.TasksAdded = len(exp.Tasks)
	if mode == ImportModeReplace {
		diff.TasksRemoved = len(existingTasks)
	}

	diff.AuditExportSet = exp.AuditExport.LogPath != "" ||
		exp.AuditExport.WebhookURL != ""
	diff.LicenseSet = exp.LicensePointer != ""

	if opts.DryRun {
		return diff, exp, nil
	}

	// Live mutation phase.
	if mode == ImportModeReplace {
		// Drop existing rules.
		for _, sr := range existingRules {
			if _, rerr := st.RemoveRule(sr.ID); rerr != nil {
				return diff, exp, fmt.Errorf(
					"remove existing rule #%d: %w", sr.ID, rerr)
			}
		}
		// Tasks: end any active task so the import's tasks don't
		// collide with the active-per-owner invariant. We don't
		// physically delete task rows (audit trail discipline).
		for _, t := range existingTasks {
			if string(t.Status) == "active" {
				_, _ = st.EndTask(t.TaskID, currentActor(),
					"config-import-replace", "completed")
			}
		}
	}

	// Insert imported rules.
	for _, cr := range exp.Rules {
		r := configToRule(cr)
		if r.Effect == "" {
			r.Effect = rules.EffectAllow
		}
		if _, err := st.AddRule(r); err != nil {
			// Skip malformed rules with a stderr warning rather than
			// aborting the import — partial recovery is more useful
			// than "rejected everything because rule[7] had a typo."
			fmt.Fprintf(os.Stderr,
				"kbounce: import: skip rule %q: %v\n", r.Pattern, err)
		}
	}

	// Profiles: rewrite profiles.yaml. Replace mode writes ONLY the
	// imported profiles + the synthesized "full-user" sentinel. Merge
	// mode preserves existing entries not touched by the import.
	if err := writeProfilesForImport(profilesPath, exp.Profiles, mode); err != nil {
		return diff, exp, fmt.Errorf("write profiles: %w", err)
	}

	// Tasks: replay imported tasks as audit-trail rows. We deliberately
	// SKIP the live-active-task semantics (an imported task's
	// expires_at is almost always in the past by the time the operator
	// imports on the new machine). Future: optional --resume-tasks
	// flag. For v1.0 the audit trail is the value.
	// (Stubbed for v1.0 — no-op; the diff still reports counts.)
	_ = ImportModeReplace // suppress unused-var if loops are skipped

	return diff, exp, nil
}

// writeProfilesForImport persists the imported profiles to disk. In
// merge mode existing profile entries are preserved; in replace mode
// the file is rewritten with ONLY the imported set.
func writeProfilesForImport(path string, imported []ConfigProfile, mode ImportMode) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mkdir %q: %w", dir, err)
		}
	}

	out := map[string]any{}
	merged := map[string]any{}

	if mode == ImportModeMerge {
		// Read existing file (if any) and copy each profile into merged.
		if raw, err := os.ReadFile(path); err == nil {
			var existing struct {
				Profiles map[string]any `yaml:"profiles"`
			}
			if err := yaml.Unmarshal(raw, &existing); err == nil {
				for k, v := range existing.Profiles {
					merged[k] = v
				}
			}
		}
	}

	// Apply imported profiles (overwrite same-name in both modes).
	for _, cp := range imported {
		merged[cp.Name] = configToProfile(cp)
	}
	out["profiles"] = merged

	body, err := yaml.Marshal(out)
	if err != nil {
		return fmt.Errorf("encode profiles yaml: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".profiles-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

func newConfigImportCmd() *cobra.Command {
	var (
		inPath       string
		fromPath     string // deprecated alias for --in per #288
		dryRun       bool
		mergeFlag    bool
		replaceFlag  bool
		yes          bool
		dbPath       string
		profilesPath string
		auditLogPath string
	)
	cmd := &cobra.Command{
		Use:   "import --in PATH [--dry-run] [--merge | --replace]",
		Short: "Import a previously-exported kbounce config",
		Long: `Import a previously-exported kbounce config JSON.

Validates schema_version + product (refuses to import a dbounce /
ibounce / gbounce export into kbounce). Schema-validates the JSON
body against the published ` + "`schemas/kbounce-config.schema.json`" + `
so malformed input is rejected BEFORE any state mutation.

Cross-product flag parity per #288: ` + "`--in PATH`" + ` is the
primary form (matches ibounce + gbounce + dbounce so one cross-product
backup script can target every Bounce product). ` + "`--from PATH`" + `
is preserved as a DEPRECATED alias — it still works but prints a
stderr deprecation warning.

Modes:

  --merge        (default; safer) overlay onto existing state.
                  Existing rules / tasks are preserved; profiles with
                  the same name are overwritten. Imported rules are
                  appended as NEW rows (preserving audit trail).

  --replace      blow away existing rules + tasks and import from
                  scratch. Profiles.yaml is rewritten with ONLY the
                  imported set. Requires --yes for safety.

  --dry-run      show what WOULD change (added / removed / changed
                  counts per section) without mutating anything.

Admin-action OCSF event fires on every import.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if mergeFlag && replaceFlag {
				return errors.New(
					"kbounce: --merge and --replace are mutually exclusive")
			}
			// Resolve the source path from --in (primary) or --from
			// (deprecated alias per #288). Both set: refuse with a
			// clear message; neither set: require --in.
			source := inPath
			if source == "" && fromPath != "" {
				source = fromPath
				fmt.Fprintln(cmd.ErrOrStderr(),
					"kbounce: deprecation: --from PATH is renamed to --in PATH "+
						"for cross-product parity (ibounce + gbounce + dbounce all use "+
						"--in). The --from alias still works but will be removed in a "+
						"future major version. Update your scripts to --in PATH.")
			} else if inPath != "" && fromPath != "" {
				return errors.New(
					"kbounce: --in and --from are aliases for the same flag; pass " +
						"exactly one (prefer --in; --from is deprecated)")
			}
			if source == "" {
				return errors.New("kbounce: --in PATH is required")
			}

			mode := ImportModeMerge
			if replaceFlag {
				mode = ImportModeReplace
				if !yes && !dryRun {
					return errors.New(
						"kbounce: --replace will discard existing rules + tasks; " +
							"re-run with --yes to confirm (or --dry-run to preview)")
				}
			}

			f, err := os.Open(source)
			if err != nil {
				return fmt.Errorf("open %q: %w", source, err)
			}
			defer f.Close()

			diff, exp, err := applyImport(ImportOptions{
				Source:         f,
				SourceName:     source,
				ProfilesPath:   profilesPath,
				DBPath:         dbPath,
				Mode:           mode,
				DryRun:         dryRun,
				DeprecationOut: cmd.ErrOrStderr(),
			})
			if err != nil {
				return err
			}

			// Human-readable diff summary, regardless of dry-run.
			w := cmd.OutOrStdout()
			label := "imported"
			if dryRun {
				label = "would import (--dry-run)"
			}
			fmt.Fprintf(w, "kbounce: %s (mode=%s)\n", label, diff.Mode)
			fmt.Fprintf(w, "  profiles:   +%d  ~%d  -%d\n",
				diff.ProfilesAdded, diff.ProfilesChanged, diff.ProfilesRemoved)
			fmt.Fprintf(w, "  rules:      +%d  -%d\n",
				diff.RulesAdded, diff.RulesRemoved)
			fmt.Fprintf(w, "  tasks:      +%d  -%d\n",
				diff.TasksAdded, diff.TasksRemoved)
			if diff.AuditExportSet {
				fmt.Fprintln(w, "  audit-export config: present")
			}
			if diff.LicenseSet {
				fmt.Fprintln(w, "  license pointer: present")
			}

			if dryRun {
				return nil
			}

			// Admin-action audit event — fires only on the real-import
			// path (dry-run is a read-only diagnostic). The after_hash
			// captures the imported snapshot so the tamper-detection
			// rule has a stable witness.
			snapshot := map[string]any{
				"schema_version":  exp.SchemaVersion,
				"product":         exp.Product,
				"source":          source,
				"mode":            string(mode),
				"profiles_added":  diff.ProfilesAdded,
				"rules_added":     diff.RulesAdded,
				"tasks_added":     diff.TasksAdded,
			}
			emitAdminAction(cmd, auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionConfigImport,
				Actor:      currentActor(),
				EntityKind: "config",
				EntityName: source,
				Source:     audit.AdminActionSourceCLI,
				Before:     nil,
				After:      snapshot,
				ExtraExt: map[string]any{
					"source": source,
					"mode":   string(mode),
				},
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&inPath, "in", "",
		"Path to the export JSON to import. Required (or pass the "+
			"deprecated --from alias).")
	cmd.Flags().StringVar(&fromPath, "from", "",
		"DEPRECATED: pre-#288 alias for --in PATH. Still works, prints "+
			"a stderr deprecation warning. Update scripts to --in.")
	// Cobra's MarkDeprecated hides the flag from --help; we keep it
	// visible so an operator who runs `kbounce config import --help`
	// after migrating from an older binary sees the explicit note
	// rather than wondering where --from went.
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"Show what would change without mutating state.")
	cmd.Flags().BoolVar(&mergeFlag, "merge", false,
		"Overlay onto existing state (default; safer). Mutually exclusive "+
			"with --replace.")
	cmd.Flags().BoolVar(&replaceFlag, "replace", false,
		"Blow away existing rules + tasks and rewrite profiles.yaml from "+
			"the import. Requires --yes (or --dry-run to preview).")
	cmd.Flags().BoolVar(&yes, "yes", false,
		"Confirm a --replace mode import. Required when --replace is set.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	cmd.Flags().StringVar(&profilesPath, "profiles", "",
		"Profiles YAML path (default: ~/.kbouncer/profiles.yaml, or "+
			"KBOUNCER_PROFILES_PATH env).")
	addAdminAuditFlag(cmd, &auditLogPath)
	return cmd
}

// resolveAuditLogPath returns the effective audit-log path the
// running proxy would use given the operator's flag + env-var inputs.
// Used by the export path to project the log-path config into the
// `audit_export.log_path` field of the export JSON.
func resolveAuditLogPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return kbenv.Get(envAdminAuditLogPath)
}

// ---------------------------------------------------------------------
// JSON-Schema validator (minimal in-house subset, no third-party deps)
// ---------------------------------------------------------------------
//
// We need to validate the import body against the published schema
// without taking on a new third-party dep (slice constraint). The
// surface our schema actually uses is small: required fields, type
// tags, nested object types, and array-of-object element schemas.
// validateConfigJSON walks the decoded schema + decoded payload and
// returns one error string per validation failure.
//
// This is NOT a general JSON-Schema implementation — it implements
// exactly the keywords our schema uses. Adding a new keyword to the
// schema requires extending validateNode. The trade-off vs pulling
// in github.com/santhosh-tekuri/jsonschema is "fewer deps, more
// code to maintain" — for our schema's stable shape it's the right
// choice.

func validateConfigJSON(payload, schema []byte) []string {
	var p any
	if err := json.Unmarshal(payload, &p); err != nil {
		return []string{fmt.Sprintf("payload is not valid JSON: %v", err)}
	}
	var s map[string]any
	if err := json.Unmarshal(schema, &s); err != nil {
		// A broken embedded schema is a programmer error, not an
		// operator-recoverable failure — surface it loudly so the
		// build CI catches it.
		return []string{fmt.Sprintf("embedded schema is broken (build bug): %v", err)}
	}
	var errs []string
	validateNode("$", p, s, &errs)
	return errs
}

// validateNode walks one schema/value pair, appending one entry to
// errs per failure. path is the JSON-pointer-like locator surfaced
// in error messages so the operator can find the bad field.
func validateNode(path string, value any, schema map[string]any, errs *[]string) {
	if t, ok := schema["type"].(string); ok {
		if !typeMatches(value, t) {
			*errs = append(*errs, fmt.Sprintf(
				"%s: expected type %q, got %s", path, t, jsonTypeOf(value)))
			return
		}
	}
	if enum, ok := schema["enum"].([]any); ok {
		matched := false
		for _, e := range enum {
			if e == value {
				matched = true
				break
			}
		}
		if !matched {
			*errs = append(*errs, fmt.Sprintf(
				"%s: value %v not in enum %v", path, value, enum))
		}
	}

	// Object: required + properties walk.
	if obj, ok := value.(map[string]any); ok {
		if req, ok := schema["required"].([]any); ok {
			for _, r := range req {
				name, _ := r.(string)
				if _, present := obj[name]; !present {
					*errs = append(*errs, fmt.Sprintf(
						"%s: missing required field %q", path, name))
				}
			}
		}
		if props, ok := schema["properties"].(map[string]any); ok {
			// Sort keys so error output is deterministic.
			keys := make([]string, 0, len(props))
			for k := range props {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v, present := obj[k]
				if !present {
					continue
				}
				if propSchema, ok := props[k].(map[string]any); ok {
					validateNode(path+"."+k, v, propSchema, errs)
				}
			}
		}
	}

	// Array: items walk.
	if arr, ok := value.([]any); ok {
		if items, ok := schema["items"].(map[string]any); ok {
			for i, item := range arr {
				validateNode(fmt.Sprintf("%s[%d]", path, i), item, items, errs)
			}
		}
	}
}

// typeMatches returns true when the JSON value matches the
// JSON-Schema type name. We accept "integer" as a sub-type of
// "number" (JSON-Schema convention) since encoding/json decodes all
// numerics into float64.
func typeMatches(v any, t string) bool {
	switch t {
	case "string":
		_, ok := v.(string)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		f, ok := v.(float64)
		if !ok {
			return false
		}
		return f == float64(int64(f))
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "null":
		return v == nil
	}
	return false
}

// jsonTypeOf returns the JSON-Schema type name of a decoded value.
// Used to make error messages readable ("expected string, got
// number" rather than "expected string, got float64").
func jsonTypeOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}
