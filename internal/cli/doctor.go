// `kbounce doctor` — operator-friendly health + caveat surface.
//
// Per task #304 + the founder direction "caveats must be easily
// discoverable to users + agents, not buried in docs/KNOWN-CAVEATS.md":
// `kbounce doctor caveats` lists every §B entry that genuinely applies
// to kbounce + links to the canonical doc.
//
// Sibling Bounce products ship the same `*bounce doctor caveats`
// subcommand shape per [[cross-product-agent-parity]] so an operator's
// muscle memory ("run doctor on the bouncer you're confused by") works
// uniformly across kbounce / dbounce / ibounce / gbounce.
//
// Per [[creates-never-mutates]]: this is a strictly READ-ONLY command.
// Per [[security-team-positioning-safety-not-surveillance]]: language
// is helpful, never accusatory.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/kbouncer/internal/caveats"
)

// newDoctorCmd assembles `kbounce doctor` + the `caveats` subcommand.
func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Operator-friendly health + caveat surfaces",
		Long: `Subcommands:

  caveats   Print the §B entries from KNOWN-CAVEATS.md that apply to
            kbounce (including cross-product entries shared with the
            other Bounce products).

Sibling Bounce products (ibounce / dbounce / gbounce) ship the same
` + "`{product} doctor caveats`" + ` subcommand. The full canonical doc
lives at ` + caveats.CanonicalDocURL() + `.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		return fmt.Errorf("kbounce doctor: subcommand required (try `kbounce doctor caveats` or `kbounce doctor logs`)")
	}
	cmd.AddCommand(newDoctorCaveatsCmd())
	// #311 / §A10 — audit-log integrity / freshness / disk check.
	cmd.AddCommand(newDoctorLogsCmd())
	return cmd
}

func newDoctorCaveatsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "caveats",
		Short: "Print KNOWN-CAVEATS §B entries that apply to kbounce",
		Long: `Print the §B (documented limits, not launch-blocking) entries
from KNOWN-CAVEATS.md that apply to kbounce.

Full canonical doc: ` + caveats.CanonicalDocURL() + `

Per [[creates-never-mutates]]: read-only.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			fmt.Fprintln(w, "kbounce: KNOWN-CAVEATS §B entries that apply to this product")
			fmt.Fprintln(w, "Full canonical doc:", caveats.CanonicalDocURL())
			fmt.Fprintln(w)
			for _, e := range caveats.DoctorEntries() {
				fmt.Fprintf(w, "§%s\n", e.ID)
				fmt.Fprintf(w, "  %s\n", e.DoctorBlurb)
				fmt.Fprintf(w, "  link: %s\n\n", e.URL())
			}
			return nil
		},
	}
}
