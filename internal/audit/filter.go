// filter.go ships the cross-product filter expression parser + matcher
// used by both `kbounce audit tail --filter` (CLI) and
// GET /audit/events?filter=... (HTTP, #271).
//
// Lives in the audit package so both `internal/cli` (the CLI surface)
// and `internal/proxy` (the HTTP surface) can call into it without
// creating an import cycle (cli imports proxy; proxy importing cli
// would loop).
//
// Grammar (per [[cross-product-agent-parity]] — ibounce + dbounce +
// gbounce ship the identical grammar):
//
//	field=value        string equality (case-sensitive)
//	field~regex        Go RE2 regex match
//	field>=N           numeric greater-or-equal
//	field<=N           numeric less-or-equal
//
// Supported fields are the cross-product OCSF allowlist + the kbounce-
// native resource.* fields (kubectl namespace / resource / name).
//
// The matcher walks the OCSF Event struct (NOT a re-marshaled map) so
// nested-path lookups are zero-allocation in the hot path of
// `--follow` + the HTTP poll loop.

package audit

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SupportedFilterFields is the cross-product field allowlist for
// `--filter` / `?filter=` expressions. Exported so help text + error
// messages can list the valid choices.
func SupportedFilterFields() []string {
	return []string{
		// Cross-product OCSF.
		"severity_id",
		"activity_id",
		"status_id",
		"actor.user.name",
		"api.operation",
		"unmapped.iam_jit.agent.name",
		"unmapped.iam_jit.agent.session_id",
		"unmapped.iam_jit.event_type",
		"unmapped.iam_jit.verdict",
		"unmapped.iam_jit.mode",
		"unmapped.iam_jit.profile",
		"unmapped.iam_jit.enforced",
		// kbounce-native extension fields.
		"resource.namespace",
		"resource.name",
		"resource.type",
	}
}

// FilterOp is one of the four supported comparison ops.
type FilterOp int

const (
	FilterOpEq  FilterOp = iota // field=value
	FilterOpRe                  // field~regex
	FilterOpGTE                 // field>=N
	FilterOpLTE                 // field<=N
)

// Filter is one parsed expression. Re is non-nil only for FilterOpRe.
type Filter struct {
	Raw   string
	Field string
	Op    FilterOp
	Value string
	Num   float64
	Re    *regexp.Regexp
}

// ParseFilter parses one expression into a Filter. Errors include the
// raw input so an operator can pinpoint which --filter flag was wrong.
//
// Order matters: ">=" and "<=" are two chars, must be checked before
// single-char "=". "~" is single-char and unambiguous.
func ParseFilter(raw string) (Filter, error) {
	switch {
	case strings.Contains(raw, ">="):
		return parseNumericFilter(raw, ">=", FilterOpGTE)
	case strings.Contains(raw, "<="):
		return parseNumericFilter(raw, "<=", FilterOpLTE)
	case strings.Contains(raw, "~"):
		field, value, ok := splitFilterOnce(raw, "~")
		if !ok || field == "" {
			return Filter{}, fmt.Errorf("filter %q: expected field~regex", raw)
		}
		if !isSupportedFilterField(field) {
			return Filter{}, unsupportedFieldErr(raw, field)
		}
		re, err := regexp.Compile(value)
		if err != nil {
			return Filter{}, fmt.Errorf("filter %q: invalid regex: %w", raw, err)
		}
		return Filter{Raw: raw, Field: field, Op: FilterOpRe, Value: value, Re: re}, nil
	case strings.Contains(raw, "="):
		field, value, ok := splitFilterOnce(raw, "=")
		if !ok || field == "" {
			return Filter{}, fmt.Errorf("filter %q: expected field=value", raw)
		}
		if !isSupportedFilterField(field) {
			return Filter{}, unsupportedFieldErr(raw, field)
		}
		return Filter{Raw: raw, Field: field, Op: FilterOpEq, Value: value}, nil
	}
	return Filter{}, fmt.Errorf("filter %q: no operator (=, ~, >=, <=)", raw)
}

// ParseFilters runs ParseFilter on each input expression. Returns the
// first error so the operator sees ONE actionable message rather than
// a wall of errors. AND semantics — every filter must match.
func ParseFilters(exprs []string) ([]Filter, error) {
	out := make([]Filter, 0, len(exprs))
	for _, e := range exprs {
		f, err := ParseFilter(e)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

func parseNumericFilter(raw, sep string, op FilterOp) (Filter, error) {
	field, value, ok := splitFilterOnce(raw, sep)
	if !ok || field == "" {
		return Filter{}, fmt.Errorf("filter %q: expected field%sN", raw, sep)
	}
	if !isSupportedFilterField(field) {
		return Filter{}, unsupportedFieldErr(raw, field)
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return Filter{}, fmt.Errorf("filter %q: numeric op %s needs a number, got %q", raw, sep, value)
	}
	return Filter{Raw: raw, Field: field, Op: op, Value: value, Num: n}, nil
}

func splitFilterOnce(s, sep string) (string, string, bool) {
	i := strings.Index(s, sep)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+len(sep):], true
}

func isSupportedFilterField(field string) bool {
	for _, f := range SupportedFilterFields() {
		if f == field {
			return true
		}
	}
	return false
}

func unsupportedFieldErr(raw, field string) error {
	return fmt.Errorf("filter %q: field %q not supported (try one of: %s)",
		raw, field, strings.Join(SupportedFilterFields(), ", "))
}

// MatchAll returns true when every filter matches the event.
func MatchAll(ev Event, filters []Filter) bool {
	for _, f := range filters {
		if !match(ev, f) {
			return false
		}
	}
	return true
}

func match(ev Event, f Filter) bool {
	switch f.Op {
	case FilterOpEq:
		return EventFieldString(ev, f.Field) == f.Value
	case FilterOpRe:
		return f.Re.MatchString(EventFieldString(ev, f.Field))
	case FilterOpGTE:
		n, ok := EventFieldNumeric(ev, f.Field)
		return ok && n >= f.Num
	case FilterOpLTE:
		n, ok := EventFieldNumeric(ev, f.Field)
		return ok && n <= f.Num
	}
	return false
}

// EventFieldString projects an OCSF Event down to one named field as a
// string. Returns "" for absent fields — equality against "" then
// matches the absence-of-value case (intentional; matches
// `jq -r '.field // ""'` semantics).
func EventFieldString(ev Event, field string) string {
	switch field {
	case "severity_id":
		return strconv.Itoa(ev.SeverityID)
	case "activity_id":
		return strconv.Itoa(ev.ActivityID)
	case "status_id":
		return strconv.Itoa(ev.StatusID)
	case "actor.user.name":
		if ev.Actor != nil && ev.Actor.User != nil {
			return ev.Actor.User.Name
		}
		return ""
	case "api.operation":
		return ev.API.Operation
	case "unmapped.iam_jit.agent.name":
		if ev.Unmapped.IAMJIT.Agent != nil {
			return ev.Unmapped.IAMJIT.Agent.Name
		}
		return ""
	case "unmapped.iam_jit.agent.session_id":
		if ev.Unmapped.IAMJIT.Agent != nil {
			return ev.Unmapped.IAMJIT.Agent.SessionID
		}
		return ""
	case "unmapped.iam_jit.event_type":
		return ev.Unmapped.IAMJIT.EventType
	case "unmapped.iam_jit.verdict":
		return ev.Unmapped.IAMJIT.Verdict
	case "unmapped.iam_jit.mode":
		return ev.Unmapped.IAMJIT.Mode
	case "unmapped.iam_jit.profile":
		return ev.Unmapped.IAMJIT.Profile
	case "unmapped.iam_jit.enforced":
		if ev.Unmapped.IAMJIT.Enforced {
			return "true"
		}
		return "false"
	case "resource.namespace":
		if v, ok := ev.Unmapped.IAMJIT.Ext["namespace"].(string); ok {
			return v
		}
		return ""
	case "resource.name":
		if len(ev.Resources) > 0 {
			return ev.Resources[0].Name
		}
		return ""
	case "resource.type":
		if len(ev.Resources) > 0 {
			return ev.Resources[0].Type
		}
		return ""
	}
	return ""
}

// EventFieldNumeric returns the float64 view used by `>=` / `<=`. Only
// id-shaped fields are numeric in OCSF; everything else returns
// (0, false) so a numeric filter on a string field cleanly misses
// instead of silently matching 0.
func EventFieldNumeric(ev Event, field string) (float64, bool) {
	switch field {
	case "severity_id":
		return float64(ev.SeverityID), true
	case "activity_id":
		return float64(ev.ActivityID), true
	case "status_id":
		return float64(ev.StatusID), true
	}
	return 0, false
}

// ensure errors uses the standard library — keeps go vet happy when
// the only error producer in this file is fmt.Errorf.
var _ = errors.New
