// agent_header_rejection.go ships the §A18 / #320 structured
// rejection breadcrumb that lands at
// `unmapped.iam_jit.ext.agent_header_rejection` whenever an inbound
// `X-Agent-Name` or `X-Agent-Session-Id` header fails validation.
//
// Same shape across all four Bounce products per
// [[cross-product-agent-parity]] — a SIEM filter on
// `unmapped.iam_jit.ext.agent_header_rejection.reason=
// invalid_name_charset` resolves uniformly across ibounce + kbounce
// + dbounce + gbounce.
//
// Per [[security-team-positioning-safety-not-surveillance]] the
// breadcrumb is "audit transparency" — operator visibility into a
// validation rejection — not "violation" framing. A rejected header
// is most often a misconfigured agent SDK, not an attack. The raw
// rejected value is NEVER included; only its length, for safe
// forensics.

package audit

// AgentHeaderRejectionReason names the enumerated reasons an inbound
// X-Agent-* header can fail validation. Bounded set so SIEM filters
// can rely on a closed vocabulary; new reasons land here when the
// validation regex evolves.
type AgentHeaderRejectionReason string

const (
	AgentHeaderRejectionInvalidNameCharset         AgentHeaderRejectionReason = "invalid_name_charset"
	AgentHeaderRejectionInvalidNameLength          AgentHeaderRejectionReason = "invalid_name_length"
	AgentHeaderRejectionInvalidSessionIDFormat     AgentHeaderRejectionReason = "invalid_session_id_format"
	AgentHeaderRejectionInvalidSessionIDLength     AgentHeaderRejectionReason = "invalid_session_id_length"
	AgentHeaderRejectionApplicationNameUnparseable AgentHeaderRejectionReason = "application_name_unparseable"
)

// AgentNameField + AgentSessionIDField name the canonical header
// fields that the rejection breadcrumb references.
const (
	AgentNameField      = "X-Agent-Name"
	AgentSessionIDField = "X-Agent-Session-Id"
)

// ClassifyAgentNameRejection returns the canonical
// AgentHeaderRejectionReason for a raw X-Agent-Name value that
// already failed IsValidAgentName.
func ClassifyAgentNameRejection(raw string) AgentHeaderRejectionReason {
	if len(raw) > 64 {
		return AgentHeaderRejectionInvalidNameLength
	}
	return AgentHeaderRejectionInvalidNameCharset
}

// ClassifyAgentSessionIDRejection returns the canonical
// AgentHeaderRejectionReason for a raw X-Agent-Session-Id value
// that already failed IsValidSessionID.
func ClassifyAgentSessionIDRejection(raw string) AgentHeaderRejectionReason {
	if len(raw) > 128 {
		return AgentHeaderRejectionInvalidSessionIDLength
	}
	return AgentHeaderRejectionInvalidSessionIDFormat
}

// BuildAgentHeaderRejectionBreadcrumb produces the per-rejection
// entry shape that lands at
// `unmapped.iam_jit.ext.agent_header_rejection` (when single) or as
// one element of a list (when multiple). NEVER include the raw
// value — only its length, for safe forensics.
func BuildAgentHeaderRejectionBreadcrumb(field string, reason AgentHeaderRejectionReason, rawValueLength int) map[string]any {
	return map[string]any{
		"field":                 field,
		"reason":                string(reason),
		"value_redacted_length": rawValueLength,
	}
}
