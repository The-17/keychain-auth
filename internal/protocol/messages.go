package protocol

// MessageType enumerates all valid protocol message types.
type MessageType string

const (
	TypeRequest  MessageType = "REQUEST"
	TypeResponse MessageType = "RESPONSE"
)

// ActionType enumerates the permitted keychain operations.
type ActionType string

const (
	ActionRead   ActionType = "read"
	ActionWrite  ActionType = "write"
	ActionDelete ActionType = "delete"
	ActionSearch ActionType = "search"
)

// MatchType controls how targets are interpreted.
type MatchType string

const (
	// MatchExact is the default: each target is an exact key name.
	MatchExact MatchType = "exact"
	// MatchPrefix treats each target as a prefix filter.
	// For "read": internally searches, filters by prefix, then reads values.
	// For "search": filters results by prefix (existing behavior).
	// For "delete": searches, filters by prefix, then deletes matches.
	MatchPrefix MatchType = "prefix"
)

// ReasonCode enumerates granular rejection/error reasons for the audit log and clients.
type ReasonCode string

const (
	ReasonUnregisteredBinaryPendingApproval ReasonCode = "unregistered_binary_pending_approval"
	ReasonActionNotInPolicy                 ReasonCode = "action_not_in_policy"
	ReasonServiceNotAllowed                 ReasonCode = "service_not_allowed"
	ReasonTargetNotAllowed                  ReasonCode = "target_not_allowed"
	ReasonMalformedRequest                  ReasonCode = "malformed_request"
	ReasonHashMismatchDuringFork            ReasonCode = "hash_mismatch_during_fork"
	ReasonInternalError                     ReasonCode = "internal_error"
)

// Envelope is used for initial JSON unmarshalling to determine message type.
type Envelope struct {
	Type MessageType `json:"type"`
}

// Request is the single, generalized structure sent by clients for any operation.
// It supports batch processing via the Targets array.
type Request struct {
	Type       MessageType       `json:"type"`       // Must be "REQUEST"
	Action     ActionType        `json:"action"`     // read, write, delete, search
	Service    string            `json:"service"`    // OS keychain service namespace (e.g. "aws")
	Match      MatchType         `json:"match,omitempty"` // "exact" (default) or "prefix"
	Targets    []string          `json:"targets,omitempty"` // The keys/accounts being acted upon
	Values     []string          `json:"values,omitempty"`  // Values to write (must align with Targets length)
	Attributes map[string]string `json:"attributes,omitempty"` // Metadata filters for searches or specific keys
}

// ResultItem represents a single returned target from a search or read operation.
type ResultItem struct {
	Target     string            `json:"target"`
	Value      string            `json:"value,omitempty"` // ⚠️ Only populated on authorized reads. Never logged.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Response is sent by the daemon. It supports batch results.
type Response struct {
	Type    MessageType  `json:"type"`             // Must be "RESPONSE"
	Status  string       `json:"status"`           // "success", "denied", "error"
	Reason  ReasonCode   `json:"reason,omitempty"` // Required if Status is not "success"
	Results []ResultItem `json:"results,omitempty"`
}
