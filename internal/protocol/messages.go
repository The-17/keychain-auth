package protocol

// MessageType enumerates all valid protocol message types.
type MessageType string

const (
    TypeSessionInit     MessageType = "SESSION_INIT"
    TypeSessionAccepted MessageType = "SESSION_ACCEPTED"
    TypeSessionRejected MessageType = "SESSION_REJECTED"
    TypeSecretRequest   MessageType = "SECRET_REQUEST"
    TypeSecretResponse  MessageType = "SECRET_RESPONSE"
    TypeSecretDenied    MessageType = "SECRET_DENIED"
    TypeError           MessageType = "ERROR"
)

// RejectReason enumerates all valid rejection/denial reason codes.
type RejectReason string

const (
    ReasonHashMismatch        RejectReason = "HASH_MISMATCH"
    ReasonInvalidPID          RejectReason = "INVALID_PID"
    ReasonPathMismatch        RejectReason = "PATH_MISMATCH"
    ReasonUnsupportedProtocol RejectReason = "UNSUPPORTED_PROTOCOL"
    ReasonUnknownSession      RejectReason = "UNKNOWN_SESSION"
    ReasonSessionExpired      RejectReason = "SESSION_EXPIRED"
    ReasonSessionInvalidated  RejectReason = "SESSION_INVALIDATED"
    ReasonSecretNotFound      RejectReason = "SECRET_NOT_FOUND"
    ReasonInvalidKey          RejectReason = "INVALID_KEY"
    ReasonUnknownMessageType  RejectReason = "UNKNOWN_MESSAGE_TYPE"
)

// Envelope is used for initial JSON unmarshalling to determine message type.
type Envelope struct {
    Type MessageType `json:"type"`
}

// --- Inbound messages (AgentSecrets → keychain-auth) ---

type SessionInit struct {
    Type            MessageType `json:"type"`              // Must be "SESSION_INIT"
    PID             int         `json:"pid"`
    BinaryPath      string      `json:"binary_path"`
    BinaryHash      string      `json:"binary_hash"`       // Format: "sha256:<hex>"
    ProtocolVersion string      `json:"protocol_version"`  // Must be "1"
}

// SecretRequest includes project_id and environment because AgentSecrets
// stores secrets as "{projectID}:{environment}:{key}" in the OS keychain.
type SecretRequest struct {
    Type         MessageType `json:"type"`           // Must be "SECRET_REQUEST"
    SessionToken string      `json:"session_token"`  // 64-char hex string
    ProjectID    string      `json:"project_id"`     // AgentSecrets project ID
    Environment  string      `json:"environment"`    // "development", "staging", "production"
    Key          string      `json:"key"`            // Bare key name (e.g., "OPENAI_API_KEY")
}

// --- Outbound messages (keychain-auth → AgentSecrets) ---

type SessionAccepted struct {
    Type         MessageType `json:"type"`          // "SESSION_ACCEPTED"
    SessionToken string      `json:"session_token"` // 64-char hex string
}

type SessionRejected struct {
    Type   MessageType  `json:"type"`   // "SESSION_REJECTED"
    Reason RejectReason `json:"reason"`
}

type SecretResponse struct {
    Type  MessageType `json:"type"`  // "SECRET_RESPONSE"
    Key   string      `json:"key"`
    Value string      `json:"value"` // ⚠️ NEVER LOG THIS FIELD
}

type SecretDenied struct {
    Type   MessageType  `json:"type"`   // "SECRET_DENIED"
    Key    string       `json:"key"`
    Reason RejectReason `json:"reason"`
}

type ErrorResponse struct {
    Type   MessageType  `json:"type"`   // "ERROR"
    Reason RejectReason `json:"reason"`
}
