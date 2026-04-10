package protocol

import (
    "encoding/json"
    "fmt"
)

// ParseMessage takes raw JSON bytes, determines the message type via Envelope,
// then unmarshals into the appropriate concrete struct.
//
// Returns:
//   - (MessageType, parsed struct, nil) on success
//   - ("", nil, error) on malformed JSON
//   - (type, nil, error) if the type is unknown (caller should send ERROR + close)
func ParseMessage(raw []byte) (MessageType, any, error) {
    var env Envelope
    if err := json.Unmarshal(raw, &env); err != nil {
        return "", nil, fmt.Errorf("malformed JSON: %w", err)
    }
    switch env.Type {
    case TypeSessionInit:
        var msg SessionInit
        if err := json.Unmarshal(raw, &msg); err != nil {
            return env.Type, nil, fmt.Errorf("invalid SESSION_INIT: %w", err)
        }
        return env.Type, &msg, nil
    case TypeSecretRequest:
        var msg SecretRequest
        if err := json.Unmarshal(raw, &msg); err != nil {
            return env.Type, nil, fmt.Errorf("invalid SECRET_REQUEST: %w", err)
        }
        return env.Type, &msg, nil
    default:
        return env.Type, nil, fmt.Errorf("unknown message type: %s", env.Type)
    }
}
