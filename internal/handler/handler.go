package handler

import (
    "io"
    "log"
    "net"

    "github.com/The-17/keychain-auth/internal/audit"
    "github.com/The-17/keychain-auth/internal/config"
    "github.com/The-17/keychain-auth/internal/keychain"
    "github.com/The-17/keychain-auth/internal/namespace"
    "github.com/The-17/keychain-auth/internal/protocol"
    "github.com/The-17/keychain-auth/internal/session"
    "github.com/The-17/keychain-auth/internal/verify"
)

type Handler struct {
    sessions *session.Store
    verifier verify.Verifier
    keychain keychain.Reader
    audit    *audit.Logger
    config   *config.Config
}

func New(
    sessions *session.Store,
    verifier verify.Verifier,
    kc keychain.Reader,
    auditLog *audit.Logger,
    cfg *config.Config,
) *Handler {
    return &Handler{
        sessions: sessions,
        verifier: verifier,
        keychain: kc,
        audit:    auditLog,
        config:   cfg,
    }
}

// Handle processes messages on a single connection until it closes or errors.
// One message in, one message out, sequentially. No pipelining.
func (h *Handler) Handle(conn net.Conn) {
    defer conn.Close()

    dec := protocol.NewDecoder(conn)
    enc := protocol.NewEncoder(conn)

    for {
        raw, err := dec.ReadRaw()
        if err != nil {
            if err == io.EOF {
                return
            }
            log.Printf("connection read error: %v", err)
            return
        }

        msgType, msg, err := protocol.ParseMessage(raw)
        if err != nil {
            if msgType != "" {
                enc.Write(protocol.ErrorResponse{
                    Type:   protocol.TypeError,
                    Reason: protocol.ReasonUnknownMessageType,
                })
            }
            return // Close connection on malformed/unknown messages
        }

        switch msgType {
        case protocol.TypeSessionInit:
            h.handleSessionInit(enc, msg.(*protocol.SessionInit))
        case protocol.TypeSecretRequest:
            h.handleSecretRequest(enc, msg.(*protocol.SecretRequest))
        }
    }
}

func (h *Handler) handleSessionInit(enc *protocol.Encoder, msg *protocol.SessionInit) {
    // Step 0: Validate protocol version
    if msg.ProtocolVersion != "1" {
        h.logAndReject(enc, msg.PID, msg.BinaryPath, protocol.ReasonUnsupportedProtocol)
        return
    }

    // Step 1: Validate the PID
    osPath, err := h.verifier.ResolveBinaryPath(msg.PID)
    if err != nil {
        h.logAndReject(enc, msg.PID, msg.BinaryPath, protocol.ReasonInvalidPID)
        return
    }

    // Step 2: Verify the binary path — OS ground truth vs. claimed
    if osPath != msg.BinaryPath {
        h.logAndReject(enc, msg.PID, msg.BinaryPath, protocol.ReasonPathMismatch)
        return
    }

    // Step 3a: Compute file hash
    fileHash, err := verify.HashBinary(osPath)
    if err != nil {
        h.logAndReject(enc, msg.PID, osPath, protocol.ReasonHashMismatch)
        return
    }

    // Step 3b: File hash must match what AgentSecrets claims
    if fileHash != msg.BinaryHash {
        h.logAndReject(enc, msg.PID, osPath, protocol.ReasonHashMismatch)
        return
    }

    // Step 3c: File hash must match a registered binary
    if h.config.FindByHash(fileHash) == nil {
        h.logAndReject(enc, msg.PID, osPath, protocol.ReasonHashMismatch)
        return
    }

    // Step 4: Issue session token
    sess, replaced := h.sessions.Create(msg.PID, osPath, fileHash)

    if replaced {
        log.Printf("WARN: replaced existing session for PID %d", msg.PID)
        h.audit.Log(audit.Event{
            EventType:          "SESSION_REPLACED",
            PID:                msg.PID,
            BinaryPath:         osPath,
            Result:             "REPLACED",
            SessionTokenPrefix: sess.TokenPrefix(),
        })
    }

    h.audit.Log(audit.Event{
        EventType:          "SESSION_INIT",
        PID:                msg.PID,
        BinaryPath:         osPath,
        Result:             "ACCEPTED",
        SessionTokenPrefix: sess.TokenPrefix(),
    })

    enc.Write(protocol.SessionAccepted{
        Type:         protocol.TypeSessionAccepted,
        SessionToken: sess.TokenHex(),
    })
}

func (h *Handler) handleSecretRequest(enc *protocol.Encoder, msg *protocol.SecretRequest) {
    // Step 1: Look up the session
    sess := h.sessions.Lookup(msg.SessionToken)
    if sess == nil {
        h.audit.Log(audit.Event{
            EventType: "SECRET_REQUEST",
            Key:       msg.Key,
            Result:    "DENIED",
            Reason:    string(protocol.ReasonUnknownSession),
        })
        enc.Write(protocol.SecretDenied{
            Type: protocol.TypeSecretDenied, Key: msg.Key,
            Reason: protocol.ReasonUnknownSession,
        })
        return
    }

    // Step 2: Re-validate PID is still alive
    alive, err := h.verifier.IsProcessAlive(sess.PID)
    if err != nil || !alive {
        h.sessions.Invalidate(msg.SessionToken)
        h.auditDeny(sess, msg.Key, msg.ProjectID, msg.Environment, protocol.ReasonSessionExpired)
        enc.Write(protocol.SecretDenied{
            Type: protocol.TypeSecretDenied, Key: msg.Key,
            Reason: protocol.ReasonSessionExpired,
        })
        return
    }

    // Step 3: Re-validate the binary has not changed
    osPath, err := h.verifier.ResolveBinaryPath(sess.PID)
    if err != nil {
        h.sessions.Invalidate(msg.SessionToken)
        h.auditDeny(sess, msg.Key, msg.ProjectID, msg.Environment, protocol.ReasonSessionInvalidated)
        enc.Write(protocol.SecretDenied{
            Type: protocol.TypeSecretDenied, Key: msg.Key,
            Reason: protocol.ReasonSessionInvalidated,
        })
        return
    }

    currentHash, err := verify.HashBinary(osPath)
    if err != nil || currentHash != sess.BinaryHash {
        h.sessions.Invalidate(msg.SessionToken)
        h.auditDeny(sess, msg.Key, msg.ProjectID, msg.Environment, protocol.ReasonSessionInvalidated)
        enc.Write(protocol.SecretDenied{
            Type: protocol.TypeSecretDenied, Key: msg.Key,
            Reason: protocol.ReasonSessionInvalidated,
        })
        return
    }

    // Step 4: Validate all key components
    if err := namespace.ValidateKey(msg.Key); err != nil {
        h.auditDeny(sess, msg.Key, msg.ProjectID, msg.Environment, protocol.ReasonInvalidKey)
        enc.Write(protocol.SecretDenied{
            Type: protocol.TypeSecretDenied, Key: msg.Key,
            Reason: protocol.ReasonInvalidKey,
        })
        return
    }
    if err := namespace.ValidateProjectID(msg.ProjectID); err != nil {
        h.auditDeny(sess, msg.Key, msg.ProjectID, msg.Environment, protocol.ReasonInvalidKey)
        enc.Write(protocol.SecretDenied{
            Type: protocol.TypeSecretDenied, Key: msg.Key,
            Reason: protocol.ReasonInvalidKey,
        })
        return
    }
    if err := namespace.ValidateEnvironment(msg.Environment); err != nil {
        h.auditDeny(sess, msg.Key, msg.ProjectID, msg.Environment, protocol.ReasonInvalidKey)
        enc.Write(protocol.SecretDenied{
            Type: protocol.TypeSecretDenied, Key: msg.Key,
            Reason: protocol.ReasonInvalidKey,
        })
        return
    }

    // Step 5: Construct the keychain key and read
    keychainKey := namespace.KeychainKey(msg.ProjectID, msg.Environment, msg.Key)

    // Final namespace guard: verify the constructed key matches the allowed pattern
    if !namespace.IsAllowedKeychainKey(keychainKey) {
        h.auditDeny(sess, msg.Key, msg.ProjectID, msg.Environment, protocol.ReasonInvalidKey)
        enc.Write(protocol.SecretDenied{
            Type: protocol.TypeSecretDenied, Key: msg.Key,
            Reason: protocol.ReasonInvalidKey,
        })
        return
    }

    value, err := h.keychain.Read(keychainKey)
    if err != nil {
        // Fallback for legacy AgentSecrets data format (development only)
        if msg.Environment == "development" || msg.Environment == "" {
            legacyKey := namespace.LegacyKeychainKey(msg.ProjectID, msg.Key)
            value, err = h.keychain.Read(legacyKey)
        }
        
        if err != nil {
            h.auditDeny(sess, msg.Key, msg.ProjectID, msg.Environment, protocol.ReasonSecretNotFound)
            enc.Write(protocol.SecretDenied{
                Type: protocol.TypeSecretDenied, Key: msg.Key,
                Reason: protocol.ReasonSecretNotFound,
            })
            return
        }
    }

    // Step 6: Log the grant and return the secret
    h.audit.Log(audit.Event{
        EventType:          "SECRET_REQUEST",
        PID:                sess.PID,
        BinaryPath:         sess.BinaryPath,
        ProjectID:          msg.ProjectID,
        Environment:        msg.Environment,
        Key:                msg.Key,
        Result:             "GRANTED",
        SessionTokenPrefix: sess.TokenPrefix(),
    })

    // ⚠️ ONLY place a secret value is transmitted. NEVER log this.
    enc.Write(protocol.SecretResponse{
        Type:  protocol.TypeSecretResponse,
        Key:   msg.Key,
        Value: value,
    })
}

// --- Helper methods ---

func (h *Handler) logAndReject(enc *protocol.Encoder, pid int, binaryPath string, reason protocol.RejectReason) {
    h.audit.Log(audit.Event{
        EventType:  "SESSION_INIT",
        PID:        pid,
        BinaryPath: binaryPath,
        Result:     "REJECTED",
        Reason:     string(reason),
    })
    enc.Write(protocol.SessionRejected{
        Type:   protocol.TypeSessionRejected,
        Reason: reason,
    })
}

func (h *Handler) auditDeny(sess *session.Session, key, projectID, env string, reason protocol.RejectReason) {
    h.audit.Log(audit.Event{
        EventType:          "SECRET_REQUEST",
        PID:                sess.PID,
        BinaryPath:         sess.BinaryPath,
        ProjectID:          projectID,
        Environment:        env,
        Key:                key,
        Result:             "DENIED",
        Reason:             string(reason),
        SessionTokenPrefix: sess.TokenPrefix(),
    })
}
