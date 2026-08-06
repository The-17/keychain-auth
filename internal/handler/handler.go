package handler

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/The-17/keychain-auth/internal/audit"
	"github.com/The-17/keychain-auth/internal/config"
	"github.com/The-17/keychain-auth/internal/keychain"
	"github.com/The-17/keychain-auth/internal/pending"
	"github.com/The-17/keychain-auth/internal/protocol"
	"github.com/The-17/keychain-auth/internal/verify"
)

const readDeadline = 30 * time.Second

type Handler struct {
	verifier verify.Verifier
	keychain keychain.Keychain
	audit    *audit.Logger
	pending  *pending.PendingStore
}

func New(
	verifier verify.Verifier,
	kc keychain.Keychain,
	auditLog *audit.Logger,
	pendingStore *pending.PendingStore,
) *Handler {
	return &Handler{
		verifier: verifier,
		keychain: kc,
		audit:    auditLog,
		pending:  pendingStore,
	}
}

// Handle processes messages on a single connection until it closes or errors.
func (h *Handler) Handle(conn net.Conn) {
	defer conn.Close()

	dec := protocol.NewDecoder(conn)
	enc := protocol.NewEncoder(conn)

	// 1. Retrieve the caller's actual PID from connection
	pid, err := h.verifier.PeerPID(conn)
	if err != nil {
		log.Printf("ERROR: failed to retrieve peer PID: %v", err)
		return
	}

	// 2. Resolve caller binary path
	osPath, err := h.verifier.ResolveBinaryPath(pid)
	if err != nil {
		log.Printf("ERROR: failed to resolve binary path for PID %d: %v", pid, err)
		return
	}

	// 3. Compute file hash
	fileHash, err := verify.HashBinary(osPath)
	if err != nil {
		log.Printf("ERROR: failed to hash binary %s: %v", osPath, err)
		return
	}

	// 4. Live config reload per connection
	cfg, err := config.Load(config.ConfigPath())
	if err != nil {
		log.Printf("ERROR: failed to load config: %v", err)
		_ = h.audit.Log(audit.Event{
			Action:     "connect",
			PID:        pid,
			BinaryPath: osPath,
			BinaryHash: fileHash,
			Result:     "ERROR",
			Reason:     string(protocol.ReasonInternalError),
		})
		_ = enc.Write(protocol.Response{
			Type:   protocol.TypeResponse,
			Status: "error",
			Reason: protocol.ReasonInternalError,
		})
		return
	}

	// 5. Look up binary hash in config
	binaryPolicy := cfg.FindByHash(fileHash)
	if isCLIBinary(osPath) {
		binaryPolicy = &config.RegisteredBinary{
			Path:      osPath,
			Hash:      fileHash,
			CanSearch: true,
		}
	} else if binaryPolicy == nil || binaryPolicy.Path != osPath {
		// Code Signature Verification Check
		var matchedSigner *config.TrustedSigner
		for i := range cfg.TrustedSigners {
			signer := &cfg.TrustedSigners[i]
			ok, err := verify.VerifySignature(osPath, signer.PublicKey)
			if err == nil && ok {
				matchedSigner = signer
				break
			}
		}

		if matchedSigner != nil {
			// Binary is signed by a trusted developer key!
			// Auto-approve and auto-register/update the policy.
			log.Printf("INFO: auto-approving connection for signed binary: %s", osPath)

			// Find existing policy by path
			var pathPolicy *config.RegisteredBinary
			for i := range cfg.RegisteredBinaries {
				if cfg.RegisteredBinaries[i].Path == osPath {
					pathPolicy = &cfg.RegisteredBinaries[i]
					break
				}
			}

			if pathPolicy != nil {
				// Update hash in memory
				pathPolicy.Hash = fileHash
				binaryPolicy = pathPolicy
			} else {
				// Create new policy with access to the signed service
				newPolicy := config.RegisteredBinary{
					Path:                 osPath,
					Hash:                 fileHash,
					RegisteredAt:         time.Now().UTC().Format(time.RFC3339),
					AllowedReadServices:  []string{matchedSigner.Service},
					AllowedWriteServices: []string{matchedSigner.Service},
					CanSearch:            true, // Allow search for its own service
				}
				cfg.RegisteredBinaries = append(cfg.RegisteredBinaries, newPolicy)
				binaryPolicy = &cfg.RegisteredBinaries[len(cfg.RegisteredBinaries)-1]
			}

			// Save the updated configuration to disk
			if err := cfg.Save(config.ConfigPath()); err != nil {
				log.Printf("ERROR: failed to save config after signature auto-registration: %v", err)
			}
		} else {
			// Log unregistered attempt to pending.json
			cmdLine, _ := h.verifier.ResolveCommandLine(pid)
			if err := h.pending.Add(osPath, fileHash, cmdLine); err != nil {
				log.Printf("ERROR: failed to add pending attempt: %v", err)
			}

			reason := protocol.ReasonUnregisteredBinaryPendingApproval
			_ = h.audit.Log(audit.Event{
				Action:     "connect",
				PID:        pid,
				BinaryPath: osPath,
				BinaryHash: fileHash,
				Result:     "DENIED",
				Reason:     string(reason),
			})

			// Graceful rejection message before closing socket
			_ = enc.Write(protocol.Response{
				Type:   protocol.TypeResponse,
				Status: "denied",
				Reason: reason,
			})
			return
		}
	}

	// Log successful connection
	_ = h.audit.Log(audit.Event{
		Action:     "connect",
		PID:        pid,
		BinaryPath: osPath,
		BinaryHash: fileHash,
		Result:     "ACCEPTED",
	})

	// Sequentially handle requests bound to this authenticated connection
	for {
		if tc, ok := conn.(*net.UnixConn); ok {
			_ = tc.SetReadDeadline(time.Now().Add(readDeadline))
		}

		raw, err := dec.ReadRaw()
		if err != nil {
			if err == io.EOF {
				return
			}
			return
		}

		var req protocol.Request
		if err := protocol.UnmarshalRequest(raw, &req); err != nil {
			_ = enc.Write(protocol.Response{
				Type:   protocol.TypeResponse,
				Status: "error",
				Reason: protocol.ReasonMalformedRequest,
			})
			return
		}

		h.processRequest(enc, &req, pid, osPath, fileHash, binaryPolicy)
	}
}

func (h *Handler) processRequest(
	enc *protocol.Encoder,
	req *protocol.Request,
	pid int,
	binPath, binHash string,
	policy *config.RegisteredBinary,
) {
	// Step 1: Normalize match mode (default to "exact")
	if req.Match == "" {
		req.Match = protocol.MatchExact
	}
	if req.Match != protocol.MatchExact && req.Match != protocol.MatchPrefix {
		h.writeError(enc, protocol.ReasonMalformedRequest, pid, binPath, binHash, req)
		return
	}

	// Step 2: Pre-flight checks & input validation
	if req.Type != protocol.TypeRequest {
		h.writeError(enc, protocol.ReasonMalformedRequest, pid, binPath, binHash, req)
		return
	}

	// Targets are required for exact mode (except search).
	// For prefix mode, targets are required (they are the prefixes).
	if req.Match == protocol.MatchExact && req.Action != protocol.ActionSearch && len(req.Targets) == 0 {
		h.writeError(enc, protocol.ReasonMalformedRequest, pid, binPath, binHash, req)
		return
	}
	if req.Match == protocol.MatchPrefix && len(req.Targets) == 0 {
		h.writeError(enc, protocol.ReasonMalformedRequest, pid, binPath, binHash, req)
		return
	}

	// Write action cannot use prefix matching (no meaning for writes)
	if req.Match == protocol.MatchPrefix && req.Action == protocol.ActionWrite {
		h.writeError(enc, protocol.ReasonMalformedRequest, pid, binPath, binHash, req)
		return
	}

	// Strict write array alignment
	if req.Action == protocol.ActionWrite {
		if len(req.Targets) != len(req.Values) {
			h.writeError(enc, protocol.ReasonMalformedRequest, pid, binPath, binHash, req)
			return
		}
	}

	// Step 3: Policy authorization
	switch req.Action {
	case protocol.ActionType("check"):
		if !isCLIBinary(binPath) {
			h.writeDenied(enc, protocol.ReasonActionNotInPolicy, pid, binPath, binHash, req)
			return
		}
	case protocol.ActionRead:
		if !contains(policy.AllowedReadServices, req.Service) {
			h.writeDenied(enc, protocol.ReasonServiceNotAllowed, pid, binPath, binHash, req)
			return
		}
		// Prefix read internally enumerates keys, so it requires can_search
		if req.Match == protocol.MatchPrefix && !policy.CanSearch {
			h.writeDenied(enc, protocol.ReasonActionNotInPolicy, pid, binPath, binHash, req)
			return
		}
	case protocol.ActionSearch:
		if !policy.CanSearch || !contains(policy.AllowedReadServices, req.Service) {
			h.writeDenied(enc, protocol.ReasonActionNotInPolicy, pid, binPath, binHash, req)
			return
		}
	case protocol.ActionWrite:
		if !contains(policy.AllowedWriteServices, req.Service) {
			h.writeDenied(enc, protocol.ReasonServiceNotAllowed, pid, binPath, binHash, req)
			return
		}
	case protocol.ActionDelete:
		if !contains(policy.AllowedWriteServices, req.Service) {
			h.writeDenied(enc, protocol.ReasonServiceNotAllowed, pid, binPath, binHash, req)
			return
		}
		// Prefix delete internally enumerates keys, so it requires can_search
		if req.Match == protocol.MatchPrefix && !policy.CanSearch {
			h.writeDenied(enc, protocol.ReasonActionNotInPolicy, pid, binPath, binHash, req)
			return
		}
	default:
		h.writeError(enc, protocol.ReasonMalformedRequest, pid, binPath, binHash, req)
		return
	}

	// Step 4: Execute OS keychain operations
	var results []protocol.ResultItem

	switch req.Action {
	case protocol.ActionType("check"):
		targetBinPath := req.Targets[0]
		targetHash, err := verify.HashBinary(targetBinPath)
		if err != nil {
			_ = enc.Write(protocol.Response{
				Type:   protocol.TypeResponse,
				Status: "error",
				Reason: protocol.ReasonInternalError,
			})
			return
		}

		cfg, err := config.Load(config.ConfigPath())
		if err != nil {
			_ = enc.Write(protocol.Response{
				Type:   protocol.TypeResponse,
				Status: "error",
				Reason: protocol.ReasonInternalError,
			})
			return
		}

		targetPolicy := cfg.FindByHash(targetHash)
		if targetPolicy == nil || targetPolicy.Path != targetBinPath {
			_ = enc.Write(protocol.Response{
				Type:   protocol.TypeResponse,
				Status: "denied",
				Reason: protocol.ReasonUnregisteredBinaryPendingApproval,
			})
			return
		}

		hasRead := false
		for _, s := range targetPolicy.AllowedReadServices {
			if s == req.Service {
				hasRead = true
				break
			}
		}
		hasWrite := false
		for _, s := range targetPolicy.AllowedWriteServices {
			if s == req.Service {
				hasWrite = true
				break
			}
		}

		if !hasRead || !hasWrite || !targetPolicy.CanSearch {
			_ = enc.Write(protocol.Response{
				Type:   protocol.TypeResponse,
				Status: "denied",
				Reason: protocol.ReasonActionNotInPolicy,
			})
			return
		}

		_ = enc.Write(protocol.Response{
			Type:   protocol.TypeResponse,
			Status: "success",
		})
		return
	case protocol.ActionRead:
		if req.Match == protocol.MatchPrefix {
			// Prefix read: search → filter → read values
			matchedTargets, err := h.resolveByPrefix(req.Service, req.Targets)
			if err != nil {
				h.logAndWriteError(enc, req, pid, binPath, binHash, err)
				return
			}
			for _, target := range matchedTargets {
				val, err := h.keychain.Read(req.Service, target)
				if err != nil {
					if errors.Is(err, keychain.ErrNotFound) {
						continue // Key vanished between search and read — skip.
					}
					h.logAndWriteError(enc, req, pid, binPath, binHash, err)
					return
				}
				results = append(results, protocol.ResultItem{
					Target: target,
					Value:  val,
				})
			}
		} else {
			// Exact read: direct key lookup.
			// ErrNotFound means the key simply doesn't exist yet — return an empty
			// success rather than internal_error. This is the correct behaviour for
			// optional keychain entries such as the workspace allowlist cache.
			for _, target := range req.Targets {
				val, err := h.keychain.Read(req.Service, target)
				if err != nil {
					if errors.Is(err, keychain.ErrNotFound) {
						// Key absent — skip silently, caller receives 0 results.
						continue
					}
					h.logAndWriteError(enc, req, pid, binPath, binHash, err)
					return
				}
				results = append(results, protocol.ResultItem{
					Target: target,
					Value:  val,
				})
			}
		}

	case protocol.ActionWrite:
		// Parallelize writes when multiple targets are batched
		if len(req.Targets) > 1 {
			errCh := make(chan error, len(req.Targets))
			for i, target := range req.Targets {
				go func(tgt, val string) {
					errCh <- h.keychain.Write(req.Service, tgt, val)
				}(target, req.Values[i])
			}
			// Collect all results before returning
			var firstErr error
			for range req.Targets {
				if err := <-errCh; err != nil && firstErr == nil {
					firstErr = err
				}
			}
			if firstErr != nil {
				h.logAndWriteError(enc, req, pid, binPath, binHash, firstErr)
				return
			}
		} else {
			for i, target := range req.Targets {
				val := req.Values[i]
				if err := h.keychain.Write(req.Service, target, val); err != nil {
					h.logAndWriteError(enc, req, pid, binPath, binHash, err)
					return
				}
			}
		}

	case protocol.ActionDelete:
		if req.Match == protocol.MatchPrefix {
			// Prefix delete: search → filter → delete matches
			matchedTargets, err := h.resolveByPrefix(req.Service, req.Targets)
			if err != nil {
				h.logAndWriteError(enc, req, pid, binPath, binHash, err)
				return
			}
			for _, target := range matchedTargets {
				if err := h.keychain.Delete(req.Service, target); err != nil {
					h.logAndWriteError(enc, req, pid, binPath, binHash, err)
					return
				}
			}
		} else {
			for _, target := range req.Targets {
				if err := h.keychain.Delete(req.Service, target); err != nil {
					h.logAndWriteError(enc, req, pid, binPath, binHash, err)
					return
				}
			}
		}

	case protocol.ActionSearch:
		targets, err := h.keychain.Search(req.Service)
		if err != nil {
			h.logAndWriteError(enc, req, pid, binPath, binHash, err)
			return
		}
		for _, target := range targets {
			if len(req.Targets) > 0 {
				if !matchesAnyPrefix(target, req.Targets) {
					continue
				}
			}
			results = append(results, protocol.ResultItem{
				Target: target,
			})
		}
	}

	// Log successful request in audit log (granular per-target records)
	_ = h.audit.Log(audit.Event{
		Action:     string(req.Action),
		PID:        pid,
		BinaryPath: binPath,
		BinaryHash: binHash,
		Service:    req.Service,
		Targets:    req.Targets,
		Result:     "GRANTED",
	})

	_ = enc.Write(protocol.Response{
		Type:    protocol.TypeResponse,
		Status:  "success",
		Results: results,
	})
}

// resolveByPrefix performs a search on the service namespace and returns only
// the targets that match at least one of the given prefixes.
func (h *Handler) resolveByPrefix(service string, prefixes []string) ([]string, error) {
	allTargets, err := h.keychain.Search(service)
	if err != nil {
		return nil, err
	}
	var matched []string
	for _, target := range allTargets {
		if matchesAnyPrefix(target, prefixes) {
			matched = append(matched, target)
		}
	}
	return matched, nil
}

// logAndWriteError logs an internal error event and writes an error response.
func (h *Handler) logAndWriteError(
	enc *protocol.Encoder,
	req *protocol.Request,
	pid int, binPath, binHash string,
	err error,
) {
	_ = h.audit.Log(audit.Event{
		Action:     string(req.Action),
		PID:        pid,
		BinaryPath: binPath,
		BinaryHash: binHash,
		Service:    req.Service,
		Targets:    req.Targets,
		Result:     "ERROR",
		Reason:     err.Error(),
	})
	_ = enc.Write(protocol.Response{
		Type:   protocol.TypeResponse,
		Status: "error",
		Reason: protocol.ReasonInternalError,
	})
}

// matchesAnyPrefix returns true if s starts with any of the given prefixes.
func matchesAnyPrefix(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

func (h *Handler) writeDenied(
	enc *protocol.Encoder,
	reason protocol.ReasonCode,
	pid int,
	binPath, binHash string,
	req *protocol.Request,
) {
	_ = h.audit.Log(audit.Event{
		Action:     string(req.Action),
		PID:        pid,
		BinaryPath: binPath,
		BinaryHash: binHash,
		Service:    req.Service,
		Targets:    req.Targets,
		Result:     "DENIED",
		Reason:     string(reason),
	})
	_ = enc.Write(protocol.Response{
		Type:   protocol.TypeResponse,
		Status: "denied",
		Reason: reason,
	})
}

func (h *Handler) writeError(
	enc *protocol.Encoder,
	reason protocol.ReasonCode,
	pid int,
	binPath, binHash string,
	req *protocol.Request,
) {
	_ = h.audit.Log(audit.Event{
		Action:     string(req.Action),
		PID:        pid,
		BinaryPath: binPath,
		BinaryHash: binHash,
		Service:    req.Service,
		Targets:    req.Targets,
		Result:     "ERROR",
		Reason:     string(reason),
	})
	_ = enc.Write(protocol.Response{
		Type:   protocol.TypeResponse,
		Status: "error",
		Reason: reason,
	})
}

func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func isCLIBinary(binPath string) bool {
	selfExe, err := os.Executable()
	if err != nil {
		return false
	}
	selfExe, err = filepath.EvalSymlinks(selfExe)
	if err != nil {
		return false
	}
	binPathEval, err := filepath.EvalSymlinks(binPath)
	if err != nil {
		binPathEval = binPath
	}
	return binPathEval == selfExe
}
