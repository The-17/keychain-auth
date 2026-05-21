# Chapter 2: Kernel-Level Identity & IPC Transport

A major strength of `keychain-auth` is that **the connection itself is the authenticated session**. There are no session tokens, cookies, or secrets transmitted over the socket to prove identity. Instead, the daemon retrieves caller information directly from the operating system kernel.

---

## 2.1 The Multi-Platform IPC Channels

* **macOS & Linux:** Standard Unix Domain Sockets. Sockets are faster and more lightweight than HTTP/TCP, and their access permissions can be restricted using standard file permissions (`0600`).
  * Default socket path: `/var/run/keychain-auth/agent.sock` (or falls back to `~/.config/keychain-auth/agent.sock` if root access is unavailable).
* **Windows:** Named Pipes.
  * Default pipe path: `\\.\pipe\keychain-auth`.

---

## 2.2 Kernel-Enforced Process ID (PID) Resolution

To prevent spoofing, `keychain-auth` ignores any self-reported PIDs. The daemon retrieves the **real** PID of the calling process directly from the kernel transport options:

### A. Linux (`SO_PEERCRED`)
On Unix domain sockets, the daemon reads the socket options using the `SO_PEERCRED` system call. The kernel returns a `ucred` structure containing the verified `pid`, `uid`, and `gid` of the client.
```go
// Go implementation in keychain-auth (internal/verify/verify_linux.go)
sysCred, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
pid := sysCred.Pid
```

### B. macOS (`LOCAL_PEERPID`)
On macOS, `SO_PEERCRED` is unavailable. The daemon queries the socket using the `LOCAL_PEERPID` option to retrieve the verified caller PID.
```go
// Go implementation in keychain-auth (internal/verify/verify_darwin.go)
pid, err := syscall.GetsockoptInt(fd, syscall.SOL_LOCAL, syscall.LOCAL_PEERPID)
```

### C. Windows Named Pipes
On Windows, the daemon utilizes the `GetNamedPipeClientProcessId` Win32 API on the active named pipe handle. The kernel enforces this process ID, guaranteeing that a malicious client cannot spoof its identity.

---

## 2.3 Resolving Executable Paths & Cryptographic Hashes

Once the PID is verified by the kernel, the daemon resolves it to a physical binary file:
* **Linux:** Reads the symlink `/proc/[PID]/exe` to locate the exact path on disk.
* **macOS:** Invokes the `proc_pidpath` system call.
* **Windows:** Opens a process handle using `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` and queries the path via `QueryFullProcessImageName`.

Once the path is resolved, the daemon reads the binary file and computes its **SHA-256 hash**. 

> [!IMPORTANT]
> **Active Binary Locking:** Modern operating systems lock running executables from being modified in place (`ETXTBSY` error on Linux). This prevents an attacker from swapping a trusted binary with a malicious one *after* it has started running. Thus, validating the binary's hash at runtime is highly secure.
