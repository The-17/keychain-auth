# Chapter 7: Production Integration Checklist

When releasing an application or CLI integrated with `keychain-auth`, use this checklist to ensure complete security compliance and premium UX:

* [ ] **Enforce `O_CLOEXEC`**: Ensure your network client library explicitly opens local sockets with `SOCK_CLOEXEC` (or handle inheritance disabled on Windows) to prevent fd hijacking by child processes.
* [ ] **Setup-Time Registration**: Make sure your tool's installer automatically runs `keychain-auth register $(which your-tool)` during the installation process.
* [ ] **Upgrade Hooks**: Make sure your package manager post-upgrade hooks run `keychain-auth upgrade $(which your-tool)` on binary updates.
* [ ] **Helpful Daemon Missing Diagnostics**: If connection to the local socket or named pipe fails, display a clear, user-friendly instruction guide on how to start the daemon:
  ```
  Error: Cannot connect to keychain-auth daemon.
  To resolve this, start the background agent:
    keychain-auth start
  ```
* [ ] **Use Private Namespaces**: If your tool does not share passwords directly with third-party tools, isolate all secrets under your own, private service namespace (e.g. `AgentSecrets`).
* [ ] **Prefix Matching for Bulk Discovery**: Avoid reading all secrets into client memory when you only need to list key names. Use search prefix-filtering to display coverage layouts securely.
