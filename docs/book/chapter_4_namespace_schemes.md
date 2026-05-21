# Chapter 4: Advanced Multi-Tenant Namespace Schemes

Native keychains (macOS, Windows, Linux) are inherently flat. They index entries using a two-key system: **Service Name** and **Account Name (Target)**. They do *not* natively support multi-tenant structures like environment folders, projects, or workspaces.

To build an advanced tool like `agentsecrets` that manages secrets across multiple workspaces, environments, and projects, you must implement a **Hierarchical Namespace Scheme** using string segmentation.

---

## 4.1 Choosing a Namespace Pattern

### Pattern A: Direct Shared Namespaces
If your CLI utility interacts directly with third-party tools (e.g. your tool writes an AWS key that the standard `aws-cli` needs to read directly from the OS keychain), you should use the target service name directly:
* **Service:** `aws`
* **Target:** `default` or `project-prod`

### Pattern B: Private Isolated Namespace (Recommended for Multi-Tenant CLIs)
If your CLI tool (like `agentsecrets`) is the sole manager of its secrets, you should isolate all data under a single private service namespace:
* **Service:** `AgentSecrets`

Within this single, isolated service namespace, you serialize all tenant context (Environment, Workspace, Project, Key) directly into the `target` parameter using a specific delimiter (like `:` or `/`).

```
Format:  [project_id]:[environment]:[secret_name]
Example: "proj_123:development:DATABASE_URL"
Example: "proj_abc:production:STRIPE_API_KEY"
```

This guarantees:
1. Absolute platform compatibility (every OS keychain safely stores standard strings).
2. O(1) direct reads when the exact path is known.
3. High-performance prefix-based discovery.
