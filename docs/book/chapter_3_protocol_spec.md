# Chapter 3: The JSON Wire Protocol Specification

The protocol is a high-performance, low-latency, newline-delimited JSON schema. 
* Every request is sent as a single line, terminated by a newline (`\n`).
* Every response is returned as a single line, terminated by a newline (`\n`).

---

## 3.1 The Request Schema

The request envelope is designed to be highly generic, supporting batch queries and optional prefix matching.

```json
{
  "type": "REQUEST",
  "action": "read | write | delete | search",
  "service": "agentsecrets",
  "match": "exact | prefix",
  "targets": ["prod/db_pass", "prod/api_key"],
  "values": ["secret1", "secret2"],
  "attributes": {
    "project": "proj_abc"
  }
}
```

### Field-by-Field Breakdown:

| JSON Key | Go Struct Field | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `type` | `Type` | String | **Yes** | Must be exactly `"REQUEST"`. |
| `action` | `Action` | String | **Yes** | Must be `"read"`, `"write"`, `"delete"`, or `"search"`. |
| `service` | `Service` | String | **Yes** | The OS keychain service namespace (e.g. `"AgentSecrets"`, `"aws"`, `"openai"`). |
| `match` | `Match` | String | No | `"exact"` (default) or `"prefix"`. If `"prefix"`, targets are treated as prefixes. (Not allowed for `"write"`). |
| `targets` | `Targets` | Array of Strings | **Yes** | The keys/accounts being queried. For `"search"`, this is optional and acts as prefix filters. |
| `values` | `Values` | Array of Strings | Cond. | Corresponding plaintext values to save. **Only required for `"write"`**. |
| `attributes`| `Attributes` | Map of Strings | No | Key-value pairs for metadata association (highly useful for tagging secrets). |

### Request Restrictions:
1. **Strict Array Alignment (Writes):** For `"action": "write"`, the length of the `targets` array **must exactly match** the length of the `values` array.
2. **Prefix Gating:** Prefix-based `"read"` or `"delete"` operations internally list/enumerate all keys in a namespace. Therefore, a client **must have `"can_search": true`** in its configuration policy, otherwise the daemon rejects the request.

---

## 3.2 The Response Schema

The daemon processes requests and returns a structured response envelope:

```json
{
  "type": "RESPONSE",
  "status": "success | denied | error",
  "reason": "unregistered_binary_pending_approval | service_not_allowed | action_not_in_policy | malformed_request | internal_error",
  "results": [
    {
      "target": "prod/db_pass",
      "value": "secret1",
      "attributes": {
        "project": "proj_abc"
      }
    }
  ]
}
```

### Field-by-Field Breakdown:

| JSON Key | Go Struct Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `type` | `Type` | String | Always `"RESPONSE"`. |
| `status` | `Status` | String | `"success"`, `"denied"` (policy rejection), or `"error"` (failure). |
| `reason` | `Reason` | String | Error code explaining the denial or error. Omitted on success. |
| `results` | `Results` | Array of Objects | Contains results of read or search actions. Values are omitted on search. |

### Results Object Breakdown:
* `target`: The name of the secret.
* `value`: The plaintext secret value. **⚠️ This is only populated on successful, authorized `"read"` actions. It is never populated on `"search"` actions to prevent bulk credential harvests.**
* `attributes`: Map of metadata associated with the secret.

---

## 3.3 Reason Codes Reference

When writing a client, your code must handle these specific rejection codes gracefully:

* **`unregistered_binary_pending_approval`**: The binary has not been registered or approved yet. The daemon has queued it in `pending.json` for interactive approval via the `keychain-auth approve` command.
* **`service_not_allowed`**: The binary attempted to read or write to a service namespace not authorized in its policy (e.g. trying to access `aws` when only authorized for `agentsecrets`).
* **`action_not_in_policy`**: The binary attempted to run a `search` or prefix-based operation, but its policy has `can_search` set to `false`.
* **`malformed_request`**: The JSON payload was invalid, had mismatched targets/values array lengths, or invalid properties.
* **`internal_error`**: An underlying failure occurred while communicating with the OS keychain (e.g., Apple Keychain DB locked, dbus connection lost).
