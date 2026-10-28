# HackTheBox — Fireflow

| | |
|---|---|
| **Platform** | HackTheBox |
| **Difficulty** | Medium |
| **OS** | Linux — **k3s** cluster (host `fireflow`) |

## Overview

```
leaked flow_id → Langflow RCE (CVE-2026-33017) → www-data → .env →
reused password → SSH as nightfall (user) → ~/.mcp/config.json →
JWT alg:none → admin on MCP → malicious tool → RCE in mcp pod →
k8s nodes/proxy → kubelet exec (privileged node-exporter pod) → root on host
```

An AI-native chain: a leaked Langflow flow leads to RCE, an MCP server with a `none`-algorithm JWT lets you impersonate an admin and run code inside a pod, and a permissive Kubernetes ClusterRole (`nodes/proxy`) turns that into root on the host.

## 1. Recon

Ports: **22** (SSH), **80/443** (nginx). Hostnames `fireflow.htb` and `flow.fireflow.htb` → `/etc/hosts`.

The site on 443 is "FireFlow". Its **Open Agent** button leads to `flow.fireflow.htb/playground/<flow_id>`, a **Langflow** environment — exposing a valid `flow_id`.

## 2. Foothold — Langflow RCE

**CVE-2026-33017** is an unauthenticated RCE in Langflow; the only requirement is a valid `flow_id`. POST a flow containing a custom `code` node to `/api/v1/build_public_tmp/<flow_id>/flow` to execute a command and get a reverse shell as **`www-data`**.

## 3. www-data → nightfall (user)

- `/etc/langflow/.env` contains `LANGFLOW_SUPERUSER_PASSWORD` and `LANGFLOW_SECRET_KEY`.
- `/etc/passwd` has a user **`nightfall`**. The Langflow superuser password is **reused** → **SSH as `nightfall`** → **user flag**.

## 4. Lateral movement — MCP server (JWT `alg:none`)

- `~/.mcp/config.json` points to an MCP server at `http://<target>:30080` with credentials for `langflow-bot`.
- `GET /api/v1/version` reveals an "MCP AI Tool Registry". Crucially, `supported_algorithms` includes **`none`**, and `POST /api/v1/tools` requires the **admin** role.
- Authenticating returns a JWT with `role:user`. Forge an **`alg:none`** token with `role:admin`:
  ```python
  b = lambda d: base64.urlsafe_b64encode(d).rstrip(b"=").decode()
  header  = b(json.dumps({"alg":"none","typ":"JWT"}).encode())
  payload = b(json.dumps({"sub":"attacker","role":"admin"}).encode())
  token = f"{header}.{payload}."
  ```
- Register a malicious tool (`POST /api/v1/tools`) and invoke it (`POST /mcp`, method `tools/call`) → code execution inside the **`mcp`** pod.

> **Automation tip.** The `tools/call` JSON-RPC result returns the tool's **stdout** in `result.content[].text`. Register a tool that runs `subprocess` and you get **RCE-with-output straight from the HTTP response** — no reverse shell needed (handy here, since the pod has no egress to the attacker VPN).

## 5. Privilege escalation — Kubernetes `nodes/proxy` → root

The `mcp` pod runs as `system:serviceaccount:default:mcp-sa` (ClusterRole `mcp-cluster-reader`).

A `SelfSubjectAccessReview` shows **`get nodes/proxy` is allowed** (while `create nodes/proxy` and `get/list pods` are denied).

```
GET /api/v1/nodes/fireflow/proxy/pods        # list node pods via kubelet
```

The juicy target is `monitoring/prometheus-prometheus-node-exporter`:

- `privileged: true`, `runAsUser: 0`, image `node-exporter:v1.11.1` (**busybox-based → ships `/bin/sh`**).
- mounts the **host `/`** at `/host/root`.

`exec` requires a **WebSocket upgrade**. Going through the apiserver node proxy **drops the `stdout/stderr` params** (`"you must specify at least 1 of stdin, stdout, stderr"`). The fix is to talk to the **kubelet directly** on `:10250` — its authorization delegates to the same `nodes/proxy` SAR, so `get` is enough:

```
https://<node-ip>:10250/exec/monitoring/<node-exporter-pod>/node-exporter
    ?output=1&error=1&command=/bin/sh&command=-c&command=<payload>
```

Drive it with a minimal WebSocket client (subprotocol `v4.channel.k8s.io`; channel 1 = stdout, 2 = stderr). As root in the privileged pod:

- `cat /host/root/root/root.txt` → **root flag**.
- `mount -o remount,rw /host/root` + append an SSH key to `/host/root/root/.ssh/authorized_keys` → `ssh root@<target>` (`PermitRootLogin yes`) → **uid=0 on the host**.

## Lessons

- `alg:none` still kills — always validate the signature algorithm server-side.
- `nodes/proxy` with only `get` is powerful: it's enough to **exec into pods via the kubelet** (WebSocket upgrade). The apiserver proxy can mangle params — hitting the kubelet directly (`:10250`) avoids it.
- A privileged pod that mounts the host `/` is trivial host root (read the flag, or remount rw and drop an SSH key).
- An MCP tool that returns stdout in its JSON-RPC result is clean RCE-with-output when there's no egress to your VPN.

## References

- Official HTB writeup (chain up to the `mcp` shell; its privesc section was truncated).
- Kubernetes `nodes/proxy` / kubelet streaming exec (`channel.k8s.io`).
