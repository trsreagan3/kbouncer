# Hardening kbounce against prompt-injected agents

How to harden kbounce (and the rest of the Bounce suite) against a
prompt-injected agent that tries to disable the proxy before issuing
`kubectl` / client-go calls. This doc is for SecOps + platform
engineers deploying kbounce on engineer laptops, jump hosts, or
shared workstations.

---

## The honest framing

kbounce is a **user-process on a user-machine.** A prompt-injected
agent that has shell access on the same machine — through a tool
primitive like `bash`/`exec`/`python -c`, or simply by writing a
shim script the user then runs — can `pkill kbounce`,
`unset KUBECONFIG`, point `KUBECONFIG` at a fresh kubeconfig pointing
straight at the cluster, or just call the kube-apiserver directly
with a freshly-built client-go config. kbounce by itself cannot stop
any of those moves.

What kbounce CAN do is make every disable-attempt **detectable** and
make the bypass **costly** when composed with the rest of an
operator's defense-in-depth stack:

- Heartbeat events emitted to the audit pipeline so a gap is visible
  within seconds (per the `heartbeat_gap` alert rule shipped in
  Slice 2).
- Tamper-detection on the audit chain (hash-chained rows; a gap or
  rewrite shows up at `kbounce audit verify`).
- Admin-action audit events so attempts to mutate the rule set,
  install a malicious profile, or change modes are themselves
  audited.

The rest of this doc walks through the **six-layer defense** that, in
combination, actually prevents (or at minimum reliably detects) the
disable-bouncer attack. kbounce is **one layer.** The other five are
the customer's OS, network, sandbox, and MDM tooling — not things
kbounce ships.

---

## The 6-layer defense

### Layer 1 — Don't give the agent shell access

**Strongest layer.** If the agent has no shell primitive, it can't run
`pkill`, can't `unset` an env var in the parent process, and can't
write a bypass kubeconfig. Everything the agent does has to go
through its declared tools.

**How to ship this:**

- **MCP-only agent configuration.** Tools the agent can call are
  exhaustively listed in the MCP server manifest. No
  `bash` / `exec` / `shell` / `run_command` tool exposed. Specifically
  for Kubernetes: expose a `kubectl_get` / `kubectl_describe` tool
  rather than `exec(["kubectl", ...args])`.
- **Claude Code default config.** As of the current release, Claude
  Code does not give the agent a shell primitive by default; the user
  must opt in explicitly with `--dangerously-skip-permissions` or by
  approving each Bash invocation. Keep that default.
- **Cursor agent mode** without the "Run terminal commands" permission
  ticked.

**Tools that do NOT satisfy this layer out of the box:**

- Most LangChain ReAct agents bootstrapped with the standard
  `shell_tool` / `terminal_tool` — these expose `subprocess.run` to
  the LLM by design.
- Several open-source agent loops that ship with a shell tool as their
  primary capability (the "shell is the universal tool" school of
  thought). Treat any agent loop whose flagship example wires a shell
  tool as **not Layer-1 safe** without modification.

**What this layer does NOT cover:** an agent that asks the human to
copy-paste a `kubectl` command into a terminal still wins — the
prompt-injection moves up a level into social engineering. Layers
2–6 cover the residual risk.

### Layer 2 — Sandbox the agent

**Very strong.** Run the agent inside a Docker container, microVM,
Firecracker VM, or browser sandbox where the laptop's shell is not
reachable.

Key properties:

- **Env vars set immutably inside the sandbox.** The sandbox starts
  with `KUBECONFIG=/etc/kbounce/kubeconfig` baked into the
  container's `ENV`. The kubeconfig itself points at
  `https://host.docker.internal:8766` (kbounce's listener) as the
  cluster `server` — not at the real apiserver. Even if the agent
  runs `unset KUBECONFIG` inside the sandbox, that only unsets it in
  the sandbox's shell; the kubectl/client-go process inherits the
  original env from container `ENV`.
- **Sandbox network namespace only routes egress through kbounce's
  outbound IP.** The sandbox is on its own Docker network whose
  iptables rules forward all kube-apiserver-port traffic to the
  host's kbounce port.
- **Agent can `pkill` inside the sandbox.** kbounce is on the HOST,
  outside the sandbox; the agent's `pkill kbounce` finds no matching
  PID inside its container.

**Concrete: Docker run with a constrained kubeconfig.**

```sh
# On the host, create a dedicated Docker network whose only outbound
# rule is "kube-apiserver port goes through kbounce".
docker network create \
  --driver bridge \
  --subnet 172.31.0.0/24 \
  --opt com.docker.network.bridge.enable_ip_masquerade=false \
  bouncer-net

# iptables rule on the host: this network's apiserver-port traffic
# goes to 127.0.0.1:8766 (where kbounce is listening).
sudo iptables -t nat -A PREROUTING \
  -s 172.31.0.0/24 \
  -p tcp --dport 6443 \
  -j DNAT --to-destination 127.0.0.1:8766

# Pre-built kubeconfig that the sandbox uses — server points at
# kbounce, not at the real apiserver.
cat > /etc/kbounce/sandbox-kubeconfig <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://host.docker.internal:8766
    insecure-skip-tls-verify: true  # kbounce terminates TLS
  name: bounced
contexts:
- context:
    cluster: bounced
    user: bounced
  name: bounced
current-context: bounced
users:
- name: bounced
  user:
    token: <sa-token-with-narrow-rbac>
EOF

# Run the agent inside this network with the bounced kubeconfig.
docker run --rm -it \
  --network bouncer-net \
  -e KUBECONFIG=/etc/kbounce/kubeconfig \
  -v /etc/kbounce/sandbox-kubeconfig:/etc/kbounce/kubeconfig:ro \
  my-agent:latest
```

The `token` in the bounced kubeconfig is a service-account token
whose RBAC is **the absolute ceiling.** kbounce narrows from there.
The agent CANNOT exceed the SA's RBAC even if it bypasses kbounce —
that is the Layer-1-equivalent for Kubernetes (RBAC on the SA the
sandbox holds).

### Layer 3 — Network egress allowlist

**Strong.** Block the dev-machine's direct egress to the
kube-apiserver IP / port except via kbounce's outbound IP. This
catches the case where the agent (or a human under social
engineering) tries to call the apiserver directly with a fresh
client-go config that doesn't use the kbounce kubeconfig.

**macOS — pf (packet filter):**

`/etc/pf.anchors/com.bouncer`:

```
# Allow loopback (kbounce listens on 127.0.0.1:8766)
pass quick on lo0

# Allow kbounce's own process (uid 501 is the operator account) to
# reach the apiserver
pass out proto tcp from any to any port 6443 user 501 keep state

# Block every OTHER user process from reaching the apiserver IPs
table <kube_apiservers> persist file "/etc/bouncer/kube_apiservers.txt"
block out quick proto tcp from any to <kube_apiservers> port { 443, 6443, 8443 }
```

Load with:

```sh
sudo pfctl -a com.bouncer -f /etc/pf.anchors/com.bouncer
sudo pfctl -e
```

**Linux — nftables:**

```
table inet bouncer {
  chain output {
    type filter hook output priority 0; policy accept;

    # Allow loopback
    oifname "lo" accept

    # Allow kbounce's process (matched by cgroup or uid) to reach the
    # apiserver
    meta skuid 1000 accept

    # Block everyone else from apiserver endpoints
    ip daddr @kube_apiservers tcp dport { 443, 6443, 8443 } reject with tcp reset
  }

  set kube_apiservers {
    type ipv4_addr
    flags interval
    # Populate from /etc/bouncer/kube_apiservers.txt
  }
}
```

**Corporate / VPN exit:** push the same allowlist as a VPN egress
ACL. Every laptop's apiserver traffic must exit through a corporate
proxy whose upstream is kbounce.

**Cloud dev workspaces (Codespaces, Gitpod, etc.):** VPC route tables
+ a NAT instance running kbounce. Same shape.

### Layer 4 — MDM-enforced signed binary + managed env vars

**Strong for managed fleets.** Use Jamf / Kandji / Intune /
equivalent to lock down:

- **Which processes can run.** Only the signed `kbounce` binary, with
  a known SHA-256, can listen on the loopback port. Modified binaries
  refuse to launch.
- **Managed env vars that the user (or agent) cannot modify.**
  `KUBECONFIG=/etc/kbounce/kubeconfig` is shipped as a managed
  preference and re-applied on every login. `unset KUBECONFIG` in a
  shell unsets it for that shell session, but the next-launched
  process inherits the managed value again.
- **Prevent `pkill` of managed services.** macOS Endpoint Security
  framework profiles can block signal-delivery to processes in a
  managed list.
- **Lock down `~/.kube/config`.** The managed kubeconfig that points
  at kbounce lives at `/etc/kbounce/kubeconfig` (root-owned, 0644).
  The user's `~/.kube/config` is removed by the MDM policy; any
  attempt by the agent to write one is denied by file-system policy
  (AppArmor / SELinux / macOS TCC).

**macOS Configuration Profile** (illustrative `.mobileconfig` payload
keys — full XML omitted for brevity; consult Apple's `profiles`
reference):

```
PayloadType: com.apple.systempolicy.kernelextensionpolicy
  AllowedTeamIdentifiers: [ <kbounce-signing-team-id> ]

PayloadType: com.apple.ManagedClient.preferences
  ManagedPreferences:
    KUBECONFIG: "/etc/kbounce/kubeconfig"

PayloadType: com.apple.TCC.configuration-profile-policy
  Services.SystemPolicyAllFiles:
    - Identifier: <kbounce-bundle-id>
      Authorization: Allow
```

**Linux — systemd hardening:**

```
[Service]
ExecStart=/usr/local/bin/kbounce run --profile safe-default
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
```

Combined with **AppArmor** (`/etc/apparmor.d/usr.local.bin.kbounce`):

```
/usr/local/bin/kbounce {
  capability net_bind_service,
  network inet stream,
  /home/*/.kbouncer/state.db rwk,
  /home/*/.kbouncer/state.db-journal rwk,
  /etc/bouncer/** r,
  /etc/kbounce/kubeconfig r,
  deny /home/*/.ssh/** rwx,
  deny /home/*/.kube/config rwx,
}
```

**Windows — Group Policy + WDAC (Windows Defender Application
Control):** ship a WDAC policy whose `Allowed Publishers` list
includes only the kbounce signing certificate; set the `KUBECONFIG`
environment variable via a Group Policy Preference (Computer
Configuration → Preferences → Environment) so it reapplies on every
user-login refresh.

### Layer 5 — launchd / systemd KeepAlive watchdog

**Medium.** If the agent does manage to kill kbounce, the OS-level
process supervisor restarts it within seconds. Combined with Layer 6,
the security team sees both the kill event AND the restart event in
the audit stream — a strong signal for incident response.

**macOS launchd plist** —
`/Library/LaunchDaemons/com.bouncer.kbounce.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.bouncer.kbounce</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/kbounce</string>
    <string>run</string>
    <string>--profile</string>
    <string>safe-default</string>
    <string>--kubeconfig</string>
    <string>/etc/kbounce/upstream-kubeconfig</string>
  </array>
  <key>KeepAlive</key>
  <true/>
  <key>RunAtLoad</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>5</integer>
  <key>StandardOutPath</key>
  <string>/var/log/kbounce.out.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/kbounce.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>/Users/operator</string>
  </dict>
</dict>
</plist>
```

Install:

```sh
sudo cp com.bouncer.kbounce.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.bouncer.kbounce.plist
```

**Linux systemd unit** — `/etc/systemd/system/kbounce.service`:

```ini
[Unit]
Description=kbounce — local Kubernetes API gating proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/kbounce run --profile safe-default --kubeconfig /etc/kbounce/upstream-kubeconfig
Restart=always
RestartSec=5
User=kbounce
Group=kbounce

# Hardening (see Layer 4)
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Install:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now kbounce.service
```

Each restart emits a kbounce startup audit event (one row per process
start; see `kbounce audit tail --event startup`). Pair with Layer 6
so the SIEM sees the kill/restart cycle.

### Layer 6 — Heartbeat + admin-action audit (what kbounce ships)

**Detection, not prevention.** This is the layer kbounce itself
provides; the other five layers are customer-owned infrastructure.

What kbounce emits today (v1.0):

- **HEARTBEAT** events every N seconds (default 30s) to the audit
  pipeline. Configurable via `KBOUNCE_HEARTBEAT_INTERVAL`.
- **Slice-2 alert rule `heartbeat_gap`** fires when the SIEM-side
  view of the audit stream sees a gap larger than 2× the configured
  interval. Routes to whichever sink the operator configures
  (Slack webhook, generic webhook, OCSF/Splunk HEC).
- **Admin-action OCSF events** for rule-mutation, profile-install,
  mode-change, and pause-override attempts. These are emitted even
  when the attempt fails the authorization check, so an agent trying
  to relax the rule set is visible.

**Cross-correlation signal:** the audit pipeline can correlate
kbounce events against the apiserver's audit log (the
`audit-policy.yaml` stream from kube-apiserver itself). Any apiserver
audit row attributed to the operator's user / SA for which there is
NO matching kbounce audit row in the same window = the proxy was
bypassed. That correlation is the canonical bypass detector.

**What the operator must do:**

1. Route kbounce audit to a SIEM (Splunk, Sumo, Datadog,
   Elasticsearch, etc.) — see
   [docs/QUERYING-AUDIT-LOGS.md](QUERYING-AUDIT-LOGS.md).
2. Enable the `heartbeat_gap` alert rule on that SIEM.
3. Subscribe the security team to the alert channel.

---

## Worked example: combining layers 1 + 3 + 5 + 6

A common deployment for an engineer laptop running Claude Code as the
agent against a multi-tenant dev cluster:

- **Layer 1 (partial):** Claude Code in its default config, with
  `Bash` tool approval prompts left on (don't
  `--dangerously-skip-permissions`).
- **Layer 3:** macOS pf rules blocking direct connections to the
  apiserver IP/port except from the kbounce process.
- **Layer 5:** launchd plist with `KeepAlive: true` so any
  `pkill kbounce` triggers an automatic restart within ~5 seconds
  (controlled by `ThrottleInterval`).
- **Layer 6:** kbounce HEARTBEAT events routed to Splunk via the
  audit-export pipeline + `heartbeat_gap` alert wired to the SecOps
  Slack channel.

**Combined behavior on a prompt-injection disable attempt:**

1. Injected prompt arrives via a poisoned tool response.
2. Agent attempts `pkill kbounce` — Claude Code surfaces the Bash
   approval prompt; the user (hopefully) denies.
3. If the user approves (or the deployment skipped Layer 1), kbounce
   dies → launchd restarts it within ~5s.
4. During the gap, the agent attempts a direct `kubectl --kubeconfig
   /tmp/fresh.yaml ...` call pointing at the real apiserver — pf
   blocks the connection at the TCP layer.
5. `heartbeat_gap` alert fires in Splunk; security team is paged.
6. Audit chain shows the kill event, the restart event, and the
   blocked direct-egress attempt — full forensic picture.

The bypass attempt is **detected within seconds**, **can't reach the
apiserver directly**, and **kbounce keeps coming back**. No single
layer provides this on its own; the combination does.

---

## What kbounce CAN'T do

Explicit, honest list of what is **not** in kbounce's lane:

- **We don't prevent the disable itself.** A user-process can be
  killed by the user. That's how operating systems work. kbounce can
  only make the kill visible.
- **We don't ship MDM.** Jamf, Kandji, Intune, and equivalent are the
  customer's IT-management tooling. kbounce can be packaged for
  managed deployment, but the policy enforcement is the MDM's.
- **We don't ship the sandbox.** Docker, Firecracker, gVisor, browser
  sandboxes — pick the one that fits your agent's runtime. kbounce
  runs on the host; the sandbox is the customer's container layer.
- **We don't ship the firewall rules.** pf, nftables, VPN ACLs, VPC
  route tables — these are network-team responsibilities. kbounce
  provides the loopback target; the routing decision is upstream.
- **We don't enforce file-system policy.** Whether the agent can read
  `~/.kube/config` directly (and then call the apiserver using those
  credentials without going through the proxy) is an AppArmor /
  SELinux / macOS TCC concern. See Layer 4.
- **We don't enforce admission control.** A `ValidatingAdmissionWebhook`
  or `OPA Gatekeeper` policy on the cluster is the apiserver-enforced
  boundary. kbounce + admission control compose well; if your threat
  model needs cluster-side enforcement, run both.

**What kbounce ships:** the audit signal, the heartbeat, the alert
rule, the admin-action event stream, and this doc explaining how to
compose all six layers.

---

## FAQ

**Q: What stops a prompt-injected agent from running `pkill kbounce`
as its first command?**

**A:** Nothing in kbounce itself. The full answer is "Layer 1
prevents the agent from having a shell, Layer 5 restarts kbounce if
it does get killed, Layer 6 alerts the SecOps team within seconds,
and Layer 3 blocks the direct-apiserver attempt during the restart
window." That combination is what stops the attack — not any single
layer.

This is the same shape as host-IDS or endpoint detection: a
prompt-injected agent can `rm -rf` a CrowdStrike agent's files too,
which is why CrowdStrike pairs detection with kernel-level
tamper-protection and a network-level egress block. kbounce uses the
same playbook, but the kernel-level tamper-protection is the
customer's MDM (Layer 4), not anything kbounce can ship as a
user-space binary.

**Q: Can kbounce be run as root to prevent the user (or agent) from
killing it?**

**A:** Running kbounce as root makes `pkill` require root, which
helps against an agent running as the unprivileged user — but it
introduces its own risks (a vulnerability in kbounce becomes a root
vulnerability) and it doesn't help against an agent that has sudo
(many dev-laptop setups give the engineer NOPASSWD sudo).

The Bounce-suite recommendation is: run kbounce as the engineer's
own user account, NOT as root. Use **Layer 5 (launchd / systemd
KeepAlive)** for the "always-restart-on-kill" property. Use
**Layer 4 (MDM-managed process protection)** for the "user can't
kill it at all" property — that one belongs to the OS, not kbounce.

If you have a hard requirement to run kbounce as a privileged
daemon, you can — `Restart=always` + `User=root` in the systemd
unit works — but the hardening team should review the resulting
threat model carefully. The default-recommended deployment is
user-process with launchd/systemd supervision.

---

## Related docs

- [`QUERYING-AUDIT-LOGS.md`](QUERYING-AUDIT-LOGS.md) — wiring audit
  output to a SIEM (the Layer 6 prerequisite).
- The cross-suite hardening doc is replicated in the `ibounce`,
  `dbounce`, and `gbounce` repos with their respective env-var and
  upstream-protocol specifics — the threat model and layer model are
  identical across the Bounce suite.
