# firewall-port-tester

[English](README.md) | [繁體中文](README.zh-TW.md)

A reusable tool to verify **TCP port access on new or existing VMs**. It checks every target over SSH, uses temporary listeners for empty ports and existing services for occupied ports, then tests company/external access and produces local JSON/CSV reports. Mode selection is automatic for each port; your configuration stays the same.

Use it only for VMs you own or have permission to test. It checks the hosts and TCP ports you list. It is not a vulnerability scanner, password cracker, or intrusion tool, and it does not discover other hosts or scan port ranges.

## Simple workflow with an AI assistant

**Company network → external network → company network → report**

You can ask an AI assistant to prepare and run the test, or run the commands yourself. Start your VMs and make sure SSH works before you begin.

1. **Provide the test details.** Give the AI the VM public IPv4 addresses, company public IP/CIDR list, SSH username, local private-key path, and the ports that should be public, company-only, or blocked. Provide the key path only, never the private-key contents.
2. **Prepare the configuration.** The AI reads this project, creates the local `targets.local.json`, and validates it. Actual testing starts after you authorize it. Copyable prompts are in [AI-GUIDE.md](AI-GUIDE.md).
3. **Let the tool check ports and choose modes.** All VMs are checked before any test service starts. Empty ports receive a temporary Python listener; occupied ports use the existing service. A monitor tracks existing listeners without taking over their ports. Unusable or uncertain bindings are marked `ERROR`, not treated as a working firewall block.
4. **Test from the company network.** The tool checks that public and company-only ports are reachable, while blocked ports are not.
5. **Switch to an external network when prompted.** For example, connect your laptop to your phone's hotspot using **4G/5G mobile data**. Check that your VPN is not still sending traffic through the company. Tell the AI when you have switched, or press Enter if you are running the tool yourself. The tool checks the public source IP, then tests that public ports are reachable and company-only/blocked ports are not.
6. **Switch back to the company network when prompted.** The tool reconnects over SSH and checks temporary-listener continuity and existing-listener identity/readiness evidence for both test phases.
7. **Clean up and review the report.** The tool stops its temporary listeners and monitor, removes their files, and saves JSON/CSV reports locally. Ask the AI to explain PASS, FAIL, and ERROR results. The report does not mark an unverified listener or cleanup as PASS.

The default **one-hour listener lifetime is a fallback cleanup limit**, not a connection timeout. Normal cleanup runs as soon as testing is done. Each connection attempt has a 3-second budget by default, with two attempts per port.

## What it checks

| Setting | Company network | External network |
| --- | --- | --- |
| `world_ports` | Allow | Allow |
| `company_ports` | Allow | Block |
| `blocked_ports` | Block | Block |

All selected ports, **including blocked ports**, need a verified TCP listener. The tool creates one only when the port is empty. After external testing, return to the company network to verify monitoring evidence and clean up this run. Failed connections without listener evidence receive `ERROR`, not `PASS`.

Results describe end-to-end TCP reachability from the laptop. They do not identify whether a cloud NSG, host firewall, upstream router or another layer permitted/blocked traffic. TLS, application behavior, private-network traffic and third-party-specific allowlists are outside this version's scope. Public-IP checks do not prove the exact routing of every target, especially with split-tunnel VPNs; verify your routing independently when applicable.

## Automatic port modes

The tool performs preflight on **all VMs before starting any test listener or monitor**. It checks listening sockets, the SSH destination IPv4 interface, host NAT/redirect rules, and TCP readiness. For empty ports it briefly binds without listening, then releases the port. Preflight failure on any VM aborts before test services start. Preflight may make one short local TCP connection to each existing candidate port.

| Detected state | Automatic mode | Behavior |
| --- | --- | --- |
| Empty TCP port that can be bound | `temporary` | Create a test listener and verify its run marker. |
| Existing listener accepting IPv4 TCP on the target interface | `existing` | Use TCP handshakes only; send/read no application data or test marker. |
| Localhost-only/wrong-interface binding, unready listener, unverifiable identity, or reserved port | `unsupported` | Skip network probes for that port and report `ERROR`; leave it unchanged. |

One VM can mix these modes. The SSH management port may be listed, but only as an existing listener; the tool will never create a listener on a missing management port. A port taken after preflight makes setup fail and triggers cleanup; it is not silently taken over or reclassified.

For existing services, a per-run monitor samples Linux listening-socket identities and listen-queue capacity about once per second. A missing/replaced listener, binding change, full/unverifiable listen queue, read error, or monitoring gap longer than 3 seconds remains an error even if the listener recovers. On return to company access, the tool also makes one local TCP readiness check per existing port. Only that port is invalidated when its evidence fails; other ports can still pass. This is sampled TCP-listener evidence, not continuous application-health monitoring; brief changes between samples may be missed.

Existing-service probes create real TCP connections that close without application data. They can still produce logs, incomplete-handshake messages, connection counters, or rate-limit events. Use a suitable testing window for live services. The tool never stops, restarts, reconfigures, or sends login/HTTP/database commands to those services.

This version supports direct listeners in the VM's host network namespace. Detected DNAT, REDIRECT, or transparent-proxy forwarding aborts preflight conservatively, even if a forwarding rule appears unrelated to the selected ports. Container-published ports, port-forwarding setups and targets whose public route reaches a different interface/endpoint need separate verification. Missing or unreadable forwarding-rule tools also abort preflight instead of assuming the ports are free. NAT outside the VM, such as a cloud public-IP mapping to the SSH destination interface, does not itself trigger this host-rule check.

Linux socket identity comes from the [documented TCP socket tables](https://docs.kernel.org/networking/proc_net_tcp.html), with queue data from [`ss`](https://man7.org/linux/man-pages/man8/ss.8.html). A report records each port's `mode`, `listener_healthy`, `health_reason`, and `cleanup_confirmed`; JSON report format is version 2. No new configuration fields are required.

## Requirements

- Local macOS or Linux, Bash, Python 3.9+ and OpenSSH client. No pip packages needed.
- Remote Linux VM with Python 3.9+, systemd (`systemctl`, `systemd-run`) and an SSH account allowed to run `sudo -n python3`. The earlier temporary-listener flow was tested from macOS against Ubuntu 26.04/systemd VMs; automatic existing-service mode has local/mocked regression coverage and still needs an authorized integration test on your own VM image.
- SSH authentication must already work non-interactively. For an encrypted key, load the matching key in `ssh-agent` first. Private keys remain on the laptop.
- SSH reachable from the company network. It need not be reachable from external networks.
- Remote access to `/proc/net/tcp` and `/proc/net/tcp6` when IPv6 is enabled, `ss` to inspect listener queues, plus `nft` or `iptables-save` to inspect forwarding rules. No packages are installed by the tool.
- Existing services must accept IPv4 TCP on the SSH destination interface (or a wildcard binding). Localhost-only, forwarded, or uncertain endpoints are not reported as valid firewall blocks.
- Enough time for both network switches before the configured listener lifetime expires (default: one hour).

## Quick start

```bash
cp examples/targets.example.json targets.local.json
```

Edit `targets.local.json` with your **actual** company public source CIDRs, SSH account/key path, target VM public IPv4 addresses and explicit port lists. Example addresses are reserved for documentation and must be replaced. Relative key paths resolve against the configuration file's directory; `~` is supported.

```bash
chmod 600 /path/to/your/private-key.pem
./test-ports.sh validate --config targets.local.json
./test-ports.sh run --config targets.local.json
```

By default each attempt has a **3-second total budget for TCP connection plus marker reading**, and each port is attempted twice (about 6 seconds maximum per port, plus scheduling overhead). Ports run concurrently; a whole batch can take longer. This is separate from the one-hour listener lifetime. Both the attempt budget and retry count are configurable.

`validate` only checks configuration and performs **no SSH connections, HTTP requests or remote changes**. `run` performs the following:

1. Check that the laptop's public IPv4 belongs to `company_cidrs`.
2. Preflight every VM and choose a mode for each port. Then use SSH and passwordless sudo to start a unique transient systemd listener/monitor service on each VM. Bind only empty ports; existing applications keep ownership of their ports.
3. Test company expectations, then prompt you to switch to an external network. Disable/change any VPN that would keep traffic on the company egress IP.
4. Verify that the source is outside `company_cidrs`, then test external expectations.
5. Prompt you to return to the company network. Retrieve listener health, verify continuity, stop this run's test services, remove their files, and write the final report.

The source IP is queried directly over HTTPS using `https://api.ipify.org` by default. That service sees your public source IP; no host inventory, ports or credentials are sent. You can specify a trusted alternative HTTPS endpoint returning plain IPv4 using `settings.public_ip_url`. HTTP proxy environment variables are bypassed so the source check uses a direct connection. A failed source check stops the run.

OpenSSH uses your local `known_hosts` and `StrictHostKeyChecking=accept-new`: new host keys are recorded; changed keys are rejected. SSH configuration may also affect routing or authentication. Review these settings for your environment.

## Reports and cleanup

Default output: `reports/<local-time>-<random-id>/report.json` and `report.csv`.

- `PASS`: observations match the expectation; listener continuity and cleanup are confirmed.
- `FAIL`: observations contradict the expectation with healthy listeners and confirmed cleanup.
- `ERROR`: incomplete run, wrong network, preflight/setup/SSH/marker failure, unsupported binding, changed/unverified existing listener, expired/unhealthy monitor, or unconfirmed cleanup. This does not prove a firewall rule worked.
- Exit codes: `0` = PASS; `1` = FAIL; `2` = ERROR.

Temporary mode listens on `0.0.0.0` for the selected empty TCP ports and returns only a run identifier. Existing mode leaves the service in place and records listener evidence; cleanup stops only the test listener/monitor unit. The tool serves no files and installs no packages. It does not modify cloud or OS firewall rules. If a supposedly blocked port is misconfigured, this intentionally makes a harmless test listener reachable so the test can detect it.

`RuntimeMaxSec` stops only the test listener/monitor service even if SSH or the laptop disconnects; existing applications keep running. The listener also has its own lifetime limit. `ExecStopPost` removes its run directory under `/run/firewall-port-tester/<random-id>`; `/run` is cleared on reboot. Normal cleanup happens immediately after testing. Cleanup attempts SSH even if the public-IP endpoint is unavailable; failed cleanup remains ERROR and the independent expiry still applies. No persistent startup service is installed. The empty root-owned base directory may remain.

If interrupted while outside the company network, return to company access and run:

```bash
./test-ports.sh cleanup --run-dir reports/<run-directory>
```

This command uses the local `run.local.json` recovery manifest and only stops services with that run's ID. It is safe to repeat. It does not turn an incomplete report into a verified PASS; run a fresh test for a complete result. After automatic expiry, health evidence is intentionally removed, so the original run may remain ERROR. Never manually delete another application's process to free a port.

## Configuration and AI assistance

See [config.schema.json](config.schema.json) for the machine-readable format and [AI-GUIDE.md](AI-GUIDE.md) for instructions and ready-to-copy prompts. A per-machine `ssh` object may override the shared SSH settings.

The tool requires only a **local key path**, never private-key text. Do not send private keys to an AI or paste credentials into this repository.

## Public repository rules

This repository is public. Tracked examples contain only documentation addresses and placeholder paths. Keep actual host IPs, company CIDRs, usernames/key paths tied to your environment, tokens, SSH material and reports out of commits. Use ignored `*.local.json` files and the ignored `reports/` directory. Ignore rules are a safeguard, not a substitute for checking staged changes; do not use `git add -f` on local data.

## HTTPS certificate troubleshooting

If public-IP lookup reports `CERTIFICATE_VERIFY_FAILED`, your local Python may lack a trusted CA bundle. Configure a valid CA bundle trusted by your organization for this process, or fix your Python installation's certificate setup:

```bash
SSL_CERT_FILE=/path/to/trusted-ca-bundle.pem ./test-ports.sh run --config targets.local.json
```

The path is a local setting; do not commit a company CA bundle. Keep certificate verification enabled. Do not use an unverified SSL context or replace the HTTPS endpoint with HTTP.

## Local development checks

```bash
python3 -m unittest discover -s tests -v
./test-ports.sh validate --config examples/targets.example.json
bash -n test-ports.sh
```

Tests use fake SSH/systemd responses and local loopback sockets; they do not contact cloud VMs or public IP services. Automated tests do not replace an authorized integration test of your own VM image and network rules.

## License

[MIT](LICENSE).
