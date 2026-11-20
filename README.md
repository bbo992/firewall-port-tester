# firewall-port-tester

A reusable tool to verify **TCP port access after VM provisioning**. It starts temporary listeners over SSH, tests an explicit list of IP addresses and ports from company and external networks, and produces local JSON/CSV reports.

這是 VM 建立後，用來確認 IP／TCP port 存取規則是否符合預期的工具。只測試你明確指定、自己管理或已獲授權的主機；不是資安弱點掃描、密碼破解或入侵工具，也不會自動探索其他主機或掃描整段 port。

## What it checks

| Setting | Company network | External network |
| --- | --- | --- |
| `world_ports` | Allow | Allow |
| `company_ports` | Allow | Block |
| `blocked_ports` | Block | Block |

All selected ports, **including blocked ports**, receive temporary listeners. After external testing, return to the company network so the tool can verify that the same listener process stayed healthy throughout the test and then remove it. Failed connections without this evidence receive `ERROR`, not `PASS`.

Results describe end-to-end TCP reachability from the laptop. They do not identify whether a cloud NSG, host firewall, upstream router or another layer permitted/blocked traffic. TLS, application behavior, private-network traffic and third-party-specific allowlists are outside this version's scope. Public-IP checks do not prove the exact routing of every target, especially with split-tunnel VPNs; verify your routing independently when applicable.

## Requirements

- Local macOS or Linux, Bash, Python 3.9+ and OpenSSH client. No pip packages needed.
- Remote Linux VM with Python 3.9+, systemd (`systemctl`, `systemd-run`) and an SSH account allowed to run `sudo -n python3`. The complete flow has also been tested from macOS against Ubuntu 26.04/systemd VMs. Other images still require compatibility verification.
- SSH authentication must already work non-interactively. For an encrypted key, load the matching key in `ssh-agent` first. Private keys remain on the laptop.
- SSH reachable from the company network. It need not be reachable from external networks.
- Selected test ports must be unused. The tool will not stop existing services. Do not list the SSH management port as a temporary test port.
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
2. Use SSH and passwordless sudo to start a unique transient systemd listener service on each VM. All listeners must bind successfully before testing begins. An occupied port aborts setup and triggers cleanup; no existing service is stopped.
3. Test company expectations, then prompt you to switch to an external network. Disable/change any VPN that would keep traffic on the company egress IP.
4. Verify that the source is outside `company_cidrs`, then test external expectations.
5. Prompt you to return to the company network. Retrieve listener health, verify continuity, stop this run's test services, remove their files, and write the final report.

The source IP is queried directly over HTTPS using `https://api.ipify.org` by default. That service sees your public source IP; no host inventory, ports or credentials are sent. You can specify a trusted alternative HTTPS endpoint returning plain IPv4 using `settings.public_ip_url`. HTTP proxy environment variables are bypassed so the source check uses a direct connection. A failed source check stops the run.

OpenSSH uses your local `known_hosts` and `StrictHostKeyChecking=accept-new`: new host keys are recorded; changed keys are rejected. SSH configuration may also affect routing or authentication. Review these settings for your environment.

## Reports and cleanup

Default output: `reports/<local-time>-<random-id>/report.json` and `report.csv`.

- `PASS`: observations match the expectation; listener continuity and cleanup are confirmed.
- `FAIL`: observations contradict the expectation with healthy listeners and confirmed cleanup.
- `ERROR`: incomplete run, wrong network, setup/SSH/marker failure, expired/unhealthy listener, or unconfirmed cleanup. This does not prove a firewall rule worked.
- Exit codes: `0` = PASS; `1` = FAIL; `2` = ERROR.

The service listens on `0.0.0.0` for the explicitly listed TCP ports and returns only a run identifier. It does not serve files or install packages. It does not modify cloud or OS firewall rules. If a supposedly blocked port is misconfigured, this intentionally makes a harmless test listener reachable so the test can detect it.

`RuntimeMaxSec` stops the service even if SSH or the laptop disconnects. The listener also has its own lifetime limit. `ExecStopPost` removes its run directory under `/run/firewall-port-tester/<random-id>`; `/run` is cleared on reboot. Normal cleanup happens immediately after testing. Cleanup attempts SSH even if the public-IP endpoint is unavailable; failed cleanup remains ERROR and the independent expiry still applies. No persistent startup service is installed. The empty root-owned base directory may remain.

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
