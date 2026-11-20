# Project instructions for AI assistants

This is a PUBLIC, reusable TCP connectivity verification tool for VMs after provisioning.
It checks explicit, authorized targets against expected company/public access policies.
It is not a vulnerability scanner, password cracker, exploit framework or discovery scanner.

- Never add real environment IPs, company CIDRs, host inventories, credentials, private keys, tokens, webhooks or test results to tracked files. Examples must use documentation-only addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and placeholder paths.
- Actual inputs belong in ignored `*.local.json`; generated artifacts belong under ignored `reports/`. Verify ignore rules before adding files. Never read, print, copy or upload private-key contents. A local key path is sufficient.
- Read README.md, AI-GUIDE.md and config.schema.json before configuring tests. Reuse the schema; do not invent missing IPs, CIDRs, users or port policies.
- Creating or validating a config does not authorize remote execution. Run against actual targets only when the user has authorized testing them. Do not commit or push without user authorization.
- Preserve the company → external → return-to-company workflow. Never expose SSH, change cloud/OS firewall rules, stop existing services, install packages or rebuild VMs to make a test pass.
- Run preflight for every VM before starting any test services. Automatically choose per port: temporary listener for an empty port, existing-service TCP-only mode for a verified occupied port, ERROR for unsupported/unverifiable bindings. Never kill or take over an existing process. A race after preflight must fail safely.
- Every selected test port, including expected-blocked ports, needs listener evidence. Existing services are monitored by socket identity sampling and local TCP readiness; gaps or changed listeners invalidate only affected ports. Do not claim continuous application health.
- Existing-service probes send/read no application data, but real connections may still affect logs/counters/rate limits. Explain this when testing live services. Detected host NAT/redirect forwarding is unsupported; never label a forwarded endpoint as a verified empty port.
- A failed connection is not enough to prove a firewall blocked it. Require listener continuity and cleanup confirmation; unknown states are ERROR, not PASS.
- Temporary listeners must expire independently of the SSH/local process. Only stop this run's unique systemd unit and remove its owned files; no broad pkill or directory deletion.
- Explain that results measure end-to-end TCP access from the observed source, not which firewall layer enforced it, nor TLS/application correctness.
- Use only Python standard library dependencies and keep the Bash entry point portable to macOS/Linux. Test with mocks and loopback; never use real infrastructure in automated unit tests.
