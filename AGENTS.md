# Project instructions for AI assistants

This is a PUBLIC, reusable TCP connectivity verification tool for VMs after provisioning.
It checks explicit, authorized targets against expected company/public access policies.
It is not a vulnerability scanner, password cracker, exploit framework or discovery scanner.

- Never add real environment IPs, company CIDRs, host inventories, credentials, private keys, tokens, webhooks or test results to tracked files. Examples must use documentation-only addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and placeholder paths.
- Actual inputs belong in ignored `*.local.json`; generated artifacts belong under ignored `reports/`. Verify ignore rules before adding files. Never read, print, copy or upload private-key contents. A local key path is sufficient.
- Read README.md, AI-GUIDE.md and config.schema.json before configuring tests. Reuse the schema; do not invent missing IPs, CIDRs, users or port policies.
- Creating or validating a config does not authorize remote execution. Run against actual targets only when the user has authorized testing them. Do not commit or push without user authorization.
- Preserve the company → external → return-to-company workflow. Never expose SSH, change cloud/OS firewall rules, stop existing services, install packages or rebuild VMs to make a test pass.
- Every selected test port, including expected-blocked ports, must have a verified listener. Occupied ports are setup errors, not permission to kill another process.
- A failed connection is not enough to prove a firewall blocked it. Require listener continuity and cleanup confirmation; unknown states are ERROR, not PASS.
- Temporary listeners must expire independently of the SSH/local process. Only stop this run's unique systemd unit and remove its owned files; no broad pkill or directory deletion.
- Explain that results measure end-to-end TCP access from the observed source, not which firewall layer enforced it, nor TLS/application correctness.
- Use only Python standard library dependencies and keep the Bash entry point portable to macOS/Linux. Test with mocks and loopback; never use real infrastructure in automated unit tests.
