# AI guide and reusable prompts

## Purpose and execution boundary

This project verifies expected TCP access **after a VM exists**. It tests explicit authorized targets from a laptop, first through company egress, then external egress, then back through company egress for health verification and cleanup. It is not a vulnerability, discovery, password or exploit tool.

Read `AGENTS.md`, `README.md`, `config.schema.json` and the example before preparing a test. Configuration preparation does not authorize connections. Ask for execution authorization if the user has only requested configuration or discussion. Do not commit/push unless requested. Respect additional instructions in the user's environment.

## Required input from the operator

- Authorized VM names and public **IPv4** addresses.
- SSH user, local private-key **path** and SSH port; optional per-VM overrides.
- Exact company public source IPv4 CIDRs. Do not confuse them with VM private subnet CIDRs.
- Explicit per-VM `world_ports`, `company_ports`, `blocked_ports`. Missing classification must be clarified; do not infer it from a port number or silently add ports.
- Authorization to preflight the selected ports, briefly bind/release empty ports and make TCP-only connections to existing services. Mode choice is automatic; do not ask the user to guess which ports are occupied or stop any service.
- For live services, explain that TCP-only connections still produce logs/counters and may trigger rate limits. The tool requires readable Linux TCP socket tables, ss listener-queue checks and nft/iptables-save forwarding checks; detected forwarded/container ports are unsupported.
- Whether the operator can switch company → external → company within the listener lifetime.

A VM with no world-open ports can use `world_ports: []`. Every VM must have at least one explicit port. Port arrays must not overlap. A listed SSH management port is always existing-only; the tool never creates one if no verified listener exists. Only TCP and IPv4 are supported. Do not include private-network-only or third-party-specific tests unless the tool is deliberately extended.

## Output contract

1. Write actual environment inputs to an ignored `targets.local.json` (or another `*.local.json`). Before saving, confirm that Git ignores it; if the folder is not a Git checkout, explain that it must remain local.
2. Use schema version 1. Do not put private-key contents into any file or command. Ask for a path, never a private-key upload.
3. Run `./test-ports.sh validate --config targets.local.json` before requesting/performing an authorized remote run. This command has no network side effects.
4. Explain exactly which IPs and ports will be tested, automatic per-port modes, preflight on every VM before any test service starts, temporary root listener/monitor behavior, the configured expiry, the public-IP endpoint and the two manual network switches. Keep actual environment details in local files or direct user communication, never in tracked examples/docs.
5. Only after execution is authorized, run `./test-ports.sh run --config targets.local.json` in an interactive terminal. Let the operator perform each network switch and press Enter. An AI must not press Enter on their behalf without evidence that the switch is complete. If the execution environment cannot accept interactive input/network changes, give the operator the command instead of fabricating a completed test.
6. Read the local report. Distinguish PASS/FAIL/ERROR and disclose any unverified cleanup. Do not equate a failed TCP connection with a successful firewall test unless listener continuity is confirmed.
7. Reports use `report_version: 2` and include `mode` (temporary/existing/unsupported), `listener_healthy`, `health_reason`, and `cleanup_confirmed` per port. Read `hosts.*.preflight` and final `port_status` to explain unsupported bindings or changed listeners. Do not label an ERROR as a blocked-port PASS. Existing-listener monitoring is sampled, not proof of uninterrupted application health.
8. If needed, return to company access and use the generated cleanup command. Do not restart/rebuild VMs or alter security rules as a testing shortcut.

## Prompt: prepare a configuration

```text
請先閱讀此專案的 AGENTS.md、README.md、AI-GUIDE.md、config.schema.json 與範例。
這是公開專案；不得把實際環境資料或報告放進 tracked 檔案。
請根據我下面提供的資訊產生 ignored 的 targets.local.json，執行 validate。
這一步只建立設定，不授權 SSH、HTTP 查詢或對遠端進行測試，也不要 commit/push。
缺少資料或 port 分類不清楚時先問我，不要猜。

公司出口 CIDR：[填寫，例如公司的固定公網 IP/32；不要提供內網 CIDR]
SSH 預設帳號：[填寫]
SSH 私鑰本機路徑：[只填路徑，不提供私鑰內容]
SSH port：[填寫]
各 VM：
- 名稱：[填寫]
  公網 IPv4：[填寫]
  全世界可連 TCP ports：[填寫或空陣列]
  僅公司可連 TCP ports：[填寫或空陣列]
  應禁止連線 TCP ports：[填寫或空陣列]
  SSH 覆寫：[如無則沿用預設]

模式由工具在 run 的預檢階段逐 port 判斷，不要在設定檔新增 mode 欄位。
請列出尚缺的資訊、設定檢查結果與後續執行指令。
```

## Prompt: execute an authorized test

```text
請先閱讀此工具的操作與安全範圍說明。
我授權你測試本機 targets.local.json 所列、由我管理的 VM 和 TCP ports。
先 validate 並向我說明測試目標與時效；不修改任何 cloud/OS 防火牆，
不安裝套件、不停止既有服務，不 commit/push。
讓工具先預檢所有 VM，再自動選擇空閒 port 的暫時監聽或既有服務模式。
不要接管已使用的 port；localhost-only、轉發或無法驗證的端點保留 ERROR。
既有服務只測 TCP，仍可能留下連線紀錄或觸發限速；先向我說明。
使用互動終端執行 run，讓我依提示切換公司 → 外網 → 公司。
在我完成切換前不要代按 Enter。無法保留互動終端時，給我自己執行的命令。
完成後解讀本機報告，確認監聽健康與清理狀態。
任何缺證據的結果都維持 ERROR，不可把沒有服務或斷線當作防火牆通過。
```

## Prompt: interpret a report

```text
請讀取我指定的本機 reports/<run-directory>/report.json。
這份報告包含實際環境資訊，不可提交到公開 Git 或複製到追蹤中的文件。
請用簡單中文列出 PASS、FAIL、ERROR 的數量，哪些 VM/port 不符預期，
公司與外網來源檢查、各 port 的 mode、listener_healthy、health_reason、
cleanup_confirmed，以及遠端監控與清理是否已確認。
請區分防火牆預期不符、SSH/監聽建立失敗、切換網路錯誤與清理未確認。
只能提供依據，不可僅憑 timeout 宣稱 NSG 設定正確。
這一步只分析，不授權連線重測、改規則或 commit/push。
```
