# firewall-port-tester

[English](README.md) | [繁體中文](README.zh-TW.md)

這是一個用來驗證**新建或現有 VM 的 TCP port 存取規則**的工具。先透過 SSH 預檢所有主機，依每個 port 的狀態自動選擇暫時監聽或既有服務模式，再從公司與外網測試並產出本機 JSON／CSV 報告。原有設定格式不變，不需要手動指定模式。

僅供測試自己管理或已獲授權的主機。這不是弱點掃描、密碼破解或入侵工具，只測試你明確列出的主機與 TCP port，不會自動探索其他主機或掃描整段 port。

## 簡易流程：搭配 AI 怎麼使用？

**公司網路 → 外網 → 公司網路 → 查看報告**

你可以請 AI 協助設定與執行，也可以自行操作指令。開始前，請先將 VM 開機，並確認能透過 SSH 登入。

1. **提供測試資料給 AI。** 包含 VM 的公網 IPv4、公司出口 IP／CIDR、SSH 帳號、私鑰的本機路徑，以及「全世界可連」「僅公司可連」「應禁止連線」的 port 清單。只提供私鑰路徑，不要提供私鑰內容。
2. **請 AI 準備設定檔。** AI 讀取本專案說明，建立只留在本機的 `targets.local.json`，並檢查格式。你授權實測後，才開始連線 VM。[AI-GUIDE.md](AI-GUIDE.md) 有可直接複製的提示詞。
3. **讓工具預檢並自動選擇模式。** 所有 VM 預檢完成後才啟動測試程序。空閒 port 建立暫時 Python 監聽；已使用的 port 使用原服務，另啟動監控來確認監聽狀態。無法使用或判斷不明的 port 記為 `ERROR`，不當成防火牆正常擋住。
4. **先測公司網路。** 確認全世界可連與僅公司可連的 port 可以連線，應禁止的 port 無法連線。
5. **依提示切換外網。** 例如讓電腦連上手機熱點，使用手機的 **4G／5G 行動網路**；同時確認 VPN 沒有繼續讓流量走公司出口。完成後告訴 AI 已切換，或在自行操作的終端機按 Enter。工具確認公網來源 IP 已不在公司清單，再測試全世界可連的 port 是否能連、僅公司與應禁止的 port 是否被擋住。
6. **依提示切回公司網路。** 工具重新透過 SSH 登入，檢查暫時監聽持續正常，並核對既有監聽的識別與 TCP 就緒證據。
7. **清理並查看報告。** 工具停止這次建立的監聽與監控、移除暫存檔，並將 JSON／CSV 報告存到本機。你可以請 AI 說明 PASS、FAIL、ERROR 的結果。監聽健康或清理未確認時，不會判定通過。

預設 **1 小時是暫時監聽的最長存活時間，不是連線等待時間**。正常測完就立即清理；每次連線預設最多 3 秒，每個 port 測試 2 次。

## 測試規則

| 設定欄位 | 公司網路 | 外網 |
| --- | --- | --- |
| `world_ports` | 應可連線 | 應可連線 |
| `company_ports` | 應可連線 | 應禁止連線 |
| `blocked_ports` | 應禁止連線 | 應禁止連線 |

所有待測 port 都需要可驗證的 TCP 監聽，包含預期禁止的 port；只有空閒 port 才會由工具建立監聽。外網測試後須切回公司，核對監控證據並完成清理。缺少監聽證據的連線失敗會記為 `ERROR`，不會直接判定防火牆通過。

結果代表從這台電腦出發的端到端 TCP 存取情況，無法單獨判定是雲端 NSG、主機防火牆或上游路由器的哪一層生效。本版不驗證 TLS、應用服務、內網存取或其他指定第三方來源的白名單。公網 IP 查詢也無法證明每個目標的實際路由；若使用分流 VPN，請另行確認路由設定。

## 自動判斷 port 模式

工具會先預檢**所有 VM，才啟動任何測試監聽或監控程序**。預檢會確認 TCP 監聽、SSH 目的端的 IPv4 介面、主機的 NAT／轉發規則與 TCP 就緒狀態；空閒 port 會短暫嘗試綁定後釋放，不開始監聽。任何主機預檢失敗時，都不會進入啟動測試程序的階段。每個既有候選 port 在預檢時可能有一次本機 TCP 連線。

| 偵測狀態 | 自動模式 | 處理方式 |
| --- | --- | --- |
| 空閒且可綁定的 TCP port | `temporary` | 建立暫時監聽，並驗證本次測試識別碼。 |
| 既有監聽可從目標介面接受 IPv4 TCP | `existing` | 使用原服務，只測 TCP 握手，不收送應用資料或測試識別碼。 |
| 只綁 localhost／其他介面、未就緒、識別不明或已保留的 port | `unsupported` | 跳過該 port 的網路探測，記為 `ERROR`，保留原狀。 |

同一台 VM 可以混用上述模式。SSH 管理 port 可以列入，但只能使用既有監聽；若沒有可驗證的管理監聽，工具不會自行建立。預檢後若有服務搶先占用原本空閒的 port，啟動會失敗並清理，不會接管或默默改用另一個服務。

既有服務模式會約每秒抽樣一次 Linux 監聽 socket 的識別與連線佇列容量。監聽消失／被替換、綁定改變、佇列飽和／容量不明、讀取失敗或監測間隔超過 3 秒，都會保留異常紀錄，即使後來恢復也不判定通過。切回公司時，每個既有 port 另做一次本機 TCP 就緒檢查。證據失效只會影響該 port，其他 port 仍可通過。這是抽樣的 TCP 監聽證據，不是應用服務的持續健康保證；抽樣間的極短暫變化可能無法發現。

既有服務測試會建立真正的 TCP 連線，但不收送應用資料。服務仍可能留下連線、未完成握手、計數器或限速事件，正式服務請安排合適的測試時段。工具不會停止、重新啟動或修改原服務，也不送登入、HTTP 或資料庫指令。

本版支援 VM 主機網路命名空間內的直接監聽。偵測到 DNAT、REDIRECT 或透明代理轉發時，會保守中止預檢，即使轉發規則看似與本次 port 無關。Docker 對外映射 port、主機轉發或公網流量抵達其他介面／端點的情境，需要另外驗證。轉發規則工具不存在或無法讀取時，也會中止，不自行假設 port 空閒。VM 外部的雲端公網 IP 對應，只要流量抵達 SSH 的目的介面，本身不會觸發這項主機規則檢查。

監聽識別依據 [Linux TCP socket 表的官方格式](https://docs.kernel.org/networking/proc_net_tcp.html)，佇列資訊來自 [`ss`](https://man7.org/linux/man-pages/man8/ss.8.html)。報告新增每個 port 的 `mode`、`listener_healthy`、`health_reason`、`cleanup_confirmed`；JSON 報告格式為第 2 版。設定檔不需要新增模式欄位。

## 執行前準備

- 本機使用 macOS 或 Linux，具備 Bash、Python 3.9+ 與 OpenSSH client，無需安裝 pip 套件。
- 遠端 VM 使用 Linux，已安裝 Python 3.9+ 與 systemd（`systemctl`、`systemd-run`）；SSH 帳號可免密碼執行 `sudo -n python3`。先前的暫時監聽流程曾由 macOS 對 Ubuntu 26.04／systemd VM 實測；新增的既有服務自動模式已做本機／模擬回歸測試，仍需在自己的映像進行已獲授權的整合驗證。
- VM 已開機，SSH 可以非互動方式驗證登入。若私鑰有密碼，請先將對應金鑰載入 `ssh-agent`。私鑰留在本機。
- 公司網路可以連上 VM 的 SSH；外網不需要開放 SSH。
- 遠端可讀取 `/proc/net/tcp`，IPv6 啟用時也可讀取 `/proc/net/tcp6`，具備 `ss` 供監聽佇列檢查，以及 `nft` 或 `iptables-save` 供轉發規則檢查。工具不會安裝套件。
- 既有服務可從 SSH 的目的 IPv4 介面或萬用綁定位址接受 TCP；只綁 localhost、轉發或判斷不明的端點不會被判定為防火牆通過。
- 能在監聽到期前完成兩次網路切換；預設最長存活時間為 1 小時。

## 快速開始

先複製設定範例：

```bash
cp examples/targets.example.json targets.local.json
```

編輯 `targets.local.json`，填入實際的公司公網來源 CIDR、SSH 帳號與私鑰路徑、VM 公網 IPv4 及 port 清單。範例中的 IP 是文件用假資料，必須替換。私鑰相對路徑以設定檔所在資料夾為基準，也支援 `~`。

```bash
chmod 600 /path/to/your/private-key.pem
./test-ports.sh validate --config targets.local.json
./test-ports.sh run --config targets.local.json
```

`validate` 只檢查設定，**不會 SSH、發出 HTTP 請求或修改遠端**。`run` 才會執行公司來源確認、所有 VM 的 port 預檢與模式選擇、啟動暫時監聽／既有監聽監控、公司測試、提示切換外網、外網測試，以及切回公司後的驗證與清理。

每次嘗試的預設 3 秒包含 TCP 連線與讀取識別碼，每個 port 測試 2 次，合計約最多 6 秒，另加排程開銷。多個 port 會並行測試，整批時間可能更長。逾時與重試次數可在設定檔調整，與監聽最長存活時間分開設定。

工具預設直接透過 HTTPS 向 `https://api.ipify.org` 查詢來源公網 IPv4。該網站只會看到來源公網 IP，不會收到主機清單、port 或憑證資料。可透過 `settings.public_ip_url` 改用信任的 HTTPS 網址，回應須為純文字 IPv4。查詢會略過 HTTP proxy 環境變數，以直接連線取得來源；來源檢查失敗時會中止測試，並嘗試清理。

OpenSSH 使用本機 `known_hosts` 與 `StrictHostKeyChecking=accept-new`：新主機金鑰會被記錄，已知主機的金鑰變更會被拒絕。SSH 設定也可能影響路由與驗證方式，請依環境確認。

## 報告與清理

預設報告位置：`reports/<本機時間>-<隨機識別碼>/report.json` 與 `report.csv`。

| 結果 | 意義 |
| --- | --- |
| `PASS` | 觀察符合預期，且監聽持續正常與清理均已確認。 |
| `FAIL` | 在監聽正常、清理已確認的情況下，觀察與預期不符。 |
| `ERROR` | 流程不完整、來源網路不符、預檢／SSH／監聽／識別碼異常、不支援的綁定、既有監聽改變、監控過期或清理未確認，無法證明規則通過。 |

指令結束代碼：`0` = PASS、`1` = FAIL、`2` = ERROR。

暫時模式在選定的空閒 TCP port 綁定 `0.0.0.0`，只回傳本次測試識別碼；既有模式保留原服務並記錄監聽證據，清理只停止本次測試監聽／監控程序。工具不提供檔案、不安裝套件，也不修改雲端或系統防火牆。若原本應封鎖的 port 實際開放，測試連線就能透過這個監聽發現問題。

即使本機或 SSH 斷線，systemd 的 `RuntimeMaxSec` 仍會停止本次測試監聽／監控，原有應用服務會繼續運作；Python 監聽本身也有存活時間限制。服務停止時，`ExecStopPost` 會移除 `/run/firewall-port-tester/<隨機識別碼>` 的本次資料，主機重新開機時 `/run` 也會清空。正常流程會在測完後立即清理；即使公網 IP 查詢異常，仍會嘗試透過 SSH 清理。清理無法確認會維持 ERROR，自動到期機制仍有效。不會安裝持續開機啟動的服務，空的 root 擁有者基底目錄可能保留。

若在外網中斷，請先回到公司網路，再執行：

```bash
./test-ports.sh cleanup --run-dir reports/<run-directory>
```

此指令使用本機的 `run.local.json`，只停止該次識別碼對應的服務，可重複執行。補做清理不會把原本不完整的報告直接改成 PASS；需要完整結果時，請重新測試。自動到期後監聽健康證據會一起移除，原測試可能維持 ERROR。請勿為了騰出 port 而刪除其他服務的程序。

## 設定格式與 AI 協助

[config.schema.json](config.schema.json) 提供機器可讀的設定格式，[AI-GUIDE.md](AI-GUIDE.md) 提供 AI 操作說明與提示詞。每台 VM 可透過自己的 `ssh` 欄位覆寫共用 SSH 設定。

工具只需要**私鑰的本機路徑**。不要將私鑰內容傳給 AI，或將任何登入憑證貼到公開專案。

## 公開專案注意事項

此專案對外公開，追蹤中的範例只使用文件用 IP 與佔位路徑。實際主機 IP、公司 CIDR、環境帳號與私鑰路徑、token、SSH 金鑰及報告都應留在本機。

請使用被 Git 忽略的 `*.local.json` 與 `reports/`。忽略規則只是保護措施，提交前仍須檢查暫存內容；不要對實際環境資料使用 `git add -f`。

## HTTPS 憑證問題

若查詢公網 IP 時出現 `CERTIFICATE_VERIFY_FAILED`，可能是本機 Python 缺少可信任的 CA 清單。請為本次程序指定組織信任的有效 CA bundle，或修正 Python 安裝的憑證設定：

```bash
SSL_CERT_FILE=/path/to/trusted-ca-bundle.pem ./test-ports.sh run --config targets.local.json
```

CA 路徑屬於本機設定，不要提交公司的 CA bundle。請保留憑證驗證，不使用跳過驗證的 SSL 設定，也不將 HTTPS 查詢改為 HTTP。

## 本機開發檢查

```bash
python3 -m unittest discover -s tests -v
./test-ports.sh validate --config examples/targets.example.json
bash -n test-ports.sh
```

自動測試使用模擬 SSH／systemd 與本機 loopback socket，不連線雲端 VM 或公網 IP 查詢服務。自己的 VM 映像與網路規則仍須另做已獲授權的整合測試。

## 授權

[MIT](LICENSE)。
