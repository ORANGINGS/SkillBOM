# SkillBOM

SkillBOM 是一個針對 **Agent Skills** 的靜態分析與供應鏈治理工具。它不只找危險字串，而是產生一份可版本控制的「技能物料清單」，記錄：

- Skill 的檔案與 SHA-256 雜湊
- Python、Node、系統工具與外部服務依賴
- 網路、憑證、Shell、檔案寫入、套件安裝與破壞性操作能力
- Agent Skills 規格問題與安全風險
- 相較基準版本新增的能力與依賴

## 最重要的使用情境

原本的 Skill 只讀取本機文件，但某次 PR 新增：

```text
+ credential-access
+ network-access
+ service:api.example.com
```

一般程式碼審查可能漏掉這個權限變化；SkillBOM 會把它視為高風險 capability drift，讓 CI 失敗並要求人工審查。

## 執行

```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -e .

skillbom scan examples\safe-skill
skillbom scan examples\risky-skill --fail-on high
```

建立基準：

```powershell
skillbom lock .github\skills --output skillbom.lock.json
```

比較新版：

```powershell
skillbom lock .github\skills --output current.json
skillbom diff skillbom.lock.json current.json --fail-on high
```

## Policy-as-Code 安全供應鏈閘門

0.2.0 讓專案能定義「哪些風險不被允許」；0.3.0 再把例外升級成**有期限、可稽核、預設失敗封閉**的安全核准紀錄。

建立範本：

```powershell
skillbom init-policy
```

`skillbom.policy.yml` 範例：

```yaml
schema-version: "2"
defaults:
  require-spec-valid: true
  max-finding-severity: medium
  denied-capabilities:
    - credential-access
    - privileged-operation
    - destructive-filesystem
  allowed-services:
    - github.com
    - "*.github.com"
  allowed-agent-tools:
    - Read
    - Grep
  exception-expiry-warning-days: 14
  max-exception-days: 90
  require-exception-ticket: true
  require-separation-of-duties: true

skills:
  release-helper:
    capability-exceptions:
      - item: process-execution
        reason: 必須呼叫已核准的發布 CLI
        owner: platform-team
        approved-by: security-team
        approved-at: 2026-07-28
        expires-at: 2026-10-26
        ticket: SEC-123
```

每個例外都必須說明用途、負責人、核准者、核准日期、到期日與工單。`expires-at` 當天仍有效；隔天開始會被視為過期。閘門還會偵測：

- 已過期或尚未生效的例外
- 期限超過政策上限的例外
- 負責人自行核准的例外
- 缺少工單的例外
- Skill 已不再需要、但政策仍保留的殘留權限
- 政策指向已不存在 Skill 的孤兒規則
- 舊版純字串例外，並要求遷移到 schema version 2

執行閘門：

```powershell
skillbom gate .github\skills --policy skillbom.policy.yml

# 固定稽核日期，方便重現歷史 CI 結果
skillbom gate .github\skills --policy skillbom.policy.yml --as-of 2026-07-28
```

它可以直接阻擋被禁止的能力、未核准網域、未核准 Agent Tool、過高風險 finding，以及治理資料不完整或失效的例外。政策鍵若拼錯或 grant 缺欄位會直接失敗，不會靜默忽略。

## 履歷可以怎麼寫

> Built an offline security supply-chain gate for Agent Skills that enforces least-privilege policy-as-code, governs time-bounded security exceptions with separation of duties, emits SARIF, and blocks stale or expired privilege in GitHub pull requests.

這個專案能展示 Python 套件設計、AST／規則分析、供應鏈安全、CLI、JSON Schema 類型資料、GitHub Actions、SARIF、測試與開源文件能力。
