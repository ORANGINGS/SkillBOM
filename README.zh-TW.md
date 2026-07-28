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

第一版只能告訴你「Skill 有哪些風險」；0.2.0 新增的 policy gate 可以定義「哪些風險在這個專案中不被允許」。

建立範本：

```powershell
skillbom init-policy
```

`skillbom.policy.yml` 範例：

```yaml
schema-version: "1"
defaults:
  require-spec-valid: true
  max-finding-severity: medium
  denied-capabilities:
    - embedded-secret
    - privileged-operation
    - destructive-filesystem
  allowed-services:
    - github.com
    - "*.github.com"
  allowed-agent-tools:
    - Read
    - Grep

skills:
  release-helper:
    capability-exceptions:
      - process-execution
    service-exceptions:
      - uploads.example.com
```

執行閘門：

```powershell
skillbom gate .github\skills --policy skillbom.policy.yml
```

它可以直接阻擋：

- 被政策禁止的憑證、提權、破壞性或動態執行能力
- 未列入 allowlist 的外部網域
- 未核准的 Agent Tool，例如 `Bash`
- 超過政策容許等級的新資安 finding
- 不符合 Agent Skills 規格的 Skill

政策鍵若拼錯會直接失敗，不會靜默忽略；每個 Skill 的例外也必須明確寫進版本控制。這使 SkillBOM 從掃描器升級成可放入 Pull Request 的供應鏈安全閘門。

## 履歷可以怎麼寫

> Built an offline security supply-chain gate for Agent Skills that generates evidence-backed capability/dependency manifests, enforces least-privilege policy-as-code, emits SARIF, and blocks unexpected privilege drift in GitHub pull requests.

這個專案能展示 Python 套件設計、AST／規則分析、供應鏈安全、CLI、JSON Schema 類型資料、GitHub Actions、SARIF、測試與開源文件能力。
