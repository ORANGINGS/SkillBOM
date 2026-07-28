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

## 履歷可以怎麼寫

> Built an offline static-analysis CLI for Agent Skills that generates evidence-backed capability/dependency manifests, emits SARIF, and blocks unexpected privilege drift in GitHub pull requests.

這個專案能展示 Python 套件設計、AST／規則分析、供應鏈安全、CLI、JSON Schema 類型資料、GitHub Actions、SARIF、測試與開源文件能力。
