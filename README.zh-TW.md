# SkillBOM

SkillBOM 是針對 **Agent Skills、MCP Server 與 AI 工具整合 Repository** 的靜態安全分析與供應鏈治理工具。

它不是一般的程式 Bug Scanner；核心用途是找出：

- 未在 README、SKILL.md 或文件中揭露的敏感能力
- MCP Tool 暴露的指令、檔案、憑證與網路權限
- 安裝階段下載並執行遠端程式等供應鏈風險
- 新舊版本之間新增的 Capability、外部網域與 MCP Tool
- Agent Skill 政策違規與已過期的安全例外

核心掃描採用 AST、規則引擎、Manifest 分析與 Git Diff，**不需要付費 AI API Key**。

## 掃描本機 MCP／Agent 專案

```powershell
skillbom scan C:\path\to\mcp-server
```

## 直接掃描公開 GitHub Repository

```powershell
skillbom scan https://github.com/owner/repository
skillbom scan https://github.com/owner/repository --ref v1.4.0
```

SkillBOM 會使用非互動式淺層 `git clone`，不初始化 submodule、不執行 Repository hook、忽略符號連結，並在掃描後刪除暫存 checkout。

## 比較兩個版本的能力漂移

```powershell
skillbom repo-diff https://github.com/owner/repository `
  --base-ref v1.3.0 `
  --head-ref v1.4.0
```

可能輸出：

```text
HIGH  capability-added  process-execution
HIGH  dependency-added  mcp-tool:run_command
MEDIUM dependency-added  service:api.unknown.example
```

## Repository 掃描內容

- Python `subprocess`、`os.system`
- Node.js `child_process.exec/spawn`
- JavaScript `eval`、`Function`
- `.ssh`、雲端憑證、`.env`、瀏覽器 Cookie／登入資料
- npm `preinstall`、`install`、`postinstall`
- 遠端下載後直接交給 Shell 執行
- Python 與 JavaScript／TypeScript MCP Tool 註冊
- 程式能力與文件聲明的落差
- 外部服務網域是否有揭露

輸出支援終端、JSON 與 SARIF：

```powershell
skillbom scan .\my-mcp --format json --output report.json
skillbom scan .\my-mcp --format sarif --output report.sarif
```

## Agent Skill Policy Gate

原有的 Skill Policy-as-Code 功能仍保留：

```powershell
skillbom gate .github\skills --policy skillbom.policy.yml
```

可阻擋禁止能力、未核准網域、未核准 Agent Tool、過高風險 Finding，以及過期、自我核准或缺少工單的安全例外。

## 重要限制

SkillBOM 不會執行受掃描程式，也不保證掃描通過即代表專案完全安全。正確定位是：

> 依目前可見程式碼、文件與規則，找出已知供應鏈風險、未揭露能力與版本權限漂移。

後續方向包含 OSV 依賴漏洞情報、資料流／污點分析、隔離沙箱動態分析、簽章與發布者來源驗證。

## 履歷描述

> Built a zero-key security supply-chain scanner for Agent Skills and MCP servers that inventories exposed tools, detects undeclared high-risk behavior, compares capability drift across Git refs, enforces policy-as-code, and emits SARIF for GitHub CI.
