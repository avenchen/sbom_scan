# SBOM 掃描管道

這是一個完整的 SBOM (Software Bill of Materials) 掃描管道，用於自動化執行依賴項掃描、格式轉換和上傳到 Dependency-Track。

## 功能特色

- 🔍 **自動化掃描**: 使用 OWASP Dependency Check 進行依賴項漏洞掃描
- 🔄 **格式轉換**: 將 Dependency Check JSON 報告轉換為 CycloneDX 格式
- 📤 **自動上傳**: 將生成的 BOM 檔案上傳到 Dependency-Track
- 📝 **完整日誌**: 詳細的執行日誌和錯誤追蹤
- ⚙️ **配置管理**: 透過 JSON 檔案管理配置

## 系統需求

- Python 3.7+
- OWASP Dependency Check
- Dependency-Track 伺服器
- NVD API 金鑰

## 安裝步驟

### 1. 安裝 Python 依賴項

```bash
pip install requests
```

### 2. 下載 OWASP Dependency Check

從 [OWASP Dependency Check 官網](https://owasp.org/www-project-dependency-check/) 下載並解壓到指定目錄。

### 3. 取得 NVD API 金鑰

1. 前往 [NVD API 金鑰申請頁面](https://nvd.nist.gov/developers/request-an-api-key)
2. 填寫申請表單
3. 等待核准並取得 API 金鑰

### 4. 配置 Dependency-Track

執行 [Dependency-Track](https://dependencytrack.org)
確保您的 Dependency-Track 伺服器正在運行，並取得：
- 伺服器 URL
- API 金鑰
- 專案 UUID（可不指定）

## 配置檔案

編輯 `config.json` 檔案：

```json
{
  "dependency_track": {
    "server_url": "http://localhost:8081",
    "api_key": "your_api_key_here"
  },
  "dependency_check": {
    "tool_path": "C:\\tools\\dependency-check\\bin",
    "nvd_api_key": "NVD API KEY"
  },
  "bom": {
    "default_file": "bom.json"
  }
}
```

## 使用方法

### 方法 1: 快速掃描 (推薦新手)

#### 互動式掃描
```bash
python quick_scan.py
```
這個工具會引導您完成整個掃描過程，無需記住複雜的參數。

### 方法 2: 使用批次檔案

#### 基本使用 (使用配置檔案)
```bash
run_sbom_scan.bat
```

#### 簡化使用 (只需要指定掃描路徑)
此範例是待掃描目錄為 C:\projects\myproject
掃瞄時，會以第一個 “-” 前為 project 名稱， 後為版本名稱。如 apache-tomcat-9.0.80，apache為專案名稱，tomcat-9.0.80為版本名稱

```bash
python sbom_scan_pipeline.py --scan-path "C:\projects" --subdir "myproject"
```

#### 使用參數
```bash
run_sbom_scan.bat config.json "C:\tools\dependency-check\bin" "C:\projects" "myproject" "your_nvd_api_key"
```

### 方法 3: 直接使用 Python 腳本

```bash
python sbom_scan_pipeline.py \
    --config config.json \
    --tool-path "C:\tools\dependency-check\bin" \
    --scan-path "C:\projects\myproject" \
    --subdir "myproject" \
    --nvd-api-key "your_nvd_api_key" \
    --report-path "reports\custom_path"
```

### 方法 4: 配置測試

在開始掃描前，建議先測試配置是否正確：

```bash
python test_config.py
```

這個工具會檢查：
- Python 環境
- 配置檔案
- dependency-check 工具
- NVD API 金鑰
- Dependency-Track 連接

### 參數說明

| 參數 | 說明 | 必填 |
|------|------|------|
| `--config` | 配置檔案路徑 | 否 (預設: config.json) |
| `--tool-path` | dependency-check 工具路徑 | 否 (可從 config.json 讀取) |
| `--scan-path` | 要掃描的專案路徑 | 是 |
| `--subdir` | 專案子目錄名稱 | 是 |
| `--nvd-api-key` | NVD API 金鑰 | 否 (可從 config.json 讀取) |
| `--report-path` | 報告輸出路徑 | 否 |

## 執行流程

1. **載入配置**: 讀取 `config.json` 檔案
2. **執行掃描**: 使用 dependency-check 掃描指定路徑
3. **格式轉換**: 將 JSON 報告轉換為 CycloneDX 格式
4. **上傳 BOM**: 將生成的 BOM 檔案上傳到 Dependency-Track

## 輸出檔案

執行完成後，會在 `reports` 目錄中生成以下檔案：

```
reports/
├── {subdir}_{timestamp}/
│   ├── dependency-check-report.html    # HTML 報告
│   ├── dependency-check-report.json    # JSON 報告
│   └── bom.json                        # CycloneDX 格式 BOM
└── sbom_scan.log                       # 執行日誌
```

## 錯誤處理

### 常見錯誤及解決方案

1. **配置檔案不存在**
   - 確保 `config.json` 檔案存在且格式正確

2. **dependency-check 工具不存在**
   - 下載並安裝 OWASP Dependency Check
   - 確認工具路徑設定正確

3. **NVD API 金鑰無效**
   - 檢查 API 金鑰是否正確
   - 確認 API 金鑰是否已啟用

4. **Dependency-Track 連接失敗**
   - 檢查伺服器 URL 是否正確
   - 確認 API 金鑰和專案 UUID 是否有效
   - 檢查網路連接

### 日誌檔案

詳細的執行日誌會記錄在 `sbom_scan.log` 檔案中，包含：
- 執行步驟
- 錯誤訊息
- 成功狀態
- 時間戳記

## 範例腳本

### 批次檔案範例

```batch
@echo off
set TOOL_PATH=C:\tools\dependency-check\bin
set SCAN_PATH=C:\projects
set SUBDIR=myproject
set NVD_API_KEY=your_nvd_api_key_here

run_sbom_scan.bat config.json "%TOOL_PATH%" "%SCAN_PATH%" "%SUBDIR%" "%NVD_API_KEY%"
```

### PowerShell 範例

```powershell
$toolPath = "C:\tools\dependency-check\bin"
$scanPath = "C:\projects"
$subdir = "myproject"
$nvdApiKey = "your_nvd_api_key_here"
```

### Python 範例

```python
python sbom_scan_pipeline.py `
    --config config.json `
    --tool-path $toolPath `
    --scan-path $scanPath `
    --subdir $subdir `
    --nvd-api-key $nvdApiKey
```

## 進階配置

### 自定義掃描選項

您可以修改 `sbom_scan_pipeline.py` 中的 `run_dependency_check` 方法來添加更多 dependency-check 參數：

```python
cmd = [
    f"{tool_path}/dependency-check.bat",
    "--scan", scan_path,
    "--format", "HTML",
    "--format", "JSON", 
    "--project", subdir,
    "--out", report_path,
    "--nvdApiKey", api_key,
    "--enableExperimental",
    "--enableRetired",
    "--failOnCVSS", "7",  # 新增：CVSS 分數大於 7 時失敗
    "--suppression", "suppression.xml"  # 新增：抑制檔案
]
```

### 自定義上傳選項

您可以修改 `upload_to_dependency_track` 方法來添加更多上傳選項：

```python
data = {
    'project': project_uuid,
    'autoCreate': 'true',  # 自動創建專案
    'bomFormat': 'CycloneDX'  # 指定 BOM 格式
}
```

## 故障排除

### 檢查工具安裝

```bash
# 檢查 Python 版本
python --version

# 檢查 dependency-check
C:\tools\dependency-check\bin\dependency-check.bat --version

# 檢查網路連接
curl -I http://localhost:8081
```

### 測試配置

創建一個測試腳本來驗證配置：

```python
import json
import requests

# 測試配置檔案
with open('config.json', 'r') as f:
    config = json.load(f)
    print("配置檔案載入成功")

# 測試 Dependency-Track 連接
response = requests.get(f"{config['dependency_track']['server_url']}/api/v1/project")
print(f"Dependency-Track 連接狀態: {response.status_code}")
```

## 授權

本專案採用 MIT 授權條款。

## 支援

如有問題或建議，請：
1. 檢查日誌檔案 `sbom_scan.log`
2. 查看本 README 的故障排除章節
3. 提交 Issue 或 Pull Request 