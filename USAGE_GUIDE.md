# SBOM 掃描使用指南

## 🚀 快速開始

### 1. 測試配置
```bash
python test_config.py
```

### 2. 執行掃描

#### 方法 A: 互動式掃描 (推薦)
```bash
python quick_scan.py
```

#### 方法 B: 批次檔案
```bash
run_sbom_scan.bat
```

#### 方法 C: 命令行
此範例是待掃描目錄為 C:\projects\myproject
掃瞄時，會以第一個 “-” 前為 project 名稱， 後為版本名稱。如 apache-tomcat-9.0.80，apache為專案名稱，tomcat-9.0.80為版本名稱
```bash
python sbom_scan_pipeline.py --scan-path "C:\projects" --subdir "myproject"
```

## 📁 檔案說明

| 檔案 | 用途 |
|------|------|
| `sbom_scan_pipeline.py` | 主要掃描管道 |
| `quick_scan.py` | 互動式掃描工具 |
| `test_config.py` | 配置測試工具 |
| `run_sbom_scan.bat` | Windows 批次檔案 |
| `config.json` | 配置檔案 |

## ⚙️ 配置檔案

copy config.json.example 為 config.json
編輯 `config.json`：

```json
{
  "dependency_track": {
    "server_url": "http://localhost:8081",
    "api_key": "your_api_key"
  },
  "dependency_check": {
    "tool_path": "C:\\tools\\dependency-check\\bin",
    "nvd_api_key": "your_nvd_api_key"
  }
}
```

## 📊 輸出結果

掃描完成後，報告會保存在 `reports/` 目錄中：

- `dependency-check-report.html` - HTML 報告
- `dependency-check-report.json` - JSON 報告  
- `bom.json` - CycloneDX 格式 BOM
- `sbom_scan.log` - 執行日誌

## 🔧 故障排除

### 常見問題

1. **配置錯誤**
   ```bash
   python test_config.py
   ```

2. **查看日誌**
   ```bash
   cat sbom_scan.log
   ```

3. **檢查工具**
   ```bash
   C:\tools\dependency-check\bin\dependency-check.bat --version
   ```

## 📞 支援

- 查看 `README.md` 獲取詳細說明
- 檢查 `sbom_scan.log` 查看錯誤信息
- 確保所有工具已正確安裝和配置 