@echo off
setlocal enabledelayedexpansion

REM SBOM 掃描批次檔案
REM 使用方法: run_sbom_scan.bat [config_file] [tool_path] [scan_path] [subdir] [nvd_api_key]

echo ========================================
echo           SBOM 掃描管道
echo ========================================
echo.

REM 設定預設值
set CONFIG_FILE=%~1
if "%CONFIG_FILE%"=="" set CONFIG_FILE=config.json

set TOOL_PATH=%~2
set SCAN_PATH=%~3
set SUBDIR=%~4
set NVD_API_KEY=%~5

REM 檢查必要參數
if "%SCAN_PATH%"=="" (
    echo 錯誤：缺少掃描路徑參數
    echo 使用方法: run_sbom_scan.bat [config_file] [tool_path] [scan_path] [subdir] [nvd_api_key]
    echo.
    echo 範例: run_sbom_scan.bat config.json "C:\tools\dependency-check\bin" "C:\projects\myproject" "myproject"
    exit /b 1
)

if "%SUBDIR%"=="" (
    echo 錯誤：缺少子目錄參數
    echo 使用方法: run_sbom_scan.bat [config_file] [tool_path] [scan_path] [subdir] [nvd_api_key]
    exit /b 1
)

echo 配置檔案: %CONFIG_FILE%
echo 掃描路徑: %SCAN_PATH%
echo 子目錄: %SUBDIR%
if not "%TOOL_PATH%"=="" echo 工具路徑: %TOOL_PATH%
if not "%NVD_API_KEY%"=="" echo NVD API 金鑰: %NVD_API_KEY%
echo.

REM 檢查 Python 是否可用
python --version >nul 2>&1
if errorlevel 1 (
    echo 錯誤：找不到 Python，請確保 Python 已安裝並在 PATH 中
    exit /b 1
)

REM 檢查配置檔案是否存在
if not exist "%CONFIG_FILE%" (
    echo 錯誤：配置檔案不存在: %CONFIG_FILE%
    exit /b 1
)

REM 檢查掃描路徑是否存在
if not exist "%SCAN_PATH%" (
    echo 錯誤：掃描路徑不存在: %SCAN_PATH%
    exit /b 1
)

echo 開始執行 SBOM 掃描...
echo.

REM 構建 Python 命令
set PYTHON_CMD=python sbom_scan_pipeline.py --config "%CONFIG_FILE%" --scan-path "%SCAN_PATH%" --subdir "%SUBDIR%"

if not "%TOOL_PATH%"=="" set PYTHON_CMD=%PYTHON_CMD% --tool-path "%TOOL_PATH%"
if not "%NVD_API_KEY%"=="" set PYTHON_CMD=%PYTHON_CMD% --nvd-api-key "%NVD_API_KEY%"

echo 執行命令: %PYTHON_CMD%
echo.

REM 執行 Python 腳本
%PYTHON_CMD%

REM 檢查執行結果
if errorlevel 1 (
    echo.
    echo ❌ SBOM 掃描執行失敗
    echo 請檢查日誌檔案 sbom_scan.log 以獲取詳細錯誤信息
    exit /b 1
) else (
    echo.
    echo ✅ SBOM 掃描執行成功
    echo 報告已生成在 reports 目錄中
)

echo.
echo 掃描完成！
pause 