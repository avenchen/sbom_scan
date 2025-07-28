@echo off
chcp 65001 >nul
echo 開始執行 SBOM 掃描...
python sbom_scan_pipeline.py --scan-path "C:\\ai3" --subdir "gateway-windows-8.5.04.b1.12"
if errorlevel 1 (
    echo 掃描執行失敗
    pause
) else (
    echo 掃描執行成功
    pause
)