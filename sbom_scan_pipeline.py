#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SBOM 掃描管道
執行完整的 SBOM 掃描、轉換和上傳流程
"""

import json
import os
import sys
import subprocess
import requests
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
import argparse


class SBOMScanPipeline:
    """SBOM 掃描管道類別"""
    
    def __init__(self, config_file: str = "config.json"):
        """初始化掃描管道"""
        self.config_file = config_file
        self.setup_logging()
        self.config = self.load_config()
        
    def setup_logging(self):
        """設定日誌記錄"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('sbom_scan.log', encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def parse_project_info(self, subdir: str) -> tuple[str, str]:
        """解析專案名稱和版本名稱"""
        if "-" in subdir:
            parts = subdir.split("-", 1)  # 只分割第一個 "-"
            project_name = parts[0]
            version_name = parts[1]
        else:
            # 如果沒有 "-"，使用預設值
            project_name = subdir
            version_name = "unknown"
        
        return project_name, version_name
    
    def load_config(self) -> Dict[str, Any]:
        """載入配置檔案"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            self.logger.info(f"成功載入配置檔案: {self.config_file}")
            return config
        except FileNotFoundError:
            self.logger.error(f"配置檔案不存在: {self.config_file}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"配置檔案格式錯誤: {e}")
            raise
            
    def run_dependency_check(self, tool_path: str, scan_path: str, 
                           report_path: str, subdir: str, api_key: str) -> bool:
        """執行 dependency-check 掃描"""
        try:
            # 確保報告目錄存在
            os.makedirs(report_path, exist_ok=True)
            
            # 構建掃描路徑
            full_scan_path = os.path.join(scan_path, subdir)
            self.logger.info(f" 全目錄: {full_scan_path}, 主目錄: {scan_path}, 專案目錄: {subdir}")
            
            # 構建命令
            cmd = [
                f"{tool_path}/dependency-check.bat",
                "--scan", full_scan_path,
                "--format", "HTML",
                "--format", "JSON", 
                "--project", subdir,
                "--out", report_path,
                "--nvdApiKey", api_key,
                "--enableExperimental",
                "--enableRetired"
            ]
            
            self.logger.info(f"執行 dependency-check 命令: {' '.join(cmd)}")
            
            # 執行命令
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace'  # 處理編碼錯誤
            )
            
            if result.returncode == 0:
                self.logger.info("dependency-check 掃描完成")
                if result.stdout:
                    self.logger.debug(f"標準輸出: {result.stdout}")
                return True
            else:
                self.logger.error(f"dependency-check 掃描失敗: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"執行 dependency-check 時發生錯誤: {e}")
            return False
            
    def convert_to_cyclonedx(self, input_file: str, output_file: str) -> bool:
        """將 dependency-check JSON 轉換為 CycloneDX 格式"""
        try:
            # 確保輸入檔案存在
            if not os.path.exists(input_file):
                self.logger.error(f"輸入檔案不存在: {input_file}")
                return False
                
            # 構建轉換命令
            cmd = [
                sys.executable,
                "convert_dc_to_cyclonedx.py",
                input_file,
                output_file
            ]
            
            self.logger.info(f"執行格式轉換命令: {' '.join(cmd)}")
            
            # 執行轉換
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace'  # 處理編碼錯誤
            )
            
            if result.returncode == 0:
                self.logger.info(f"成功轉換為 CycloneDX 格式: {output_file}")
                return True
            else:
                self.logger.error(f"格式轉換失敗: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"執行格式轉換時發生錯誤: {e}")
            return False
            
    def test_dt_connection(self, server_url: str, api_key: str) -> bool:
        """測試 Dependency-Track 連接"""
        try:
            headers = {"X-API-Key": api_key}
            response = requests.get(f"{server_url}/api/version", headers=headers, timeout=10)
            if response.status_code == 200:
                version_info = response.json()
                self.logger.info(f"成功連接到 Dependency-Track v{version_info.get('version', 'Unknown')}")
                return True
            else:
                self.logger.error(f"連接失敗: HTTP {response.status_code}")
                return False
        except Exception as e:
            self.logger.error(f"連接錯誤: {e}")
            return False
    
    def get_dt_projects(self, server_url: str, api_key: str) -> list:
        """獲取所有 Dependency-Track 專案"""
        try:
            headers = {"X-API-Key": api_key}
            response = requests.get(f"{server_url}/api/v1/project", headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"獲取專案失敗: HTTP {response.status_code}")
                return []
        except Exception as e:
            self.logger.error(f"獲取專案錯誤: {e}")
            return []
    
    def find_dt_project(self, server_url: str, api_key: str, name: str, version: str) -> Optional[str]:
        """查找現有 Dependency-Track 專案"""
        projects = self.get_dt_projects(server_url, api_key)
        for project in projects:
            if project.get('name') == name and project.get('version') == version:
                return project.get('uuid')
        return None
    
    def create_dt_project(self, server_url: str, api_key: str, name: str, version: str, description: str = "") -> Optional[str]:
        """創建新的 Dependency-Track 專案"""
        project_data = {
            "name": name,
            "version": version,
            "description": description,
            "tags": ["auto-created", "converted-from-dependency-check"]
        }
        
        try:
            headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
            response = requests.put(f"{server_url}/api/v1/project", json=project_data, headers=headers, timeout=30)
            if response.status_code in [200, 201]:
                project = response.json()
                self.logger.info(f"專案創建成功: {project.get('name')} v{project.get('version')}")
                self.logger.info(f"專案 UUID: {project.get('uuid')}")
                return project.get('uuid')
            else:
                self.logger.error(f"創建專案失敗: HTTP {response.status_code}")
                self.logger.error(f"回應: {response.text}")
                return None
        except Exception as e:
            self.logger.error(f"創建專案錯誤: {e}")
            return None
    
    def upload_to_dependency_track(self, server_url: str, api_key: str, 
                                 project_uuid: str, bom_file: str) -> bool:
        """上傳 BOM 到 Dependency-Track"""
        try:
            # 確保 BOM 檔案存在
            if not os.path.exists(bom_file):
                self.logger.error(f"BOM 檔案不存在: {bom_file}")
                return False
                
            # 構建上傳 URL
            upload_url = f"{server_url}/api/v1/bom"
            
            # 準備檔案和資料
            with open(bom_file, 'rb') as f:
                files = {
                    'bom': (os.path.basename(bom_file), f, 'application/json')
                }
                data = {
                    'project': project_uuid
                }
                headers = {
                    'X-API-Key': api_key
                }
                
                self.logger.info(f"上傳 BOM 到 Dependency-Track: {upload_url}")
                
                # 發送請求
                response = requests.post(
                    upload_url,
                    files=files,
                    data=data,
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    self.logger.info("成功上傳 BOM 到 Dependency-Track")
                    self.logger.debug(f"回應: {response.text}")
                    return True
                else:
                    self.logger.error(f"上傳失敗，狀態碼: {response.status_code}")
                    self.logger.error(f"回應內容: {response.text}")
                    return False
                    
        except requests.exceptions.RequestException as e:
            self.logger.error(f"上傳到 Dependency-Track 時發生網路錯誤: {e}")
            return False
        except Exception as e:
            self.logger.error(f"上傳到 Dependency-Track 時發生錯誤: {e}")
            return False
            
    def run_pipeline(self, tool_path: str = None, scan_path: str = None, subdir: str = None, 
                    nvd_api_key: str = None, report_path: str = None) -> bool:
        """執行完整的掃描管道"""
        try:
            self.logger.info("開始執行 SBOM 掃描管道")
            
            # 從配置檔案獲取預設值
            dc_config = self.config.get("dependency_check", {})
            if not tool_path:
                tool_path = dc_config.get("tool_path")
                if not tool_path:
                    self.logger.error("dependency-check 工具路徑未設定")
                    return False
            
            if not nvd_api_key:
                nvd_api_key = dc_config.get("nvd_api_key")
                if not nvd_api_key:
                    self.logger.error("NVD API 金鑰未設定")
                    return False
            
            # 檢查必要參數
            if not all([scan_path, subdir]):
                self.logger.error("缺少必要參數: scan_path, subdir")
                return False
            
            # 解析專案名稱和版本名稱
            project_name, version_name = self.parse_project_info(subdir)
            self.logger.info(f"解析結果 - 專案名稱: {project_name}, 版本名稱: {version_name}, , 掃瞄目錄: {subdir}")
            
            # 設定報告路徑
            if not report_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                report_path = f"reports/{project_name}_{version_name}_{timestamp}"
                
            # 確保報告目錄存在
            os.makedirs(report_path, exist_ok=True)
            
            # 步驟 1: 執行 dependency-check 掃描
            self.logger.info("步驟 1: 執行 dependency-check 掃描")
            if not self.run_dependency_check(tool_path, scan_path, report_path, 
                                           subdir, nvd_api_key):
                self.logger.error("dependency-check 掃描失敗，停止管道")
                return False
                
            # 步驟 2: 轉換為 CycloneDX 格式
            self.logger.info("步驟 2: 轉換為 CycloneDX 格式")
            dc_json_file = os.path.join(report_path, "dependency-check-report.json")
            bom_file = os.path.join(report_path, "bom.json")
            
            if not self.convert_to_cyclonedx(dc_json_file, bom_file):
                self.logger.error("格式轉換失敗，停止管道")
                return False
                
            # 步驟 3: 上傳到 Dependency-Track
            self.logger.info("步驟 3: 上傳到 Dependency-Track")
            dt_config = self.config.get("dependency_track", {})
            server_url = dt_config.get("server_url")
            api_key = dt_config.get("api_key")
            
            if not all([server_url, api_key]):
                self.logger.error("Dependency-Track 配置不完整")
                return False
            
            # 測試連接
            self.logger.info("測試 Dependency-Track 連接...")
            if not self.test_dt_connection(server_url, api_key):
                self.logger.error("無法連接到 Dependency-Track")
                return False
            
            # 查找或創建專案
            self.logger.info(f"查找專案: {project_name} v{version_name}")
            project_uuid = self.find_dt_project(server_url, api_key, project_name, version_name)
            
            if project_uuid:
                self.logger.info(f"找到現有專案: {project_name} v{version_name}")
            else:
                self.logger.info(f"創建新專案: {project_name} v{version_name}")
                project_uuid = self.create_dt_project(server_url, api_key, project_name, version_name)
                if not project_uuid:
                    self.logger.error("無法創建專案")
                    return False
            
            # 上傳 BOM
            self.logger.info(f"上傳到專案: {project_name}, 版本: {version_name}")
            if not self.upload_to_dependency_track(server_url, api_key, 
                                                 project_uuid, bom_file):
                self.logger.error("上傳到 Dependency-Track 失敗")
                return False
                
            self.logger.info("SBOM 掃描管道執行完成")
            return True
            
        except Exception as e:
            self.logger.error(f"執行管道時發生錯誤: {e}")
            return False


def main():
    """主函數"""
    parser = argparse.ArgumentParser(description="SBOM 掃描管道")
    parser.add_argument("--config", default="config.json", 
                       help="配置檔案路徑 (預設: config.json)")
    parser.add_argument("--tool-path",
                       help="dependency-check 工具路徑 (可從 config.json 讀取)")
    parser.add_argument("--scan-path", required=True,
                       help="要掃描的專案路徑")
    parser.add_argument("--subdir", required=True,
                       help="專案子目錄名稱")
    parser.add_argument("--nvd-api-key",
                       help="NVD API 金鑰 (可從 config.json 讀取)")
    parser.add_argument("--report-path",
                       help="報告輸出路徑 (可選)")
    
    args = parser.parse_args()
    
    try:
        # 創建掃描管道實例
        pipeline = SBOMScanPipeline(args.config)
        
        # 執行管道
        success = pipeline.run_pipeline(
            tool_path=args.tool_path,
            scan_path=args.scan_path,
            subdir=args.subdir,
            nvd_api_key=args.nvd_api_key,
            report_path=args.report_path
        )
        
        if success:
            print("✅ SBOM 掃描管道執行成功")
            sys.exit(0)
        else:
            print("❌ SBOM 掃描管道執行失敗")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ 執行時發生錯誤: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 