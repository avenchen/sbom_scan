#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置測試腳本
驗證 SBOM 掃描管道的配置是否正確
"""

import json
import os
import sys
import requests
import subprocess
from pathlib import Path


class ConfigTester:
    """配置測試器"""
    
    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.config = None
        
    def load_config(self) -> bool:
        """載入配置檔案"""
        try:
            if not os.path.exists(self.config_file):
                print(f"❌ 配置檔案不存在: {self.config_file}")
                return False
                
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            print(f"✅ 配置檔案載入成功: {self.config_file}")
            return True
        except json.JSONDecodeError as e:
            print(f"❌ 配置檔案格式錯誤: {e}")
            return False
        except Exception as e:
            print(f"❌ 載入配置檔案時發生錯誤: {e}")
            return False
    
    def test_python(self) -> bool:
        """測試 Python 環境"""
        try:
            version = sys.version_info
            print(f"✅ Python 版本: {version.major}.{version.minor}.{version.micro}")
            
            # 檢查必要模組
            import requests
            print(f"✅ requests 模組可用 (版本: {requests.__version__})")
            
            return True
        except ImportError as e:
            print(f"❌ 缺少必要模組: {e}")
            print("請執行: pip install requests")
            return False
    
    def test_dependency_check(self) -> bool:
        """測試 dependency-check 工具"""
        if not self.config:
            return False
            
        dc_config = self.config.get("dependency_check", {})
        tool_path = dc_config.get("tool_path")
        
        if not tool_path:
            print("❌ dependency-check 工具路徑未設定")
            return False
        
        # 檢查工具路徑是否存在
        if not os.path.exists(tool_path):
            print(f"❌ dependency-check 工具路徑不存在: {tool_path}")
            return False
        
        # 檢查 dependency-check.bat 是否存在
        bat_file = os.path.join(tool_path, "dependency-check.bat")
        if not os.path.exists(bat_file):
            print(f"❌ dependency-check.bat 不存在: {bat_file}")
            return False
        
        # 測試執行 dependency-check
        try:
            result = subprocess.run(
                [bat_file, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                print(f"✅ dependency-check 可用: {version}")
                return True
            else:
                print(f"❌ dependency-check 執行失敗: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            print("❌ dependency-check 執行超時")
            return False
        except Exception as e:
            print(f"❌ 執行 dependency-check 時發生錯誤: {e}")
            return False
    
    def test_nvd_api_key(self) -> bool:
        """測試 NVD API 金鑰"""
        if not self.config:
            return False
            
        dc_config = self.config.get("dependency_check", {})
        api_key = dc_config.get("nvd_api_key")
        
        if not api_key:
            print("❌ NVD API 金鑰未設定")
            return False
        
        # 測試 API 金鑰
        try:
            headers = {"apiKey": api_key}
            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers=headers,
                params={"resultsPerPage": 1},
                timeout=10
            )
            
            if response.status_code == 200:
                print("✅ NVD API 金鑰有效")
                return True
            elif response.status_code == 403:
                print("❌ NVD API 金鑰無效或已過期")
                return False
            else:
                print(f"❌ NVD API 測試失敗: HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ 測試 NVD API 時發生錯誤: {e}")
            return False
    
    def test_dependency_track(self) -> bool:
        """測試 Dependency-Track 連接"""
        if not self.config:
            return False
            
        dt_config = self.config.get("dependency_track", {})
        server_url = dt_config.get("server_url")
        api_key = dt_config.get("api_key")
        
        if not server_url:
            print("❌ Dependency-Track 伺服器 URL 未設定")
            return False
        
        if not api_key:
            print("❌ Dependency-Track API 金鑰未設定")
            return False
        
        # 測試連接
        try:
            headers = {"X-API-Key": api_key}
            response = requests.get(
                f"{server_url}/api/version",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                version_info = response.json()
                version = version_info.get("version", "Unknown")
                print(f"✅ Dependency-Track 連接成功 (版本: {version})")
                return True
            else:
                print(f"❌ Dependency-Track 連接失敗: HTTP {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print(f"❌ 無法連接到 Dependency-Track: {server_url}")
            print("請檢查伺服器是否正在運行")
            return False
        except Exception as e:
            print(f"❌ 測試 Dependency-Track 時發生錯誤: {e}")
            return False
    
    def test_file_structure(self) -> bool:
        """測試檔案結構"""
        required_files = [
            "sbom_scan_pipeline.py",
            "convert_dc_to_cyclonedx.py",
            "requirements.txt"
        ]
        
        missing_files = []
        for file in required_files:
            if not os.path.exists(file):
                missing_files.append(file)
        
        if missing_files:
            print(f"❌ 缺少必要檔案: {', '.join(missing_files)}")
            return False
        
        print("✅ 所有必要檔案都存在")
        return True
    
    def run_all_tests(self) -> bool:
        """執行所有測試"""
        print("=" * 50)
        print("          配置測試開始")
        print("=" * 50)
        print()
        
        tests = [
            ("檔案結構", self.test_file_structure),
            ("配置檔案", self.load_config),
            ("Python 環境", self.test_python),
            ("dependency-check 工具", self.test_dependency_check),
            ("NVD API 金鑰", self.test_nvd_api_key),
            ("Dependency-Track 連接", self.test_dependency_track)
        ]
        
        results = []
        for test_name, test_func in tests:
            print(f"測試 {test_name}...")
            try:
                result = test_func()
                results.append((test_name, result))
            except Exception as e:
                print(f"❌ 測試 {test_name} 時發生錯誤: {e}")
                results.append((test_name, False))
            print()
        
        # 顯示測試結果摘要
        print("=" * 50)
        print("          測試結果摘要")
        print("=" * 50)
        
        passed = 0
        total = len(results)
        
        for test_name, result in results:
            status = "✅ 通過" if result else "❌ 失敗"
            print(f"{test_name}: {status}")
            if result:
                passed += 1
        
        print()
        print(f"總計: {passed}/{total} 項測試通過")
        
        if passed == total:
            print("🎉 所有測試通過！系統配置正確。")
            return True
        else:
            print("⚠️  部分測試失敗，請檢查配置。")
            return False


def main():
    """主函數"""
    config_file = "config.json"
    
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    
    tester = ConfigTester(config_file)
    success = tester.run_all_tests()
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main() 