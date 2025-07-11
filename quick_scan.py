#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速掃描腳本
提供互動式介面來執行 SBOM 掃描
"""

import os
import sys
import json
import subprocess
from pathlib import Path


class QuickScanner:
    """快速掃描器"""
    
    def __init__(self):
        self.config_file = "config.json"
        self.config = None
        
    def load_config(self):
        """載入配置檔案"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                return True
            return False
        except:
            return False
    
    def get_input(self, prompt: str, default: str = "") -> str:
        """獲取用戶輸入"""
        if default:
            user_input = input(f"{prompt} (預設: {default}): ").strip()
            return user_input if user_input else default
        else:
            return input(f"{prompt}: ").strip()
    
    def select_scan_path(self) -> str:
        """選擇掃描路徑"""
        print("\n=== 選擇掃描路徑 ===")
        
        # 嘗試從配置檔案獲取預設路徑
        default_path = ""
        if self.config and "default_scan_path" in self.config:
            default_path = self.config["default_scan_path"]
        
        while True:
            scan_path = self.get_input("請輸入要掃描的專案路徑", default_path)
            
            if not scan_path:
                print("❌ 掃描路徑不能為空")
                continue
            
            if not os.path.exists(scan_path):
                print(f"❌ 路徑不存在: {scan_path}")
                continue
            
            return scan_path
    
    def select_subdir(self, scan_path: str) -> str:
        """選擇子目錄"""
        print(f"\n=== 選擇子目錄 (從 {scan_path}) ===")
        
        # 列出子目錄
        try:
            subdirs = [d for d in os.listdir(scan_path) 
                      if os.path.isdir(os.path.join(scan_path, d))]
            
            if not subdirs:
                print("❌ 沒有找到子目錄")
                return self.get_input("請手動輸入子目錄名稱")
            
            print("可用的子目錄:")
            for i, subdir in enumerate(subdirs, 1):
                print(f"  {i}. {subdir}")
            
            while True:
                choice = self.get_input(f"請選擇子目錄 (1-{len(subdirs)}) 或輸入自定義名稱")
                
                try:
                    index = int(choice) - 1
                    if 0 <= index < len(subdirs):
                        return subdirs[index]
                except ValueError:
                    # 不是數字，當作自定義名稱
                    if choice:
                        return choice
                
                print("❌ 無效選擇，請重試")
                
        except Exception as e:
            print(f"❌ 讀取目錄時發生錯誤: {e}")
            return self.get_input("請手動輸入子目錄名稱")
    
    def confirm_scan(self, scan_path: str, subdir: str) -> bool:
        """確認掃描參數"""
        print("\n=== 掃描參數確認 ===")
        print(f"掃描路徑: {scan_path}")
        print(f"子目錄: {subdir}")
        print(f"完整路徑: {os.path.join(scan_path, subdir)}")
        
        # 解析專案名稱和版本
        if "-" in subdir:
            parts = subdir.split("-", 1)
            project_name = parts[0]
            version_name = parts[1]
        else:
            project_name = subdir
            version_name = "unknown"
        
        print(f"專案名稱: {project_name}")
        print(f"版本名稱: {version_name}")
        
        confirm = self.get_input("\n確認開始掃描？(y/N)").lower()
        return confirm in ['y', 'yes', '是']
    
    def run_scan(self, scan_path: str, subdir: str) -> bool:
        """執行掃描"""
        print("\n=== 開始執行掃描 ===")
        
        # 構建命令
        cmd = [
            sys.executable,
            "sbom_scan_pipeline.py",
            "--scan-path", scan_path,
            "--subdir", subdir
        ]
        
        # 添加配置檔案
        if os.path.exists(self.config_file):
            cmd.extend(["--config", self.config_file])
        
        print(f"執行命令: {' '.join(cmd)}")
        print()
        
        try:
            # 執行掃描
            result = subprocess.run(cmd, check=True)
            return result.returncode == 0
        except subprocess.CalledProcessError as e:
            print(f"❌ 掃描執行失敗: {e}")
            return False
        except KeyboardInterrupt:
            print("\n❌ 掃描被用戶中斷")
            return False
        except Exception as e:
            print(f"❌ 執行掃描時發生錯誤: {e}")
            return False
    
    def show_help(self):
        """顯示幫助信息"""
        print("""
=== SBOM 快速掃描工具 ===

這個工具可以幫助您快速執行 SBOM 掃描，無需記住複雜的命令行參數。

使用步驟:
1. 選擇要掃描的專案路徑
2. 選擇專案子目錄
3. 確認掃描參數
4. 等待掃描完成

注意事項:
- 確保已正確配置 config.json 檔案
- 確保 dependency-check 工具已安裝
- 確保 Dependency-Track 伺服器正在運行

如需詳細配置，請參考 README.md 檔案。
""")
    
    def run(self):
        """執行快速掃描"""
        print("🚀 SBOM 快速掃描工具")
        print("=" * 40)
        
        # 載入配置
        if self.load_config():
            print("✅ 配置檔案載入成功")
        else:
            print("⚠️  配置檔案載入失敗，將使用預設值")
        
        try:
            # 獲取掃描參數
            scan_path = self.select_scan_path()
            subdir = self.select_subdir(scan_path)
            
            # 確認掃描
            if not self.confirm_scan(scan_path, subdir):
                print("❌ 掃描已取消")
                return
            
            # 執行掃描
            if self.run_scan(scan_path, subdir):
                print("\n🎉 掃描完成！")
                print("報告已生成在 reports 目錄中")
            else:
                print("\n❌ 掃描失敗")
                print("請檢查日誌檔案 sbom_scan.log 以獲取詳細錯誤信息")
                
        except KeyboardInterrupt:
            print("\n❌ 操作被用戶中斷")
        except Exception as e:
            print(f"\n❌ 發生錯誤: {e}")


def main():
    """主函數"""
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', 'help']:
        QuickScanner().show_help()
        return
    
    scanner = QuickScanner()
    scanner.run()


if __name__ == "__main__":
    main() 