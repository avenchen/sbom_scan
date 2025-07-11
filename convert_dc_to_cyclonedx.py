#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dependency Check 到 CycloneDX 轉換器
將 OWASP Dependency Check JSON 報告轉換為 CycloneDX 格式
"""

import json
import uuid
import sys
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional


class DependencyCheckToCycloneDX:
    """Dependency Check 到 CycloneDX 轉換器"""
    
    def __init__(self):
        self.component_counter = 0
        
    def generate_bom_ref(self) -> str:
        """生成唯一的 BOM 參考 ID"""
        return str(uuid.uuid4())
    
    def convert_severity(self, severity: str) -> str:
        """轉換嚴重性等級"""
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high", 
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info"
        }
        return severity_map.get(severity.upper(), "unknown")
    
    def extract_cpe(self, vulnerability_ids: List[Dict]) -> Optional[str]:
        """從漏洞 ID 中提取 CPE"""
        for vuln_id in vulnerability_ids:
            if vuln_id.get("id", "").startswith("cpe:"):
                return vuln_id["id"]
        return None
    
    def extract_purl(self, packages: List[Dict]) -> Optional[str]:
        """從套件中提取 PURL"""
        for package in packages:
            if package.get("id", "").startswith("pkg:"):
                return package["id"]
        return None
    
    def convert_vulnerability(self, vuln: Dict) -> Dict:
        """轉換單個漏洞"""
        ratings = []
        if "cvssv3" in vuln:
            cvss = vuln["cvssv3"]
            ratings.append({
                "method": "CVSSv3",
                "score": cvss.get("baseScore"),
                "severity": self.convert_severity(cvss.get("baseSeverity", "UNKNOWN")),
                "vector": f"CVSS:3.1/{cvss.get('attackVector', 'N')}/{cvss.get('attackComplexity', 'L')}/{cvss.get('privilegesRequired', 'N')}/{cvss.get('userInteraction', 'N')}/{cvss.get('scope', 'U')}/{cvss.get('confidentialityImpact', 'N')}/{cvss.get('integrityImpact', 'N')}/{cvss.get('availabilityImpact', 'N')}"
            })
        
        references = []
        if "references" in vuln:
            for i, ref in enumerate(vuln["references"]):
                references.append({
                    "id": f"ref-{i+1}",
                    "source": {
                        "name": "external",
                        "url": ref.get("url", "")
                    }
                })
        
        cwes = []
        if "cwes" in vuln:
            for cwe in vuln["cwes"]:
                # 提取 CWE 編號（例如從 "CWE-44" 提取 44）
                if cwe.startswith("CWE-"):
                    cwe_number = cwe.replace("CWE-", "")
                    try:
                        cwes.append(int(cwe_number))
                    except ValueError:
                        # 如果不是數字，跳過
                        continue
                else:
                    try:
                        cwes.append(int(cwe))
                    except ValueError:
                        # 如果不是數字，跳過
                        continue
        
        return {
            "id": vuln.get("name", ""),
            "source": {
                "name": vuln.get("source", "unknown"),
                "url": ""
            },
            "ratings": ratings,
            "description": vuln.get("description", ""),
            "references": references,
            "cwes": cwes
        }
    
    def convert_component(self, dependency: Dict) -> Dict:
        """轉換單個依賴項為 CycloneDX 組件"""
        self.component_counter += 1
        
        # 提取基本信息
        name = dependency.get("fileName", "Unknown")
        version = "UNKNOWN"
        
        # 嘗試從套件中獲取版本
        if "packages" in dependency and dependency["packages"]:
            for package in dependency["packages"]:
                package_id = package.get("id", "")
                if "@" in package_id:
                    version = package_id.split("@")[-1]
                    break
        
        # 如果沒有找到版本，嘗試從檔案名中提取
        if version == "UNKNOWN" and "fileName" in dependency:
            filename = dependency["fileName"]
            if "-" in filename and filename.endswith(".jar"):
                parts = filename.replace(".jar", "").split("-")
                if len(parts) > 1:
                    version = parts[-1]
        
        # 確定組件類型
        component_type = "library"
        if name.endswith((".exe", ".dll")):
            component_type = "application"
        elif name.endswith((".jar", ".war", ".ear")):
            component_type = "library"
        else:
            component_type = "file"
        
        # 構建組件
        component = {
            "type": component_type,
            "bom-ref": self.generate_bom_ref(),
            "name": name,
            "version": version,
            "description": dependency.get("description", ""),
            "hashes": []
        }
        
        # 添加雜湊值
        if "md5" in dependency:
            component["hashes"].append({
                "alg": "MD5",
                "content": dependency["md5"]
            })
        if "sha1" in dependency:
            component["hashes"].append({
                "alg": "SHA-1", 
                "content": dependency["sha1"]
            })
        if "sha256" in dependency:
            component["hashes"].append({
                "alg": "SHA-256",
                "content": dependency["sha256"]
            })
        
        # 添加 CPE
        if "vulnerabilityIds" in dependency:
            cpe = self.extract_cpe(dependency["vulnerabilityIds"])
            if cpe:
                component["cpe"] = cpe
        
        # 添加 PURL
        if "packages" in dependency:
            purl = self.extract_purl(dependency["packages"])
            if purl:
                component["purl"] = purl
        
        # 添加許可證
        if "license" in dependency:
            component["licenses"] = [{
                "license": {
                    "name": dependency["license"]
                }
            }]
        
        # 添加屬性
        properties = []
        if "filePath" in dependency:
            properties.append({
                "name": "dependency-check:filePath",
                "value": dependency["filePath"]
            })
        
        if properties:
            component["properties"] = properties
        
        return component
    
    def convert_vulnerabilities(self, dependencies: List[Dict]) -> List[Dict]:
        """轉換所有漏洞"""
        vulnerabilities = {}  # 使用字典來去重，以漏洞 ID 為鍵
        
        for dependency in dependencies:
            if "vulnerabilities" in dependency:
                for vuln in dependency["vulnerabilities"]:
                    vuln_id = vuln.get("name", "")
                    if not vuln_id:
                        continue
                    
                    if vuln_id not in vulnerabilities:
                        # 新的漏洞，創建完整記錄
                        converted_vuln = self.convert_vulnerability(vuln)
                        converted_vuln["affects"] = [{
                            "ref": dependency.get("fileName", "unknown")
                        }]
                        vulnerabilities[vuln_id] = converted_vuln
                    else:
                        # 已存在的漏洞，只添加受影響的組件（避免重複）
                        existing_vuln = vulnerabilities[vuln_id]
                        new_ref = dependency.get("fileName", "unknown")
                        
                        # 檢查是否已經存在相同的 ref
                        ref_exists = any(affect.get("ref") == new_ref for affect in existing_vuln["affects"])
                        if not ref_exists:
                            existing_vuln["affects"].append({
                                "ref": new_ref
                            })
        
        return list(vulnerabilities.values())
    
    def convert(self, dc_report: Dict) -> Dict:
        """轉換整個 Dependency Check 報告"""
        dependencies = dc_report.get("dependencies", [])
        
        # 生成 CycloneDX BOM
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "OWASP",
                        "name": "Dependency-Check",
                        "version": "12.1.3"
                    }
                ],
                "component": {
                    "type": "application",
                    "bom-ref": self.generate_bom_ref(),
                    "name": "Converted Application",
                    "version": "1.0.0"
                }
            },
            "components": [],
            "vulnerabilities": []
        }
        
        # 轉換組件
        for dependency in dependencies:
            if not dependency.get("isVirtual", False):  # 跳過虛擬依賴
                component = self.convert_component(dependency)
                bom["components"].append(component)
        
        # 轉換漏洞
        bom["vulnerabilities"] = self.convert_vulnerabilities(dependencies)
        
        return bom
    
    def convert_file(self, input_file: str, output_file: str) -> None:
        """轉換檔案"""
        try:
            print(f"正在讀取 {input_file}...")
            with open(input_file, 'r', encoding='utf-8', errors='replace') as f:
                dc_report = json.load(f)
            
            print("正在轉換...")
            bom = self.convert(dc_report)
            
            print(f"正在寫入 {output_file}...")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(bom, f, indent=2, ensure_ascii=False)
            
            print(f"轉換完成！")
            print(f"組件數量: {len(bom['components'])}")
            print(f"漏洞數量: {len(bom['vulnerabilities'])}")
            
        except FileNotFoundError:
            print(f"錯誤：找不到檔案 {input_file}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"錯誤：JSON 解析失敗 - {e}")
            sys.exit(1)
        except Exception as e:
            print(f"錯誤：{e}")
            sys.exit(1)


def main():
    """主函數"""
    if len(sys.argv) != 3:
        print("使用方法: python convert_dc_to_cyclonedx.py <input_file> <output_file>")
        print("範例: python convert_dc_to_cyclonedx.py dependency-check-report.json bom-converted.json")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    converter = DependencyCheckToCycloneDX()
    converter.convert_file(input_file, output_file)


if __name__ == "__main__":
    main() 