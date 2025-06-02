#!/usr/bin/env python3
"""
AI-Powered API Pentesting Tool
Uses Gemini LLM via LangChain to generate dynamic payloads and analyze responses
"""

import subprocess
import sys
import os
import json
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import time
from urllib.parse import urlparse, parse_qs
from dotenv import load_dotenv
# LangChain imports
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.schema import HumanMessage, SystemMessage
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain

load_dotenv()

GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')

@dataclass
class TestResult:
    """Data class to store test results"""
    test_name: str
    payload: str
    response_code: int
    response_body: str
    response_headers: str
    vulnerability_found: bool
    severity: str
    description: str

class APISecurityTester:
    """AI-powered API security testing tool"""
    
    def __init__(self, gemini_api_key: str, model_name: str = "gemini-2.0-flash") -> None:
        """Initialize the tester with Gemini API key"""
        self.llm = ChatGoogleGenerativeAI(
            model=model_name,
            google_api_key=gemini_api_key,
            temperature=0.1  # Lower temperature for more consistent security testing
        )
        self.test_results = []
        
    def analyze_curl_command(self, curl_command: str) -> Dict:
        """Use LLM to analyze curl command and extract key information"""
        analysis_prompt = """
        Analyze this curl command and extract the following information in JSON format:
        - URL and endpoint
        - HTTP method
        - Headers (especially authentication, content-type)
        - Request body/data
        - Parameters
        - Potential attack surfaces
        - Authentication mechanism used
        
        Curl command:
        {curl_command}
        
        Provide response in valid JSON format only.
        """
        
        response = self.llm.invoke([HumanMessage(content=analysis_prompt.format(curl_command=curl_command))])
        
        try:
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response.content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                return {"error": "Could not parse LLM response"}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON response from LLM"}

    def generate_security_payloads(self, curl_analysis: Dict, test_type: str) -> List[str]:
        """Generate dynamic security payloads based on curl analysis"""
        
        payload_prompt = """
        Based on this API analysis, generate {count} specific {test_type} payloads for testing:
        
        API Analysis:
        {analysis}
        
        Generate payloads that are:
        1. Relevant to the specific API endpoint and parameters
        2. Tailored to the authentication mechanism
        3. Appropriate for the data format (JSON, form-data, etc.)
        4. Realistic and likely to reveal vulnerabilities
        
        Return only the payloads, one per line, without explanation.
        For SQL injection, focus on the actual injection strings.
        For XSS, provide the XSS payloads.
        For authentication bypass, provide modified authentication headers/tokens.
        """
        
        test_counts = {
            "sql_injection": 8,
            "xss": 6,
            "authentication_bypass": 5,
            "parameter_pollution": 4,
            "directory_traversal": 5,
            "command_injection": 6,
            "xxe": 4,
            "csrf": 3
        }
        
        count = test_counts.get(test_type, 5)
        
        response = self.llm.invoke([HumanMessage(content=payload_prompt.format(
            analysis=json.dumps(curl_analysis, indent=2),
            test_type=test_type.replace('_', ' '),
            count=count
        ))])
        
        # Extract payloads from response
        payloads = [line.strip() for line in response.content.split('\n') if line.strip()]
        return payloads[:count]  # Limit to requested count

    def modify_curl_with_payload(self, original_curl: str, payload: str, test_type: str, curl_analysis: Dict) -> str:
        """Use LLM to intelligently modify curl command with payload"""
        
        modification_prompt = """
        Modify this curl command to include the security payload for {test_type} testing.
        
        Original curl command:
        {curl_command}
        
        Payload to inject:
        {payload}
        
        API Analysis:
        {analysis}
        
        Instructions:
        1. Inject the payload in the most appropriate location (URL parameters, POST data, headers)
        2. Maintain the original request structure
        3. Keep authentication headers intact
        4. For SQL injection: inject into data parameters or URL parameters
        5. For XSS: inject into user input fields
        6. For auth bypass: modify authentication headers/tokens
        7. Return only the modified curl command, nothing else
        
        Modified curl command:
        """
        
        response = self.llm.invoke([HumanMessage(content=modification_prompt.format(
            curl_command=original_curl,
            payload=payload,
            test_type=test_type.replace('_', ' '),
            analysis=json.dumps(curl_analysis, indent=2)
        ))])
        
        # Extract curl command from response
        curl_lines = response.content.strip().split('\n')
        for line in curl_lines:
            if 'curl' in line.lower():
                return line.strip()
        
        return response.content.strip()

    def execute_curl(self, curl_command: str) -> Tuple[str, str, int]:
        """Execute curl command and return response"""
        try:
            # Clean the command
            cleaned_command = self.clean_curl_command(curl_command)
            
            # Execute with timeout
            result = subprocess.run(
                cleaned_command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            return result.stdout, result.stderr, result.returncode
            
        except subprocess.TimeoutExpired:
            return "", "Request timeout", -1
        except Exception as e:
            return "", str(e), -1

    def analyze_response(self, payload: str, response_body: str, response_code: int, test_type: str) -> Dict:
        """Use LLM to analyze response for vulnerabilities"""
        
        analysis_prompt = """
        Analyze this API response for {test_type} vulnerability:
        
        Payload used: {payload}
        Response code: {response_code}
        Response body: {response_body}
        
        Determine:
        1. Is there a vulnerability? (yes/no)
        2. Severity level (low/medium/high/critical)
        3. Brief description of the finding
        4. Evidence from the response that indicates vulnerability
        
        Respond in JSON format:
        {{
            "vulnerable": true/false,
            "severity": "low/medium/high/critical",
            "description": "brief description",
            "evidence": "specific evidence from response"
        }}
        """
        
        # Truncate response body if too long
        truncated_response = response_body[:2000] + "..." if len(response_body) > 2000 else response_body
        
        response = self.llm.invoke([HumanMessage(content=analysis_prompt.format(
            test_type=test_type.replace('_', ' '),
            payload=payload,
            response_code=response_code,
            response_body=truncated_response
        ))])
        
        try:
            json_match = re.search(r'\{.*\}', response.content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                return {"vulnerable": False, "severity": "low", "description": "Could not analyze", "evidence": ""}
        except json.JSONDecodeError:
            return {"vulnerable": False, "severity": "low", "description": "Analysis failed", "evidence": ""}

    def clean_curl_command(self, curl_command: str) -> str:
        """Clean curl command for execution"""
        cleaned = curl_command.replace('\\\n', ' ').replace('\n', ' ')
        cleaned = ' '.join(cleaned.split())
        cleaned = re.sub(r"\$'([^']*)'", r'"\1"', cleaned)
        return cleaned

    def run_security_test(self, curl_command: str, test_type: str) -> List[TestResult]:
        """Run a specific type of security test"""
        print(f"\n🔍 Running {test_type.replace('_', ' ').title()} tests...")
        
        # Analyze the curl command
        curl_analysis = self.analyze_curl_command(curl_command)
        if "error" in curl_analysis:
            print(f"❌ Error analyzing curl command: {curl_analysis['error']}")
            return []
        
        # Generate payloads
        payloads = self.generate_security_payloads(curl_analysis, test_type)
        print(f"📝 Generated {len(payloads)} payloads")
        
        test_results = []
        
        for i, payload in enumerate(payloads, 1):
            print(f"   Testing payload {i}/{len(payloads)}...")
            
            # Modify curl command with payload
            modified_curl = self.modify_curl_with_payload(curl_command, payload, test_type, curl_analysis)
            
            # Execute the request
            stdout, stderr, status_code = self.execute_curl(modified_curl)
            
            # Analyze response for vulnerabilities
            vuln_analysis = self.analyze_response(payload, stdout, status_code, test_type)
            
            # Create test result
            result = TestResult(
                test_name=f"{test_type}_{i}",
                payload=payload,
                response_code=status_code,
                response_body=stdout[:500] + "..." if len(stdout) > 500 else stdout,
                response_headers="",
                vulnerability_found=vuln_analysis.get("vulnerable", False),
                severity=vuln_analysis.get("severity", "low"),
                description=vuln_analysis.get("description", "")
            )
            
            test_results.append(result)
            
            if result.vulnerability_found:
                print(f"   ⚠️  Potential vulnerability found! Severity: {result.severity}")
            
            # Small delay to avoid overwhelming the target
            time.sleep(0.5)
        
        return test_results

    def run_comprehensive_test(self, curl_command: str) -> Dict:
        """Run comprehensive security testing"""
        print("🚀 Starting AI-Powered API Security Testing")
        print("=" * 50)
        
        test_types = [
            "sql_injection",
            "xss", 
            "authentication_bypass",
            "parameter_pollution",
            "directory_traversal",
            "command_injection"
        ]
        
        all_results = {}
        vulnerabilities_found = 0
        
        for test_type in test_types:
            results = self.run_security_test(curl_command, test_type)
            all_results[test_type] = results
            
            # Count vulnerabilities
            vulns_in_test = sum(1 for r in results if r.vulnerability_found)
            vulnerabilities_found += vulns_in_test
            
            if vulns_in_test > 0:
                print(f"   ⚠️  Found {vulns_in_test} potential vulnerabilities")
            else:
                print(f"   ✅ No vulnerabilities detected")
        
        print(f"\n📊 Testing completed! Total potential vulnerabilities: {vulnerabilities_found}")
        return all_results

    def generate_report(self, test_results: Dict) -> str:
        """Generate a comprehensive security report"""
        report_prompt = """
        Generate a professional security testing report based on these test results:
        
        {results}
        
        Include:
        1. Executive Summary
        2. Vulnerability Summary (with counts by severity)
        3. Detailed Findings (for each vulnerability found)
        4. Recommendations
        5. Risk Assessment
        
        Format as a professional security report.
        """
        
        # Prepare results summary for LLM
        results_summary = {}
        for test_type, results in test_results.items():
            results_summary[test_type] = []
            for result in results:
                if result.vulnerability_found:
                    results_summary[test_type].append({
                        "payload": result.payload,
                        "severity": result.severity,
                        "description": result.description,
                        "response_code": result.response_code
                    })
        
        response = self.llm.invoke([HumanMessage(content=report_prompt.format(
            results=json.dumps(results_summary, indent=2)
        ))])
        
        return response.content

def main():
    """Main function"""
    print("AI-Powered API Pentesting Tool")
    print("=" * 40)
    
    # Check for Gemini API key
    gemini_api_key = os.getenv('GEMINI_API_KEY')
    if not gemini_api_key:
        print("❌ Please set GEMINI_API_KEY environment variable")
        sys.exit(1)
    
    # Initialize tester
    tester = APISecurityTester(gemini_api_key)
    
    # Read curl command
    curl_command = None
    
    if len(sys.argv) > 1:
        if sys.argv[1].endswith('.txt'):
            # Read from file
            try:
                with open(sys.argv[1], 'r') as f:
                    curl_command = f.read().strip()
                print(f"📖 Loaded curl command from {sys.argv[1]}")
            except FileNotFoundError:
                print(f"❌ File {sys.argv[1]} not found")
                sys.exit(1)
        else:
            # Use command line argument
            curl_command = " ".join(sys.argv[1:])
    else:
        # Check for curl.txt file
        if os.path.exists("curl.txt"):
            with open("curl.txt", 'r') as f:
                curl_command = f.read().strip()
            print("📖 Loaded curl command from curl.txt")
        else:
            print("❌ No curl command provided. Usage:")
            print("   python script.py 'curl command'")
            print("   python script.py curl_file.txt")
            print("   or create a curl.txt file")
            sys.exit(1)
    
    if not curl_command or not curl_command.strip().startswith('curl'):
        print("❌ Invalid curl command")
        sys.exit(1)
    
    # Run comprehensive testing
    results = tester.run_comprehensive_test(curl_command)
    
    # Generate and save report
    print("\n📄 Generating security report...")
    report = tester.generate_report(results)
    
    # Save report to file
    timestamp = int(time.time())
    report_file = f"security_report_{timestamp}.txt"
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"📄 Report saved to: {report_file}")
    print("\n" + "=" * 50)
    print("SECURITY REPORT PREVIEW:")
    print("=" * 50)
    print(report[:1000] + "..." if len(report) > 1000 else report)

if __name__ == "__main__":
    main()