A specialized web fuzzing tool for discovering unknown endpoints and parameter vulnerabilities. This tool is designed for security professionals and penetration testers to conduct thorough web application security assessments.

## Features

- **Endpoint Discovery**
  - Multi-threaded scanning
  - Support for custom wordlists
  - Multiple HTTP method testing (GET, POST, PUT, DELETE, OPTIONS)
  - Rate limiting to avoid detection

- **Vulnerability Detection**
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Local File Inclusion (LFI)
  - Remote Code Execution (RCE)
  - Server-Side Request Forgery (SSRF)
  - Intelligent response analysis
  - Confidence scoring for vulnerabilities

- **Security Features**
  - WAF (Web Application Firewall) detection
  - Custom User-Agent and headers
  - SSL verification options
  - Error handling and timeout management
  - Rate limiting

- **Advanced Reporting**
  - Detailed HTML reports
  - Logging with timestamps
  - Vulnerability confidence scoring
  - Response analysis details
  - Clean and organized output

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/web-fuzzer.git
cd web-fuzzer
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python WebFuzzer.py -t https://target-website.com -w fuzzing_wordlist.txt
```

Advanced usage with options:
```bash
python WebFuzzer.py -t https://target-website.com -w fuzzing_wordlist.txt -r 0.2 --threads 3 -o custom_results
```

### Command Line Arguments

- `-t, --target`: Target URL to fuzz (required)
- `-w, --wordlist`: Path to wordlist file (optional, default wordlist provided)
- `-r, --rate-limit`: Delay between requests in seconds (default: 0.1)
- `--threads`: Number of concurrent threads (default: 5)
- `-o, --output-dir`: Directory to store results (default: fuzzing_results)

## Output

The tool generates:
1. HTML report with detailed findings
2. Log file with timestamps
3. List of discovered endpoints
4. Potential vulnerabilities with confidence scores

Results are saved in the 'fuzzing_results' directory (or custom directory if specified).

## Wordlist

A comprehensive wordlist (`fuzzing_wordlist.txt`) is included, containing:
- Common web endpoints
- API endpoints
- Authentication paths
- Framework-specific paths
- Database-related endpoints
- Security-related files
- And more...

## Warning

This tool should only be used for authorized security testing. Unauthorized testing of web applications may be illegal and unethical. Always ensure you have explicit permission to test any target system.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.