# LogAnalyzer

## Overview

**LogAnalyzer** is a Python-based tool for processing, analyzing, and reporting web server logs. This script efficiently handles large log files, extracts key insights, and generates structured reports. It is ideal for identifying patterns, analyzing endpoints, tracking IP requests, and detecting suspicious activities in log data.

---

## Features

- **Efficient Processing**: Uses memory mapping for parsing large log files with minimal memory overhead.
- **Modular Design**: Highly configurable patterns and thresholds for different log structures.
- **Insightful Reports**:
  - Requests per IP address.
  - Most frequently accessed endpoint.
  - Suspicious activity detection based on failed login attempts.
- **Output Options**:
  - Displays results in a well-structured format in the terminal.
  - Saves detailed results to a CSV file for further analysis.

---

## Prerequisites

- Python 3.7 or above
- Install required modules (if not already available):  
  ```bash
  pip install -r requirements.txt
  ```

---

## Installation

1. Clone the repository or download the script:
   ```bash
   git clone https://github.com/yourusername/log-analyzer.git
   cd log-analyzer
   ```

2. Set up the configuration:
   - Edit the `config.py` file to define patterns, thresholds, and CSV structure as per your log file's format.

---

## Configuration

The configurations are stored in `config.py`. Below is an example structure:

```python
def config():
    return {
        "patterns": {
            "ip": rb"\d+\.\d+\.\d+\.\d+",
            "endpoint": rb'"[A-Z]+\s+([^\s]+)',
            "status": rb'HTTP/\d\.\d" (\d{3})',
        },
        "suspicious_ip_threshold": 10,
        "failed_login_conditions": {
            "status_codes": ["401"],
            "keywords": [b"Invalid credentials"],
        },
        "data_counters": ["ip_requests", "endpoint_access", "failed_logins"],
        "csv_structure": {
            "requests_per_ip": ["IP Address", "Request Count"],
            "most_accessed_endpoint": ["Endpoint", "Access Count"],
            "suspicious_activity": ["IP Address", "Failed Login Attempts"],
        },
    }
```

### Key Parameters:
- **`patterns`**: Regex patterns to extract IP addresses, endpoints, and HTTP statuses.
- **`suspicious_ip_threshold`**: Minimum failed login attempts to flag suspicious IPs.
- **`failed_login_conditions`**: Conditions for detecting failed login attempts.

---

## Usage

1. Place your log file in the project directory (e.g., `sample.log`).
2. Run the script:
   ```bash
   python log_analyzer.py
   ```
3. View the results in the terminal and find the CSV report (`log_analysis_results.csv`) in the same directory.

---

## Output

### Terminal Report:
- **Requests per IP Address**: Lists all IP addresses with their corresponding request counts.
- **Most Frequently Accessed Endpoint**: Displays the endpoint with the highest access count.
- **Suspicious Activity Detected**: Identifies IPs exceeding the failed login threshold.

### CSV Report:
Each section of the analysis is saved in the following structure:
- `requests_per_ip`: IP addresses and their request counts.
- `most_accessed_endpoint`: Most accessed endpoint and its access count.
- `suspicious_activity`: IP addresses flagged for suspicious activity and their failed login counts.

---

## Example

### Sample Input Log (`sample.log`):
```
192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
192.168.1.2 - - [03/Dec/2024:10:15:01 +0000] "POST /login HTTP/1.1" 401 256
192.168.1.1 - - [03/Dec/2024:10:18:45 +0000] "GET /dashboard HTTP/1.1" 200 1024
```

### Sample Terminal Output:
```
Requests per IP Address:
-------------------------
IP Address          Request Count
192.168.1.1         2
192.168.1.2         1

Most Frequently Accessed Endpoint:
-----------------------------------
/home (Accessed 2 times)

Suspicious Activity Detected:
-----------------------------
IP Address          Failed Login Attempts
192.168.1.2         1
```

---

## Extensibility

- Add new patterns by modifying the `patterns` dictionary in `config.py`.
- Update thresholds or keywords to adjust the detection logic.

---

## Known Limitations

- Requires structured log data. Ensure logs adhere to a consistent format for regex matching.
- Performance may vary for extremely large files, depending on hardware.

---
