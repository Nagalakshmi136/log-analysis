from typing import List, Dict
def config() -> Dict[str, any]:
        """
        configuration for the LogAnalyzer.

        Returns:
        -------
        `Dict[str,any]`:
            configuration dictionary.
        """
        return {
            "patterns": {
                "ip": rb"\d+\.\d+\.\d+\.\d+",
                "endpoint": rb'"[A-Z]+ (/\w+)',
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
                "suspicious_activity": ["IP Address", "Failed Login Count"],
            },
        }