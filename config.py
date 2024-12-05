from typing import Dict, Any


def config() -> Dict[str, Any]:
    """
    Configuration for the LogAnalyzer.

    Returns:
    -------
    Dict[str, Any]:
        Configuration dictionary containing patterns, thresholds, conditions, counters, and CSV structure.
    """
    return {
        # Regular expression patterns for log analysis
        "patterns": {
            "ip": rb"\d+\.\d+\.\d+\.\d+",  
            "endpoint": rb'"[A-Z]+ (/\w+)', 
            "status": rb'HTTP/\d\.\d" (\d{3})',  
        },
        # Threshold for marking an IP as suspicious
        "suspicious_ip_threshold": 10,
        # Conditions to identify failed login attempts
        "failed_login_conditions": {
            "status_codes": ["401"],  
            "keywords": [b"Invalid credentials"],  
        },
        # Data counters for various metrics
        "data_counters": ["ip_requests", "endpoint_access", "failed_logins"],
        # Structure of the CSV output
        "csv_structure": {
            "requests_per_ip": [
                "IP Address",
                "Request Count",
            ],  # CSV columns for requests per IP
            "most_accessed_endpoint": [
                "Endpoint",
                "Access Count",
            ],  # CSV columns for most accessed endpoints
            "suspicious_activity": [
                "IP Address",
                "Failed Login Count",
            ],  # CSV columns for suspicious activity
        },
    }
