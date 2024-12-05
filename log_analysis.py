import csv
import mmap
import re
import logging
from collections import Counter
from typing import Dict, List, Generator, Optional

from config import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class LogAnalyzer:
    """LogAnalyzer is a tool for processing, analyzing, and reporting log data.

    This class provides the ability to:
    - Parse large log files efficiently using memory mapping.
    - Extract meaningful information such as request counts, endpoint usage, and suspicious activity.
    - Generate structured reports in both console and CSV formats.
    """

    def __init__(self, log_file_path: str, output_file_path: str = "log_analysis_results.csv"):
        """
        Initialize the LogAnalyzer with paths and configurations.

        Parameters:
        ----------
        log_file_path : `str`
            Path to the log file.
        output_file_path : `str`, optional
            Path to save the analysis results (default: "log_analysis_results.csv").
        """
        self.log_file_path = log_file_path
        self.output_file_path = output_file_path
        self.config = config()

        # Data counters
        self.data_counters = {key: Counter() for key in self.config["data_counters"]}

        # Patterns
        self.patterns = {key: re.compile(pattern) for key, pattern in self.config["patterns"].items()}

    def extract_match(self, pattern_key: str, line: bytes, group_index: int = 0) -> Optional[str]:
        """
        Extract the first match for a given pattern in the provided log line.

        Parameters:
        ----------
        pattern_key : `str`
            Key of the pattern to use for extraction.
        line : `bytes`
            A single log entry.
        group_index : `int`, optional
            Index of the capturing group to extract (default: 0).

        Returns:
        -------
        `Optional[str]`:
            Extracted match as a string, or None if no match is found.

        Raises:
        ------
        `KeyError`:
            If the pattern key is not found in the registered patterns.
        """
        pattern = self.patterns.get(pattern_key)
        if pattern is None:
            raise KeyError(f"Pattern '{pattern_key}' not found in the configured patterns.")

        match = pattern.search(line)
        if match:
            try:
                return match.group(group_index).decode("utf-8")
            except IndexError:
                logging.warning(f"Group index {group_index} out of range for pattern '{pattern_key}'.")
        return None

    def process_log_line(self, line: bytes) -> None:
        """
        Process a single line from the log file using registered patterns.

        Parameters:
        ----------
        line : `bytes`
            A single log entry.
        """
        # Extract relevant data from the log line
        ip = self.extract_match("ip", line)
        endpoint = self.extract_match("endpoint", line, 1)
        status = self.extract_match("status", line)

        # Update counters based on extracted data
        if ip:
            self.data_counters["ip_requests"][ip] += 1
            if status and self.is_failed_login(status, line):
                self.data_counters["failed_logins"][ip] += 1
        if endpoint:
            self.data_counters["endpoint_access"][endpoint] += 1

    def is_failed_login(self, status: str, line: bytes) -> bool:
        """
        Check if the line indicates a failed login attempt.

        Parameters:
        ----------
        status : `str`
            HTTP status code from the log line.
        line : `bytes`
            The log entry.

        Returns:
        -------
        `bool`:
            True if the line indicates a failed login attempt, False otherwise.
        """
        conditions = self.config["failed_login_conditions"]
        return (status in conditions["status_codes"]) or any(
            keyword in line for keyword in conditions["keywords"]
        )
    def parse_log_file(self) -> Generator[bytes, None, None]:
        """
        Efficiently parse the log file using memory mapping.

        Yields:
        -------
        `Generator[bytes, None, None]`:
            A generator that yields each line of the log file as bytes.
        """
        try:
            with open(self.log_file_path, "rb") as file:
                with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                    for line in iter(mmapped_file.readline, b""):
                        yield line
        except (OSError, IOError) as e:
            logging.error(f"Error while parsing log file: {e}")

    def generate_report(self) -> Dict[str, List]:
        """
        Generate a structured report of the log analysis.

        Returns:
        -------
        `Dict[str, List]`:
            A dictionary containing sections of the report.
        """
        threshold = self.config["suspicious_ip_threshold"]
        return {
            "requests_per_ip": self.data_counters["ip_requests"].most_common(),
            "most_accessed_endpoint": self.data_counters["endpoint_access"].most_common(
                1
            ),
            "suspicious_activity": [
                (ip, count)
                for ip, count in self.data_counters["failed_logins"].items()
                if count > threshold
            ],
        }

    def display_report(self, report: Dict[str, any]) -> None:
        """
        Display the results report in the terminal in a clear format

        Parameters:
        ----------
            report: `Dict[str, any]`
                A dictionary containing sections of the report.
        """
        print("\nRequests per IP Address:")
        print("-" * 25)
        print(f"{'IP Address':<20}{'Request Count':<15}")
        for ip, count in report["requests_per_ip"]:
            print(f"{ip:<20}{count:<15}")

        print("\nMost Frequently Accessed Endpoint:")
        print("-" * 35)
        endpoint, count = report["most_accessed_endpoint"][0]
        print(f"{endpoint} (Accessed {count} times)")

        print("\nSuspicious Activity Detected:")
        print("-" * 30)
        print(f"{'IP Address':<20}{'Failed Login Attempts':<25}")
        for ip, count in report["suspicious_activity"]:
            print(f"{ip:<20}{count:<25}")

    def save_to_csv(self, report: Dict[str, List]) -> None:
        """
        Save the analysis report to a CSV file.

        Parameters:
        ----------
        report : `Dict[str, List]`
            Analysis report structured as a dictionary.
        """
        try:
            with open(self.output_file_path, "w", newline="", encoding="utf-8") as csv_file:
                writer = csv.writer(csv_file)
                for section, data in report.items():
                    # Write section title
                    writer.writerow([section.replace("_", " ").title()])
                    # Write headers based on the section
                    headers = self.config["csv_structure"].get(section, [])
                    if headers:
                        writer.writerow(headers)
                    # Write data rows
                    writer.writerows(data)
                    # Add a blank line between sections for readability
                    writer.writerow([])
        except IOError as e:
            logging.error(f"Error while saving results to CSV: {e}")

    def run(self) -> None:
        """
        Perform the log analysis by parsing the log file, processing each line,
        generating a report, displaying the report, and saving it to a CSV file.
        """
        # Parse and process log file
        for line in self.parse_log_file():
            self.process_log_line(line)
        
        # Generate and handle the report
        report = self.generate_report()
        self.display_report(report)
        self.save_to_csv(report)
        


if __name__ == "__main__":
    LogAnalyzer("sample.log").run()
