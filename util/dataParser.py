import os
import re
from typing import List, Dict, Optional
from datetime import datetime

import pandas as pd
import matplotlib.pyplot as plt


# Function to read and return lines from the log file
def read_log_file(file_path):
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return []

    with open(file_path, 'r') as file:
        lines = file.readlines()

    return lines

def extract_logs_by_level(log_lines: List[str], level: str) -> List[dict]:
    """
    Extract log entries of a specific logging level from a list of log lines.

    Args:
        log_lines (List[str]): The list of log lines to parse.
        level (str): The log level to filter by (e.g., 'INFO', 'ERROR').

    Returns:
        List[dict]: A list of dictionaries with 'timestamp', 'level', and 'message'.
    """
    filtered_logs = []

    for line in log_lines:
        line = line.strip()
        parts = line.split("::", 2)  # Split into exactly 3 parts

        if len(parts) != 3:
            raise KeyboardInterrupt("Invalid log line detected!")

        timestamp, log_level, message = parts

        if log_level == level.upper():
            filtered_logs.append({
                "timestamp": timestamp,
                "level": log_level,
                "message": message
            })

    return filtered_logs

def log_contains_pattern(message: str, pattern: str, use_regex: bool = False) -> bool:
    """
    Check if a log message contains a specific pattern.

    Args:
        message (str): The log message to search.
        pattern (str): The pattern to look for.
        use_regex (bool): If True, interpret `pattern` as a regular expression.

    Returns:
        bool: True if the pattern is found in the message, False otherwise.
    """
    if use_regex:
        return re.search(pattern, message) is not None
    else:
        return pattern in message

def mean_elapsed_time_between_patterns(
    logs: List[Dict[str, str]],
    start_pattern: str,
    end_pattern: str,
    use_regex: bool = False
) -> Optional[float]:
    """
    Calculate the mean elapsed time in milliseconds between logs matching two patterns.

    Args:
        logs (List[Dict[str, str]]): List of parsed log dictionaries.
        start_pattern (str): Pattern to detect the start log.
        end_pattern (str): Pattern to detect the end log.
        use_regex (bool): Whether to interpret patterns as regular expressions.

    Returns:
        Optional[float]: Average elapsed time in milliseconds, or None if no valid pairs found.
    """
    time_deltas = []
    waiting_for_end = False
    start_time = None

    for log in logs:
        message = log["message"]

        if not waiting_for_end and log_contains_pattern(message, start_pattern, use_regex):
            # Found a start pattern
            start_time = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S.%f")
            waiting_for_end = True

        elif waiting_for_end and log_contains_pattern(message, end_pattern, use_regex):
            # Found an end pattern after a start
            end_time = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S.%f")
            delta_ms = (end_time - start_time).total_seconds() * 1000  # Convert to ms
            time_deltas.append(delta_ms)
            waiting_for_end = False
            start_time = None

    if not time_deltas:
        return None

    return sum(time_deltas) / len(time_deltas)

# Example usage
if __name__ == "__main__":
    # Path to your log file
    logA_file_path = "../data/20km/ML-DSA-87/logA.log"
    logB_file_path = "../data/20km/ML-DSA-87/logB.log"

    # Read the log file
    logA_lines = read_log_file(logA_file_path)
    logB_lines = read_log_file(logB_file_path)

    # Show a preview of the first 5 lines
    # print("First 5 lines from the log file:")
    # for line in logA_lines[:5]:
    #     print(line.strip())
    # for line in logB_lines[:5]:
    #     print(line.strip())

    # Extract only INFO-level logs
    info_logs = extract_logs_by_level(logA_lines, "INFO")
    # print(f"\nFound {len(info_logs)} INFO logs:")
    # for log in info_logs[:5]:
    #     if log_contains_pattern(log["message"], "TX count"):
    #         print(log)

    avg_time = mean_elapsed_time_between_patterns(
        logs=info_logs,  # list of parsed logs
        start_pattern="Raw packet received",
        end_pattern="Encrypted and signed payload forwarded",
        use_regex=False
    )

    if avg_time is not None:
        print(f"Average time between events: {avg_time:.2f} ms")
    else:
        print("No valid start-end pairs found.")
