import os
import re
from typing import Union, List, Dict, Optional
from datetime import datetime


# Function to read and return lines from the log file
def read_log_file(file_path):
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return []

    with open(file_path, 'r') as file:
        lines = file.readlines()

    return lines

def extract_logs_by_level(log_lines: List[str], levels: Union[str, List[str]]) -> List[dict]:
    """
    Extract log entries of a specific logging level from a list of log lines.

    Args:
        log_lines (List[str]): The list of log lines to parse.
        levels (List[str]): The log levels to filter by (e.g., 'INFO', 'ERROR').

    Returns:
        List[dict]: A list of dictionaries with 'timestamp', 'level', and 'message'.
    """
    if isinstance(levels, str):
        levels = [levels]
    levels = [lvl.upper() for lvl in levels]
    filtered_logs = []

    for line in log_lines:
        line = line.strip()
        parts = line.split("::", 2)  # Split into exactly 3 parts

        if len(parts) != 3:
            print("Invalid log line detected - Ignoring.")
            continue

        timestamp, log_level, message = parts

        if log_level.upper() in levels:
            filtered_logs.append({
                "timestamp": timestamp,
                "level": log_level,
                "message": message
            })

    return filtered_logs

def sorted_log_combine(logs1: List[Dict[str, str]], logs2: List[Dict[str, str]]) -> List[dict[str, str]]:
    return sorted(logs1 + logs2, key=lambda log: log["timestamp"])

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

def elapsed_time_between_patterns(
    logs: List[Dict[str, str]],
    start_pattern: str,
    end_pattern: str,
    use_regex: bool = False
) -> Optional[list]:
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

    return time_deltas
