import os
import re
from typing import Union, List, Dict, Optional, Tuple, Callable
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
    use_regex: bool = False,
    condition_pattern: Optional[str] = None,
    abort_pattern: Optional[str] = None
) -> Optional[list]:
    """
    Calculate the mean elapsed time in milliseconds between logs matching two patterns.

    Args:
        logs (List[Dict[str, str]]): List of parsed log dictionaries.
        start_pattern (str): Pattern to detect the start log.
        end_pattern (str): Pattern to detect the end log.
        use_regex (bool): Whether to interpret patterns as regular expressions.
        condition_pattern (Optional[str]): If provided, checks if condition pattern is between start and end logs.
        abort_pattern (Optional[str]): If provided, looks for new start if pattern is found before end log.

    Returns:
        Optional[float]: Average elapsed time in milliseconds, or None if no valid pairs found.
    """
    time_deltas = []
    waiting_for_end = False
    start_time = None
    contains_condition = False

    for log in logs:
        message = log["message"]

        if not waiting_for_end and log_contains_pattern(message, start_pattern, use_regex):
            # Found a start pattern
            start_time = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S.%f")
            waiting_for_end = True

        if condition_pattern is not None and waiting_for_end:
            if log_contains_pattern(message, condition_pattern, use_regex):
                contains_condition = True

        if abort_pattern is not None and waiting_for_end:
            if log_contains_pattern(message, abort_pattern, use_regex):
                waiting_for_end = False
                contains_condition = False

        if waiting_for_end and log_contains_pattern(message, end_pattern, use_regex):
            # Found an end pattern after a start
            if condition_pattern is None or contains_condition is True:
                end_time = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S.%f")
                delta_ms = (end_time - start_time).total_seconds() * 1000  # Convert to ms
                time_deltas.append(delta_ms)
                contains_condition = False
            waiting_for_end = False
            start_time = None

    if not time_deltas:
        return None

    return time_deltas

def remove_error_blocks_between_patterns(
    logs: List[Dict],
    start_pattern: str,
    end_pattern: str,
    pattern_match_fn: Callable[[str, str], bool],
    inclusive: bool = True,
    error_filter_pattern: Optional[str] = None
) -> Tuple[List[Dict], int]:
    """
    Removes blocks of logs (from start_pattern to end_pattern) that contain a specific error.

    Args:
        logs: List of log dictionaries.
        start_pattern: Pattern identifying the start of a block.
        end_pattern: Pattern identifying the end of a block.
        pattern_match_fn: Boolean function to match patterns in messages.
        inclusive: If True, remove start and end logs too; otherwise keep them.
        error_filter_pattern: If provided, only errors matching this pattern will trigger removal.

    Returns:
        A tuple containing:
            - Filtered list of logs with error-containing blocks removed.
            - The number of removed blocks.
    """
    cleaned_logs = []
    i = 0
    n = len(logs)
    removed_count = 0

    while i < n:
        log = logs[i]
        if pattern_match_fn(log['message'], start_pattern):
            # Start of a block
            block = [log]
            error_found = (
                log['level'].upper() == 'ERROR' and
                (error_filter_pattern is None or pattern_match_fn(log['message'], error_filter_pattern))
            )
            i += 1

            # Scan until end_pattern or end of file
            while i < n:
                current_log = logs[i]
                block.append(current_log)

                if (
                    current_log['level'].upper() == 'ERROR' and
                    (error_filter_pattern is None or pattern_match_fn(current_log['message'], error_filter_pattern))
                ):
                    error_found = True

                if pattern_match_fn(current_log['message'], end_pattern):
                    break
                i += 1

            if error_found:
                # Remove block
                removed_count += 1
                i += 1  # Move past end of block
            else:
                # Keep the block
                if inclusive:
                    cleaned_logs.extend(block)
                else:
                    cleaned_logs.extend(block[1:-1] if len(block) > 2 else [])
                i += 1
        else:
            cleaned_logs.append(log)
            i += 1

    return cleaned_logs, removed_count

def contains_error_log(logs: List[Dict[str, str]]) -> bool:
    """
    Returns True if any log in the list has level 'ERROR'.

    Args:
        logs: A list of log dictionaries, each with at least a 'level' key.

    Returns:
        True if an error log is found; False otherwise.
    """
    return any(log.get('level', '').upper() == 'ERROR' for log in logs)
