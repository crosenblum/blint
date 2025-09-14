"""Blint - A lightweight batch file linter for Windows.

This module provides functionality to lint Windows batch files (.bat)
for common syntax errors, style issues, and potential pitfalls.
"""

import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple, DefaultDict, Optional
import warnings

__version__ = "1.0.0"


def read_file_with_encoding(file_path: str) -> Tuple[List[str], str]:
    """
    Reads a file with robust encoding detection and fallback mechanisms.

    Args:
        file_path: Path to the file to read

    Returns:
        Tuple of (lines, encoding_used)

    Raises:
        UnicodeDecodeError: If all encoding attempts fail (should be rare)
        FileNotFoundError: If file doesn't exist
        PermissionError: If file can't be accessed
        OSError: If file operation fails
    """
    # List of encodings to try in order of preference
    encodings_to_try = [
        "utf-8",  # Standard UTF-8
        "utf-8-sig",  # UTF-8 with BOM
        "latin1",  # ISO 8859-1 (can decode any byte sequence)
        "cp1252",  # Windows-1252 (common Windows encoding)
        "iso-8859-1",  # ISO Latin-1
        "ascii",  # Basic ASCII
        "cp437",  # Original IBM PC encoding
        "utf-16",  # UTF-16 with BOM detection
        "utf-32",  # UTF-32 with BOM detection
    ]

    # Try to detect encoding using chardet if available
    try:
        import chardet  # pylint: disable=import-outside-toplevel

        with open(file_path, "rb") as file_handle:
            raw_data = file_handle.read()

        detected = chardet.detect(raw_data)
        if detected and detected["encoding"] and detected["confidence"] > 0.7:
            detected_encoding = detected["encoding"].lower()
            # Add detected encoding to the front of our list if it's not already there
            if detected_encoding not in [enc.lower() for enc in encodings_to_try]:
                encodings_to_try.insert(0, detected_encoding)
            else:
                # Move detected encoding to front if it exists in our list
                for i, enc in enumerate(encodings_to_try):
                    if enc.lower() == detected_encoding:
                        encodings_to_try.insert(0, encodings_to_try.pop(i))
                        break
    except ImportError:
        # chardet not available, continue with fallback approach
        pass
    except (OSError, ValueError, TypeError):
        # Any other error in detection, continue with fallback
        pass

    # Try each encoding until one works
    last_exception: Optional[Exception] = None
    for encoding in encodings_to_try:
        try:
            with open(file_path, "r", encoding=encoding, errors="strict") as file_handle:
                lines = file_handle.readlines()
            return lines, encoding
        except UnicodeDecodeError as decode_error:
            last_exception = decode_error
            continue
        except (LookupError, ValueError) as encoding_error:
            # Encoding not supported or invalid
            last_exception = encoding_error
            continue

    # If we get here, all encodings failed - this should be extremely rare
    # since latin1 can decode any byte sequence
    if last_exception:
        raise OSError(
            f"All encoding attempts failed for file '{file_path}'. " f"Last error: {last_exception}"
        ) from last_exception

    raise OSError(f"Could not read file '{file_path}' with any supported encoding")


DANGEROUS_COMMANDS = [
    r"del\s+\*/\*|\*\.?\*",
    r"format\s+[a-z]:",
    r"shutdown",
    r"rmdir\s+/s\s+/q\s+",
]

ERROR_SEVERITY: Dict[str, str] = {
    "Missing '@echo off' at top of file": "WARNING",
    "Unquoted variable usage": "WARNING",
    "'goto' has no matching label": "CRITICAL",
    "'if' statement missing comparison operator '=='": "WARNING",
    "Potentially dangerous command": "CRITICAL",
    "Line exceeds 120 characters": "STYLE",
    "Delayed expansion used without 'setlocal enabledelayedexpansion'": "CRITICAL",
    "Unescaped special character outside quotes": "WARNING",
    "Malformed 'for' loop missing 'do'": "CRITICAL",
    "Trailing whitespace": "STYLE",
    "Duplicate label": "WARNING",
    "Potential unsafe 'set' command usage": "WARNING",
    "Usage of undefined variable": "CRITICAL",
    "Mismatched quotes detected": "CRITICAL",
}

ERROR_EXPLANATIONS: Dict[str, str] = {
    "Missing '@echo off' at top of file": (
        "Batch scripts usually start with '@echo off' to prevent "
        "command echoing during execution."
    ),
    "Unquoted variable usage": (
        "Variables like %VAR% or !VAR! should be quoted to prevent "
        "issues with spaces or special characters."
    ),
    "'goto' has no matching label": (
        "A 'goto' statement points to a label that does not exist, "
        "which causes runtime errors."
    ),
    "'if' statement missing comparison operator '=='": (
        "An 'if' statement must have a comparison operator '==' "
        "to work correctly."
    ),
    "Potentially dangerous command": (
        "Commands like 'del *.*' or 'format c:' can cause data loss "
        "or system shutdowns."
    ),
    "Line exceeds 120 characters": (
        "Lines longer than 120 characters are hard to read and maintain."
    ),
    "Delayed expansion used without 'setlocal enabledelayedexpansion'": (
        "Using variables with exclamation marks (!) requires delayed "
        "expansion enabled by 'setlocal enabledelayedexpansion'."
    ),
    "Unescaped special character outside quotes": (
        "Special characters like &, |, <, > should be escaped or "
        "enclosed in quotes to avoid unintended command execution."
    ),
    "Malformed 'for' loop missing 'do'": (
        "A 'for' loop must contain the 'do' keyword for proper execution."
    ),
    "Trailing whitespace": (
        "Trailing spaces at the end of a line can cause subtle errors "
        "and should be removed."
    ),
    "Duplicate label": (
        "Multiple labels with the same name can cause unpredictable "
        "'goto' behavior."
    ),
    "Potential unsafe 'set' command usage": (
        "Using 'set' to assign variables without proper quoting or "
        "checks can cause unexpected results."
    ),
    "Usage of undefined variable": (
        "Variables are used in the script but never set, which may "
        "cause runtime errors or unexpected behavior."
    ),
    "Mismatched quotes detected": (
        "Lines with an odd number of quotes may cause syntax errors "
        "or unexpected command behavior."
    ),
}


def print_help() -> None:
    """Print help information for the blint command."""
    help_text = """
Batch Linter - Help Menu

Usage:
  python blint.py <batch_file> [options]

Arguments:
  <batch_file>        Path to the batch (.bat) file to lint.

Options:
  --summary           Show a summary section with total errors and most common error.
  --severity          Show error severity levels and their meaning.
  --help              Display this help menu and exit.

Examples:
  python blint.py myscript.bat
      Shows detailed error list only (default).

  python blint.py myscript.bat --summary
      Shows summary and detailed errors.

  python blint.py myscript.bat --severity
      Shows detailed errors plus error severity.

  python blint.py myscript.bat --summary --severity
      Shows summary, detailed errors, and severity info.

If no <batch_file> is specified or '--help' is passed, this help menu will be displayed.
"""
    print(help_text.strip())


def _collect_labels(lines: List[str]) -> Tuple[Dict[str, int], List[Tuple[int, str]]]:
    """Collect all labels and detect duplicates."""
    labels: Dict[str, int] = {}
    issues: List[Tuple[int, str]] = []

    for i, line in enumerate(lines, start=1):
        if line.strip().startswith(":"):
            label = line.strip().lower()
            if label in labels:
                issues.append((i, "Duplicate label"))
            else:
                labels[label] = i

    return labels, issues


def _collect_set_variables(lines: List[str]) -> set[str]:
    """Collect all variables that are set in the script."""
    set_vars: set[str] = set()
    for line in lines:
        set_match = re.match(r"set\s+([A-Za-z0-9_]+)=", line.strip(), re.IGNORECASE)
        if set_match:
            var_name_text: str = set_match.group(1)
            set_vars.add(var_name_text.upper())
    return set_vars


def _check_basic_rules(line: str, line_num: int, labels: Dict[str, int]) -> List[Tuple[int, str]]:
    """Check basic rules for a single line."""
    issues: List[Tuple[int, str]] = []
    stripped = line.strip()

    # Rule: unquoted %VAR% or !VAR!
    pattern = r'(?<!["\'])%[A-Z0-9_]+%|(?<!["\'])![A-Z0-9_]+!'
    if re.search(pattern, stripped, re.IGNORECASE):
        issues.append((line_num, "Unquoted variable usage"))

    # Rule: GOTO without label
    goto_match = re.match(r"goto\s+(:?\S+)", stripped, re.IGNORECASE)
    if goto_match:
        label_text: str = goto_match.group(1)
        target_label: str = label_text.lower()
        if not target_label.startswith(":"):
            target_label = ":" + target_label
        if target_label not in labels:
            issues.append((line_num, f"'goto {label_text}' has no matching label"))

    # Rule: if without == operator (basic heuristic)
    if re.match(r"if\s+[^=]+$", stripped, re.IGNORECASE) and "==" not in stripped:
        issues.append((line_num, "'if' statement missing comparison operator '=='"))

    # Rule: suspicious dangerous commands
    for cmd_pattern in DANGEROUS_COMMANDS:
        if re.search(cmd_pattern, stripped, re.IGNORECASE):
            issues.append((line_num, "Potentially dangerous command"))

    # Rule: long lines
    if len(line.rstrip("\n")) > 120:
        issues.append((line_num, "Line exceeds 120 characters"))

    # Rule: Malformed 'for' loop missing 'do'
    if re.match(r"for\s+.*", stripped, re.IGNORECASE) and " do " not in stripped.lower():
        issues.append((line_num, "Malformed 'for' loop missing 'do'"))

    # Rule: Trailing whitespace
    if line.rstrip("\n") != line.rstrip():
        issues.append((line_num, "Trailing whitespace"))

    return issues


def _check_delayed_expansion(
    line: str, line_num: int, delayed_expansion_enabled: bool
) -> List[Tuple[int, str]]:
    """Check delayed expansion rules for a single line."""
    issues: List[Tuple[int, str]] = []
    stripped = line.strip()

    if not delayed_expansion_enabled and re.search(r"![A-Z0-9_]+!", stripped, re.IGNORECASE):
        issues.append((
            line_num, "Delayed expansion used without 'setlocal enabledelayedexpansion'"
        ))

    return issues


def _check_special_characters(line: str, line_num: int) -> List[Tuple[int, str]]:
    """Check for unescaped special characters outside quotes."""
    issues: List[Tuple[int, str]] = []
    special_chars = ["&", "|", "<", ">"]
    in_quotes = False
    prev_char = ""

    for char in line:
        if char == '"':
            in_quotes = not in_quotes
        elif char in special_chars and not in_quotes:
            if prev_char != "^":
                issues.append((line_num, "Unescaped special character outside quotes"))
                break
        prev_char = char

    return issues


def _check_set_command(line: str, line_num: int) -> List[Tuple[int, str]]:
    """Check set command usage for safety."""
    issues: List[Tuple[int, str]] = []
    stripped = line.strip()

    set_match = re.match(r"set\s+([A-Za-z0-9_]+)=(.+)", stripped, re.IGNORECASE)
    if set_match:
        var_val_text: str = set_match.group(2)
        var_val: str = var_val_text.strip()
        if not (var_val.startswith('"') and var_val.endswith('"')):
            issues.append((line_num, "Potential unsafe 'set' command usage"))

    return issues


def _check_undefined_variables(lines: List[str], set_vars: set[str]) -> List[Tuple[int, str]]:
    """Check for usage of undefined variables."""
    issues: List[Tuple[int, str]] = []
    var_usage_pattern = re.compile(r"%([A-Z0-9_]+)%|!([A-Z0-9_]+)!", re.IGNORECASE)

    for i, line in enumerate(lines, start=1):
        for match in var_usage_pattern.finditer(line):
            var_match_1: Optional[str] = match.group(1)
            var_match_2: Optional[str] = match.group(2)
            var_name: str = (var_match_1 or var_match_2 or "").upper()
            if var_name not in set_vars:
                issues.append((i, "Usage of undefined variable"))

    return issues


def _check_mismatched_quotes(lines: List[str]) -> List[Tuple[int, str]]:
    """Check for mismatched quotes."""
    issues: List[Tuple[int, str]] = []

    for i, line in enumerate(lines, start=1):
        if line.count('"') % 2 != 0:
            issues.append((i, "Mismatched quotes detected"))

    return issues


def lint_batch_file(file_path: str) -> List[Tuple[int, str]]:
    """Lint a batch file and return list of issues.

    Args:
        file_path: Path to the batch file to lint

    Returns:
        List of tuples containing (line_number, error_message)

    Raises:
        OSError: If file cannot be read or encoding issues occur
        FileNotFoundError: If file doesn't exist
        PermissionError: If file can't be accessed
    """
    lines, encoding_used = read_file_with_encoding(file_path)

    # Issue a warning if we had to fall back from UTF-8
    if encoding_used.lower() not in ["utf-8", "utf-8-sig"]:
        warnings.warn(
            f"File '{file_path}' was read using '{encoding_used}' encoding instead of UTF-8. "
            f"Consider converting the file to UTF-8 for better compatibility.",
            UserWarning,
            stacklevel=2,
        )

    issues: List[Tuple[int, str]] = []

    # Rule: @echo off at the top
    if lines and not lines[0].strip().lower().startswith("@echo off"):
        issues.append((1, "Missing '@echo off' at top of file"))

    # Collect labels and check for duplicates
    labels, label_issues = _collect_labels(lines)
    issues.extend(label_issues)

    # Detect if delayed expansion enabled
    delayed_expansion_enabled = any(
        re.search(r"setlocal\s+enabledelayedexpansion", line, re.IGNORECASE) for line in lines
    )

    # Check each line
    for i, line in enumerate(lines, start=1):
        issues.extend(_check_basic_rules(line, i, labels))
        issues.extend(_check_delayed_expansion(line, i, delayed_expansion_enabled))
        issues.extend(_check_special_characters(line, i))
        issues.extend(_check_set_command(line, i))

    # Collect set variables and check for undefined usage
    set_vars = _collect_set_variables(lines)
    issues.extend(_check_undefined_variables(lines, set_vars))
    issues.extend(_check_mismatched_quotes(lines))

    return issues


def group_issues(issues: List[Tuple[int, str]]) -> DefaultDict[str, List[int]]:
    """Group issues by type and return dictionary.

    Args:
        issues: List of tuples containing (line_number, error_message)

    Returns:
        Dictionary mapping error types to lists of line numbers
    """
    grouped: DefaultDict[str, List[int]] = defaultdict(list)
    for lineno, message in issues:
        if "Potentially dangerous command" in message:
            key = "Potentially dangerous command"
        elif "'goto" in message:
            key = "Missing label(s) for 'goto' statements"
        elif message.startswith("Usage of undefined variable"):
            key = "Usage of undefined variable"
        else:
            key = message
        grouped[key].append(lineno)
    return grouped


def print_summary(grouped: DefaultDict[str, List[int]]) -> None:
    """Print summary statistics of linting issues.

    Args:
        grouped: Dictionary mapping error types to lists of line numbers
    """
    total_errors = sum(len(lines) for lines in grouped.values())

    def get_error_count(item: Tuple[str, List[int]]) -> int:
        return len(item[1])

    most_common_error = max(grouped.items(), key=get_error_count) if grouped else ("", [])

    # Count errors per severity
    severity_counts: DefaultDict[str, int] = defaultdict(int)
    for error_type, lines in grouped.items():
        sev = ERROR_SEVERITY.get(error_type, "UNKNOWN")
        severity_counts[sev] += len(lines)

    print("\nSUMMARY:")
    print(f"Total errors: {total_errors}")
    if most_common_error[0]:
        print(
            f"Most common error: '{most_common_error[0]}' ({len(most_common_error[1])} occurrences)"
        )
    else:
        print("No errors found")
    print("\nErrors by severity:")
    for sev in ["CRITICAL", "WARNING", "STYLE", "UNKNOWN"]:
        if sev in severity_counts:
            print(f"  {sev}: {severity_counts[sev]}")


def print_detailed(grouped: DefaultDict[str, List[int]]) -> None:
    """Print detailed error information.

    Args:
        grouped: Dictionary mapping error types to lists of line numbers
    """
    # Group errors by severity and sort severity by importance
    severity_order = ["CRITICAL", "WARNING", "STYLE", "UNKNOWN"]
    severity_groups: DefaultDict[str, List[Tuple[str, List[int]]]] = defaultdict(list)
    for error_type, lines in grouped.items():
        sev = ERROR_SEVERITY.get(error_type, "UNKNOWN")
        severity_groups[sev].append((error_type, lines))

    print("\nDETAILED ERRORS:")
    print("----------------")
    for sev in severity_order:
        if sev not in severity_groups:
            continue
        print(f"{sev} ISSUES:")
        for error_type, lines in severity_groups[sev]:
            line_list = ", ".join(str(l) for l in sorted(lines))
            explanation = ERROR_EXPLANATIONS.get(error_type, "No explanation available.")
            print(f"   Line numbers: {line_list}")
            print(f"   {error_type}")
            print(f"   - Explanation: {explanation}")
            print("   - Recommendation: (optional) Review and fix the issue on these lines.\n")


def print_severity_info(grouped: DefaultDict[str, List[int]]) -> None:
    """Print severity level information.

    Args:
        grouped: Dictionary mapping error types to lists of line numbers
    """
    severity_counts: DefaultDict[str, int] = defaultdict(int)
    for error_type, lines in grouped.items():
        sev = ERROR_SEVERITY.get(error_type, "UNKNOWN")
        severity_counts[sev] += len(lines)

    descriptions: Dict[str, str] = {
        "CRITICAL": "Must fix before running the script; may cause crashes or data loss.",
        "WARNING": "Should fix; can cause unexpected behavior.",
        "STYLE": "Cosmetic or style issue; does not affect execution.",
        "UNKNOWN": "Unknown severity level.",
    }

    print("\nERROR SEVERITY:")
    print("---------------")
    for sev in ["CRITICAL", "WARNING", "STYLE", "UNKNOWN"]:
        count = severity_counts.get(sev, 0)
        if count == 0:
            continue
        error_word = "error" if count == 1 else "errors"
        print(f"{sev}: {count} {error_word}")
        print(f"    {descriptions.get(sev)}")


def main() -> None:
    """Main entry point for the blint application."""
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print_help()
        return

    batch_file: Optional[str] = None
    show_summary = False

    for arg in sys.argv[1:]:
        if arg.lower().endswith(".bat"):
            batch_file = arg
        elif arg == "--summary":
            show_summary = True
        elif arg == "--severity":
            pass  # Severity is always shown

    if not batch_file or not Path(batch_file).is_file():
        print("Error: No valid batch file provided.\n")
        print_help()
        return

    try:
        issues = lint_batch_file(batch_file)
        grouped = group_issues(issues)
    except UnicodeDecodeError as decode_error:
        print(f"Error: Could not read the batch file '{batch_file}' due to encoding issues:")
        print(f"  {decode_error}")
        print("\nTroubleshooting tips:")
        print("  1. Ensure the file is a valid text file")
        print("  2. Try converting the file to UTF-8 encoding")
        print("  3. Check if the file contains binary data")
        print("  4. For better encoding detection, install 'chardet': pip install chardet")
        return
    except FileNotFoundError:
        print(f"Error: File '{batch_file}' not found.")
        return
    except PermissionError:
        print(f"Error: Permission denied when trying to read '{batch_file}'.")
        return
    except (OSError, ValueError, TypeError) as general_error:
        print(f"Error: Unexpected error while processing '{batch_file}': {general_error}")
        return

    print_detailed(grouped)

    if show_summary:
        print_summary(grouped)

    print_severity_info(grouped)


if __name__ == "__main__":
    main()
