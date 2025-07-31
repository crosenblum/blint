import re
import sys
from collections import defaultdict
from pathlib import Path

DANGEROUS_COMMANDS = [
    r'del\s+\*/\*|\*\.?\*',
    r'format\s+[a-z]:',
    r'shutdown',
    r'rmdir\s+/s\s+/q\s+'
]

ERROR_SEVERITY = {
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
    "Mismatched quotes detected": "CRITICAL"
}

ERROR_EXPLANATIONS = {
    "Missing '@echo off' at top of file":
        "Batch scripts usually start with '@echo off' to prevent command echoing during execution.",
    "Unquoted variable usage":
        "Variables like %VAR% or !VAR! should be quoted to prevent issues with spaces or special characters.",
    "'goto' has no matching label":
        "A 'goto' statement points to a label that does not exist, which causes runtime errors.",
    "'if' statement missing comparison operator '=='":
        "An 'if' statement must have a comparison operator '==' to work correctly.",
    "Potentially dangerous command":
        "Commands like 'del *.*' or 'format c:' can cause data loss or system shutdowns.",
    "Line exceeds 120 characters":
        "Lines longer than 120 characters are hard to read and maintain.",
    "Delayed expansion used without 'setlocal enabledelayedexpansion'":
        "Using variables with exclamation marks (!) requires delayed expansion enabled by 'setlocal enabledelayedexpansion'.",
    "Unescaped special character outside quotes":
        "Special characters like &, |, <, > should be escaped or enclosed in quotes to avoid unintended command execution.",
    "Malformed 'for' loop missing 'do'":
        "A 'for' loop must contain the 'do' keyword for proper execution.",
    "Trailing whitespace":
        "Trailing spaces at the end of a line can cause subtle errors and should be removed.",
    "Duplicate label":
        "Multiple labels with the same name can cause unpredictable 'goto' behavior.",
    "Potential unsafe 'set' command usage":
        "Using 'set' to assign variables without proper quoting or checks can cause unexpected results.",
    "Usage of undefined variable":
        "Variables are used in the script but never set, which may cause runtime errors or unexpected behavior.",
    "Mismatched quotes detected":
        "Lines with an odd number of quotes may cause syntax errors or unexpected command behavior."
}

def print_help():
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

def lint_batch_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    issues = []

    # Rule: @echo off at the top
    if not lines[0].strip().lower().startswith("@echo off"):
        issues.append((1, "Missing '@echo off' at top of file"))

    # Pre-gather all labels for goto checks and track duplicates
    labels = {}
    for i, line in enumerate(lines, start=1):
        if line.strip().startswith(":"):
            label = line.strip().lower()
            if label in labels:
                issues.append((i, "Duplicate label"))
            else:
                labels[label] = i

    # Detect if delayed expansion enabled
    delayed_expansion_enabled = any(
        re.search(r'setlocal\s+enabledelayedexpansion', line, re.IGNORECASE) for line in lines
    )

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Rule: unquoted %VAR% or !VAR!
        pattern = r'(?<!["\'])%[A-Z0-9_]+%|(?<!["\'])![A-Z0-9_]+!'
        if re.search(pattern, stripped, re.IGNORECASE):
            issues.append((i, "Unquoted variable usage"))

        # Rule: GOTO without label
        m = re.match(r'goto\s+(:?\S+)', stripped, re.IGNORECASE)
        if m:
            label = m.group(1).lower()
            if not label.startswith(':'):
                label = ':' + label
            if label not in labels:
                issues.append((i, f"'goto {m.group(1)}' has no matching label"))

        # Rule: if without == operator (basic heuristic)
        if re.match(r'if\s+[^=]+$', stripped, re.IGNORECASE) and '==' not in stripped:
            issues.append((i, "'if' statement missing comparison operator '=='"))

        # Rule: suspicious dangerous commands
        for cmd_pattern in DANGEROUS_COMMANDS:
            if re.search(cmd_pattern, stripped, re.IGNORECASE):
                issues.append((i, f"Potentially dangerous command"))

        # Rule: long lines
        if len(line.rstrip('\n')) > 120:
            issues.append((i, "Line exceeds 120 characters"))

        # Rule: Detect delayed expansion usage without setlocal enabledelayedexpansion
        if not delayed_expansion_enabled and re.search(r'![A-Z0-9_]+!', stripped, re.IGNORECASE):
            issues.append((i, "Delayed expansion used without 'setlocal enabledelayedexpansion'"))

        # Rule: Unescaped special characters outside quotes
        special_chars = ['&', '|', '<', '>']
        in_quotes = False
        prev_char = ''
        for ch in line:
            if ch == '"':
                in_quotes = not in_quotes
            elif ch in special_chars and not in_quotes:
                if prev_char != '^':
                    issues.append((i, "Unescaped special character outside quotes"))
                    break
            prev_char = ch

        # Rule: Malformed 'for' loop missing 'do'
        if re.match(r'for\s+.*', stripped, re.IGNORECASE) and ' do ' not in stripped.lower():
            issues.append((i, "Malformed 'for' loop missing 'do'"))

        # Rule: Trailing whitespace
        if line.rstrip('\n') != line.rstrip():
            issues.append((i, "Trailing whitespace"))

        # Rule: Potential unsafe 'set' command usage
        set_match = re.match(r'set\s+([A-Za-z0-9_]+)=(.+)', stripped, re.IGNORECASE)
        if set_match:
            var_val = set_match.group(2).strip()
            if not (var_val.startswith('"') and var_val.endswith('"')):
                issues.append((i, "Potential unsafe 'set' command usage"))

    # New check: gather all variables that are set in the script
    set_vars = set()
    for line in lines:
        set_match = re.match(r'set\s+([A-Za-z0-9_]+)=', line.strip(), re.IGNORECASE)
        if set_match:
            set_vars.add(set_match.group(1).upper())

    # New check: undefined variable usage
    var_usage_pattern = re.compile(r'%([A-Z0-9_]+)%|!([A-Z0-9_]+)!', re.IGNORECASE)
    for i, line in enumerate(lines, start=1):
        for match in var_usage_pattern.finditer(line):
            var_name = (match.group(1) or match.group(2)).upper()
            if var_name not in set_vars:
                issues.append((i, "Usage of undefined variable"))

    # New check: mismatched quotes
    for i, line in enumerate(lines, start=1):
        if line.count('"') % 2 != 0:
            issues.append((i, "Mismatched quotes detected"))

    return issues

def group_issues(issues):
    grouped = defaultdict(list)
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

def print_summary(grouped):
    total_errors = sum(len(lines) for lines in grouped.values())
    most_common_error = max(grouped.items(), key=lambda x: len(x[1]))

    # Count errors per severity
    severity_counts = defaultdict(int)
    for error_type, lines in grouped.items():
        sev = ERROR_SEVERITY.get(error_type, "UNKNOWN")
        severity_counts[sev] += len(lines)

    print("\nSUMMARY:")
    print(f"Total errors: {total_errors}")
    print(f"Most common error: '{most_common_error[0]}' ({len(most_common_error[1])} occurrences)")
    print("\nErrors by severity:")
    for sev in ["CRITICAL", "WARNING", "STYLE", "UNKNOWN"]:
        if sev in severity_counts:
            print(f"  {sev}: {severity_counts[sev]}")

def print_detailed(grouped):
    # Group errors by severity and sort severity by importance
    severity_order = ["CRITICAL", "WARNING", "STYLE", "UNKNOWN"]
    severity_groups = defaultdict(list)
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
            print(f"   - Recommendation: (optional) Review and fix the issue on these lines.\n")

def print_severity_info(grouped):
    severity_counts = defaultdict(int)
    for error_type, lines in grouped.items():
        sev = ERROR_SEVERITY.get(error_type, "UNKNOWN")
        severity_counts[sev] += len(lines)

    descriptions = {
        "CRITICAL": "Must fix before running the script; may cause crashes or data loss.",
        "WARNING": "Should fix; can cause unexpected behavior.",
        "STYLE": "Cosmetic or style issue; does not affect execution.",
        "UNKNOWN": "Unknown severity level."
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

def main():
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print_help()
        return

    batch_file = None
    show_summary = False
    show_severity = False

    for arg in sys.argv[1:]:
        if arg.lower().endswith(".bat"):
            batch_file = arg
        elif arg == "--summary":
            show_summary = True
        elif arg == "--severity":
            show_severity = True

    if not batch_file or not Path(batch_file).is_file():
        print("Error: No valid batch file provided.\n")
        print_help()
        return

    issues = lint_batch_file(batch_file)
    grouped = group_issues(issues)

    print_detailed(grouped)

    if show_summary:
        print_summary(grouped)

    print_severity_info(grouped)

if __name__ == "__main__":
    main()
