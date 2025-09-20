"""Blint - A lightweight batch file linter for Windows.

This module provides functionality to lint Windows batch files (.bat and .cmd)
for common syntax errors, style issues, and potential pitfalls.
"""
# pylint: disable=too-many-lines

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import re
import sys
from typing import DefaultDict, Dict, List, Optional, Tuple, Set
import warnings

__version__ = "1.0.0"


class RuleSeverity(Enum):
    """Rule severity levels."""
    ERROR = "Error"
    WARNING = "Warning"
    STYLE = "Style"
    SECURITY = "Security"
    PERFORMANCE = "Performance"


@dataclass
class Rule:
    """Represents a linting rule with code, explanation, and recommendation."""
    code: str
    name: str
    severity: RuleSeverity
    explanation: str
    recommendation: str
    def __post_init__(self) -> None:
        """Validate rule after initialization."""
        if not self.code or not isinstance(self.code, str):
            raise ValueError("Rule code must be a non-empty string")
        if not self.name or not isinstance(self.name, str):
            raise ValueError("Rule name must be a non-empty string")
        if not isinstance(self.severity, RuleSeverity):
            raise ValueError("Rule severity must be a RuleSeverity enum")
        if not self.explanation or not isinstance(self.explanation, str):
            raise ValueError("Rule explanation must be a non-empty string")
        if not self.recommendation or not isinstance(self.recommendation, str):
            raise ValueError("Rule recommendation must be a non-empty string")


@dataclass
class LintIssue:
    """Represents a linting issue found in a batch file."""
    line_number: int
    rule: Rule
    context: str = ""  # Additional context about the issue
    def __post_init__(self) -> None:
        """Validate issue after initialization."""
        if self.line_number < 1:
            raise ValueError("Line number must be positive")
        if not isinstance(self.rule, Rule):
            raise ValueError("Rule must be a Rule instance")


# Comprehensive rule definitions
RULES: Dict[str, Rule] = {
    # Error Level Rules (E001-E999)
    "E001": Rule(
        code="E001",
        name="Nested parentheses mismatch",
        severity=RuleSeverity.ERROR,
        explanation="Batch scripts have improper nesting or mismatched "
                    "parentheses which will cause syntax errors",
        recommendation="Ensure all opening parentheses have matching "
                      "closing parentheses and are properly nested"
    ),
    "E002": Rule(
        code="E002",
        name="Missing label for GOTO statement",
        severity=RuleSeverity.ERROR,
        explanation="GOTO statement points to a label that does not exist, "
                    "which will cause runtime errors",
        recommendation="Create the missing label or correct the GOTO "
                      "statement to point to an existing label"
    ),
    "E003": Rule(
        code="E003",
        name="IF statement improper formatting",
        severity=RuleSeverity.ERROR,
        explanation="IF statement has improper spacing or syntax that "
                    "will prevent correct execution",
        recommendation="Use proper spacing: IF \"condition\" operator \"value\" command"
    ),
    "E004": Rule(
        code="E004",
        name="IF EXIST syntax mixing",
        severity=RuleSeverity.ERROR,
        explanation="Mixing IF EXIST syntax with comparison operators "
                    "creates invalid syntax",
        recommendation="Use either 'IF EXIST filename' or "
                      "'IF \"variable\"==\"value\"' but not both together"
    ),
    "E005": Rule(
        code="E005",
        name="Invalid path syntax",
        severity=RuleSeverity.ERROR,
        explanation="Path contains invalid characters or exceeds "
                    "system length limits",
        recommendation="Remove invalid characters (<>|\"*?) and ensure "
                      "path length is under 260 characters"
    ),
    "E006": Rule(
        code="E006",
        name="Undefined variable reference",
        severity=RuleSeverity.ERROR,
        explanation="Script references variables that were never set, "
                    "which may cause runtime errors",
        recommendation="Define the variable using SET before referencing it, "
                      "or add existence checks"
    ),
    "E007": Rule(
        code="E007",
        name="Empty variable check syntax error",
        severity=RuleSeverity.ERROR,
        explanation="Incorrect syntax for checking if variables are empty "
                    "will cause comparison errors",
        recommendation="Use proper syntax: IF \"%%VAR%%\"==\"\" for "
                      "empty variable checks"
    ),
    "E008": Rule(
        code="E008",
        name="Unreachable code after EXIT or GOTO",
        severity=RuleSeverity.ERROR,
        explanation="Code after EXIT or GOTO statements will never execute",
        recommendation="Remove unreachable code or restructure script logic"
    ),
    "E009": Rule(
        code="E009",
        name="Mismatched quotes",
        severity=RuleSeverity.ERROR,
        explanation="Lines with unmatched quotes will cause syntax errors or unexpected behavior",
        recommendation="Ensure all quotes are properly paired and closed"
    ),
    "E010": Rule(
        code="E010",
        name="Malformed FOR loop missing DO",
        severity=RuleSeverity.ERROR,
        explanation="FOR loops must contain the DO keyword for proper execution",
        recommendation="Add DO keyword: FOR %%i IN (items) DO command"
    ),

    # Warning Level Rules (W001-W999)
    "W001": Rule(
        code="W001",
        name="Missing exit code",
        severity=RuleSeverity.WARNING,
        explanation="Script doesn't set appropriate exit codes to indicate success or failure",
        recommendation="Add EXIT /b 0 for success or EXIT /b 1 for errors at script end"
    ),
    "W002": Rule(
        code="W002",
        name="Missing ERRORLEVEL check",
        severity=RuleSeverity.WARNING,
        explanation="Critical operations should check %%ERRORLEVEL%% to handle failures properly",
        recommendation="Add IF ERRORLEVEL 1 checks after operations that might fail"
    ),
    "W003": Rule(
        code="W003",
        name="Operation without error handling",
        severity=RuleSeverity.WARNING,
        explanation="Operations that commonly fail lack proper error checking",
        recommendation="Add error checking and appropriate responses for failed operations"
    ),
    "W004": Rule(
        code="W004",
        name="Potential infinite loop",
        severity=RuleSeverity.WARNING,
        explanation="Loop construct may run infinitely without proper exit conditions",
        recommendation="Add counter variables or proper exit conditions to prevent infinite loops"
    ),
    "W005": Rule(
        code="W005",
        name="Unquoted variable with spaces",
        severity=RuleSeverity.WARNING,
        explanation="Variables that may contain spaces should be quoted to prevent parsing errors",
        recommendation="Use quotes around variables: IF \"%%VARIABLE%%\"==\"value\""
    ),
    "W006": Rule(
        code="W006",
        name="Network operation without timeout",
        severity=RuleSeverity.WARNING,
        explanation="Network operations may hang indefinitely without proper timeout settings",
        recommendation="Add timeout parameters to network commands like PING -n 4"
    ),
    "W007": Rule(
        code="W007",
        name="File operation on potentially locked file",
        severity=RuleSeverity.WARNING,
        explanation="Operations on files that may be in use by other programs can fail",
        recommendation="Check if applications are using the file before attempting operations"
    ),
    "W008": Rule(
        code="W008",
        name="Permanent PATH modification",
        severity=RuleSeverity.WARNING,
        explanation="SETX modifies PATH permanently, which may not be desired",
        recommendation="Use SET for temporary changes or confirm permanent changes are intended"
    ),
    "W009": Rule(
        code="W009",
        name="Windows version compatibility",
        severity=RuleSeverity.WARNING,
        explanation="Command may not be available in older Windows versions",
        recommendation="Use version checks or provide alternative commands for older Windows"
    ),
    "W010": Rule(
        code="W010",
        name="Architecture-specific operation",
        severity=RuleSeverity.WARNING,
        explanation="Operation is specific to 32-bit or 64-bit architecture",
        recommendation="Add architecture detection and appropriate handling for both architectures"
    ),
    "W011": Rule(
        code="W011",
        name="Unicode handling issue",
        severity=RuleSeverity.WARNING,
        explanation="File operation may not handle Unicode characters properly",
        recommendation="Consider using commands with better Unicode support"
    ),
    "W012": Rule(
        code="W012",
        name="Non-ASCII characters detected",
        severity=RuleSeverity.WARNING,
        explanation="Non-ASCII characters may cause issues in some environments",
        recommendation="Use ASCII-only characters or ensure proper encoding handling"
    ),
    "W013": Rule(
        code="W013",
        name="Duplicate label",
        severity=RuleSeverity.WARNING,
        explanation="Multiple labels with the same name can cause unpredictable GOTO behavior",
        recommendation="Rename duplicate labels to have unique names"
    ),

    # Style Level Rules (S001-S999)
    "S001": Rule(
        code="S001",
        name="Missing @ECHO OFF at file start",
        severity=RuleSeverity.STYLE,
        explanation="Batch scripts usually start with @ECHO OFF to prevent "
                    "command echoing during execution",
        recommendation="Add '@ECHO OFF' as the first line of your script"
    ),
    "S002": Rule(
        code="S002",
        name="ECHO OFF without @ prefix",
        severity=RuleSeverity.STYLE,
        explanation="ECHO OFF should use @ prefix to prevent the command "
                    "itself from being displayed",
        recommendation="Use '@ECHO OFF' instead of 'ECHO OFF'"
    ),
    "S003": Rule(
        code="S003",
        name="Inconsistent command capitalization",
        severity=RuleSeverity.STYLE,
        explanation="Batch commands should follow consistent casing conventions for readability",
        recommendation="Use consistent UPPERCASE for all batch commands"
    ),
    "S004": Rule(
        code="S004",
        name="Trailing whitespace",
        severity=RuleSeverity.STYLE,
        explanation="Trailing spaces at line end can cause subtle errors and should be removed",
        recommendation="Remove trailing spaces and tabs from line endings"
    ),
    "S005": Rule(
        code="S005",
        name="Mixed line endings",
        severity=RuleSeverity.STYLE,
        explanation="Inconsistent line endings (CRLF vs LF) within the same file",
        recommendation="Use consistent CRLF line endings for Windows batch files"
    ),
    "S006": Rule(
        code="S006",
        name="Inconsistent variable naming",
        severity=RuleSeverity.STYLE,
        explanation="Variable names should follow consistent naming conventions",
        recommendation="Use consistent naming: either ALL_CAPS or camelCase throughout"
    ),
    "S007": Rule(
        code="S007",
        name="BAT extension used instead of CMD for newer Windows",
        severity=RuleSeverity.STYLE,
        explanation="The .cmd file extension is recommended over .bat for Windows NT and newer versions (Windows 2000+). "
                    "CMD files support additional features and have better error handling in newer Windows environments",
        recommendation="Consider renaming .bat files to .cmd for scripts intended for Windows 2000 and newer versions. "
                      "CMD files provide better compatibility with modern Windows features and improved error reporting"
    ),
    "S008": Rule(
        code="S008",
        name="Missing comments for complex code",
        severity=RuleSeverity.STYLE,
        explanation="Complex sections should have comments explaining their purpose",
        recommendation="Add REM comments to explain complex logic and operations"
    ),
    "S009": Rule(
        code="S009",
        name="Magic numbers used",
        severity=RuleSeverity.STYLE,
        explanation="Hardcoded numeric values should be defined as named variables",
        recommendation="Define constants using SET before using numeric values"
    ),
    "S010": Rule(
        code="S010",
        name="Dead code detected",
        severity=RuleSeverity.STYLE,
        explanation="Unused labels or unreferenced subroutines make code harder to maintain",
        recommendation="Remove unused labels and unreferenced code sections"
    ),
    "S011": Rule(
        code="S011",
        name="Line exceeds maximum length",
        severity=RuleSeverity.STYLE,
        explanation="Lines longer than 120 characters are hard to read and maintain",
        recommendation="Break long lines into multiple shorter lines for better readability"
    ),

    # Security Level Rules (SEC001-SEC999)
    "SEC001": Rule(
        code="SEC001",
        name="Potential command injection vulnerability",
        severity=RuleSeverity.SECURITY,
        explanation="User input used in commands without validation could "
                    "allow malicious code execution",
        recommendation="Validate and sanitize all user input before using in commands"
    ),
    "SEC002": Rule(
        code="SEC002",
        name="Unsafe SET command usage",
        severity=RuleSeverity.SECURITY,
        explanation="SET commands without proper validation or quoting can cause security issues",
        recommendation="Always quote SET values and validate input: SET \"var=safe value\""
    ),
    "SEC003": Rule(
        code="SEC003",
        name="Dangerous command without confirmation",
        severity=RuleSeverity.SECURITY,
        explanation="Destructive commands should require user confirmation "
                    "to prevent accidental execution",
        recommendation="Add confirmation prompts before destructive operations"
    ),
    "SEC004": Rule(
        code="SEC004",
        name="Dangerous registry operation",
        severity=RuleSeverity.SECURITY,
        explanation="Registry modifications can damage system functionality "
                    "and should be carefully reviewed",
        recommendation="Backup registry before modifications and use specific "
                      "keys rather than broad deletions"
    ),
    "SEC005": Rule(
        code="SEC005",
        name="Missing privilege check",
        severity=RuleSeverity.SECURITY,
        explanation="Operations requiring admin rights should check for proper privileges",
        recommendation="Use NET SESSION >nul 2>&1 to check for administrator privileges"
    ),
    "SEC006": Rule(
        code="SEC006",
        name="Hardcoded absolute path",
        severity=RuleSeverity.SECURITY,
        explanation="Absolute paths may not exist on other systems and could be security risks",
        recommendation="Use environment variables like %%USERPROFILE%% instead of hardcoded paths"
    ),
    "SEC007": Rule(
        code="SEC007",
        name="Hardcoded temporary directory",
        severity=RuleSeverity.SECURITY,
        explanation="Hardcoded temp paths may not exist and could create security vulnerabilities",
        recommendation="Use %%TEMP%% environment variable instead of hardcoded temporary paths"
    ),

    # Performance Level Rules (P001-P999)
    "P001": Rule(
        code="P001",
        name="Redundant file existence check",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Unnecessary repeated file existence checks reduce script performance",
        recommendation="Combine existence checks or store result in variable for reuse"
    ),
    "P002": Rule(
        code="P002",
        name="Code duplication detected",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Repeated code blocks should be refactored into "
                    "subroutines for better maintainability",
        recommendation="Create subroutines using CALL :function_name for repeated code"
    ),
    "P003": Rule(
        code="P003",
        name="Unnecessary SETLOCAL",
        severity=RuleSeverity.PERFORMANCE,
        explanation="SETLOCAL is not needed if there are no SET commands in the script",
        recommendation="Remove SETLOCAL if no local variables are set"
    ),
    "P004": Rule(
        code="P004",
        name="Unnecessary ENABLEDELAYEDEXPANSION",
        severity=RuleSeverity.PERFORMANCE,
        explanation="ENABLEDELAYEDEXPANSION is not needed if no !VARIABLES! are used",
        recommendation="Remove ENABLEDELAYEDEXPANSION if delayed expansion is not used"
    ),
    "P005": Rule(
        code="P005",
        name="ENDLOCAL without SETLOCAL",
        severity=RuleSeverity.PERFORMANCE,
        explanation="ENDLOCAL is not needed without a corresponding SETLOCAL",
        recommendation="Remove unnecessary ENDLOCAL commands"
    ),
    "P006": Rule(
        code="P006",
        name="Missing ENDLOCAL before exit",
        severity=RuleSeverity.PERFORMANCE,
        explanation="SETLOCAL should be paired with ENDLOCAL before every exit point",
        recommendation="Add ENDLOCAL before all EXIT statements when SETLOCAL is used"
    ),
    "P007": Rule(
        code="P007",
        name="Temporary file without random name",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Temporary files should use %%RANDOM%% to prevent file collisions",
        recommendation="Use %%RANDOM%% in temporary filenames: temp_%%RANDOM%%.txt"
    ),
    "P008": Rule(
        code="P008",
        name="Delayed expansion without enablement",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Using !VARIABLES! requires SETLOCAL "
                    "ENABLEDELAYEDEXPANSION for proper functionality",
        recommendation="Add SETLOCAL ENABLEDELAYEDEXPANSION before using !variable! syntax"
    ),
}


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
        import chardet  # pylint: disable=import-outside-toplevel  # isort: skip

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


# Legacy support - will be removed in future version
DANGEROUS_COMMANDS = [
    r"del\s+\*/\*|\*\.?\*",
    r"format\s+[a-z]:",
    r"shutdown",
    r"rmdir\s+/s\s+/q\s+",
]

# Pattern definitions for rule matching
DANGEROUS_COMMAND_PATTERNS: List[Tuple[str, str]] = [
    (r"del\s+\*/\*|\*\.?\*", "SEC003"),  # del *.* type commands
    (r"format\s+[a-z]:", "SEC003"),     # format c: type commands
    (r"shutdown", "SEC003"),             # shutdown commands
    (r"rmdir\s+/s\s+/q\s+", "SEC003"), # rmdir /s /q commands
    (r"reg\s+delete\s+.*\s+/f", "SEC004"), # forced registry deletions
]

COMMAND_CASING_KEYWORDS = {
    'echo', 'set', 'if', 'for', 'goto', 'call', 'exit', 'rem', 'pause',
    'copy', 'move', 'del', 'dir', 'type', 'find', 'findstr', 'sort',
    'more', 'cls', 'cd', 'pushd', 'popd', 'mkdir', 'rmdir', 'attrib',
    'xcopy', 'robocopy', 'ping', 'ipconfig', 'netstat', 'tasklist',
    'taskkill', 'sc', 'net', 'reg', 'wmic', 'powershell', 'timeout',
    'choice', 'setlocal', 'endlocal', 'enabledelayedexpansion'
}

OLDER_WINDOWS_COMMANDS = {
    'choice', 'forfiles', 'where', 'robocopy', 'timeout', 'icacls'
}

ARCHITECTURE_SPECIFIC_PATTERNS = [
    r"Wow6432Node",  # 32-bit registry redirect
    r"Program Files \(x86\)",  # 32-bit program files
    r"SysWow64",  # 32-bit system directory
]

UNICODE_PROBLEMATIC_COMMANDS = {
    'type', 'echo', 'find', 'findstr'
}


def print_help() -> None:
    """Print help information for the blint command."""
    help_text = """
Batch Linter - Help Menu

Usage:
  python blint.py <batch_file> [options]

Arguments:
  <batch_file>        Path to the batch (.bat or .cmd) file to lint.

Options:
  --summary           Show a summary section with total errors and most common error.
  --severity          Show error severity levels and their meaning.
  --help              Display this help menu and exit.

Rule Categories:
  E001-E999   Error Level    - Issues that will cause script failure
  W001-W999   Warning Level  - Bad practices that won't necessarily break script
  S001-S999   Style Level    - Code style and formatting issues
  SEC001+     Security Level - Security-related issues and vulnerabilities
  P001-P999   Performance    - Performance and efficiency improvements

Examples:
  python blint.py myscript.bat
      Shows detailed error list with rule codes and recommendations.

  python blint.py myscript.cmd --summary
      Shows summary and detailed errors.

  python blint.py myscript.bat --severity
      Shows detailed errors plus error severity breakdown.

  python blint.py myscript.cmd --summary --severity
      Shows summary, detailed errors, and severity info.

If no <batch_file> is specified or '--help' is passed, this help menu will be displayed.
"""
    print(help_text.strip())


def _collect_labels(lines: List[str]) -> Tuple[Dict[str, int], List[LintIssue]]:
    """Collect all labels and detect duplicates."""
    labels: Dict[str, int] = {}
    issues: List[LintIssue] = []

    for i, line in enumerate(lines, start=1):
        if line.strip().startswith(":"):
            label = line.strip().lower()
            if label in labels:
                issues.append(LintIssue(
                    line_number=i,
                    rule=RULES["W013"],  # Duplicate label
                    context=f"Label '{label}' already defined on line {labels[label]}"
                ))
            else:
                labels[label] = i

    return labels, issues


def _collect_set_variables(lines: List[str]) -> Set[str]:
    """Collect all variables that are set in the script."""
    set_vars: Set[str] = set()
    for line in lines:
        # Match different SET patterns
        patterns = [
            r"set\s+([A-Za-z0-9_]+)=",  # Regular set
            r"set\s+/p\s+([A-Za-z0-9_]+)=",  # Set with prompt
            r"set\s+/a\s+([A-Za-z0-9_]+)=",  # Arithmetic set
        ]

        for pattern in patterns:
            set_match = re.match(pattern, line.strip(), re.IGNORECASE)
            if set_match:
                var_name_text: str = set_match.group(1)
                set_vars.add(var_name_text.upper())
                break

    # Add common environment variables that are typically available
    common_env_vars = {
        'PATH', 'TEMP', 'TMP', 'USERPROFILE', 'USERNAME', 'COMPUTERNAME',
        'PROCESSOR_ARCHITECTURE', 'PROCESSOR_IDENTIFIER', 'ERRORLEVEL',
        'CD', 'DATE', 'TIME', 'RANDOM', 'CMDEXTVERSION', 'COMSPEC',
        'HOMEDRIVE', 'HOMEPATH', 'LOGONSERVER', 'NUMBER_OF_PROCESSORS',
        'OS', 'PATHEXT', 'PROGRAMFILES', 'SYSTEMDRIVE', 'SYSTEMROOT',
        'WINDIR', 'ALLUSERSPROFILE', 'APPDATA', 'LOCALAPPDATA',
        'PROGRAMDATA', 'PUBLIC'
    }
    set_vars.update(common_env_vars)

    return set_vars


def _check_syntax_errors(line: str, line_num: int, labels: Dict[str, int]) -> List[LintIssue]:
    """Check for syntax error level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # E002: Missing label for GOTO statement
    goto_match = re.match(r"goto\s+(:?\S+)", stripped, re.IGNORECASE)
    if goto_match:
        label_text: str = goto_match.group(1)
        target_label: str = label_text.lower()
        if not target_label.startswith(":"):
            target_label = ":" + target_label
        if target_label not in labels:
            issues.append(LintIssue(
                line_number=line_num,
                rule=RULES["E002"],
                context=f"GOTO points to non-existent label '{label_text}'"
            ))

    # E003: IF statement improper formatting
    if_match = re.match(r"if\s+[^=]+$", stripped, re.IGNORECASE)
    if (if_match and "exist" not in stripped.lower() and
            "defined" not in stripped.lower() and "==" not in stripped):
        issues.append(LintIssue(
            line_number=line_num,
            rule=RULES["E003"],
            context="IF statement appears to be missing comparison operator"
        ))

    # E004: IF EXIST syntax mixing
    if re.match(r"if\s+exist\s+.*==.*", stripped, re.IGNORECASE):
        issues.append(LintIssue(
            line_number=line_num,
            rule=RULES["E004"],
            context="Mixing IF EXIST with comparison operators"
        ))

    # E005: Invalid path syntax (basic check for invalid characters)
    path_patterns = [r'"([^"]*[<>|*?][^"]*)",', r"'([^']*[<>|*?][^']*)'"]
    for pattern in path_patterns:
        if re.search(pattern, stripped):
            issues.append(LintIssue(
                line_number=line_num,
                rule=RULES["E005"],
                context="Path contains invalid characters"
            ))
            break

    # E009: Mismatched quotes
    if line.count('"') % 2 != 0:
        issues.append(LintIssue(
            line_number=line_num,
            rule=RULES["E009"],
            context="Unmatched double quotes detected"
        ))

    # E010: Malformed FOR loop missing DO
    if re.match(r"for\s+.*", stripped, re.IGNORECASE) and " do " not in stripped.lower():
        issues.append(LintIssue(
            line_number=line_num,
            rule=RULES["E010"],
            context="FOR loop is missing required DO keyword"
        ))

    return issues


def _check_warning_issues(  # pylint: disable=unused-argument
        line: str, line_num: int, set_vars: Set[str],
        delayed_expansion_enabled: bool) -> List[LintIssue]:
    """Check for warning level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # W005: Unquoted variable with spaces
    unquoted_var_pattern = r'(?<!["\'])%[A-Z0-9_]+%|(?<!["\'])![A-Z0-9_]+!'
    if re.search(unquoted_var_pattern, stripped, re.IGNORECASE):
        # Check if it's in a context where spaces could be problematic
        if any(cmd in stripped.lower() for cmd in ['if', 'echo', 'set', 'call']):
            issues.append(LintIssue(
                line_number=line_num,
                rule=RULES["W005"],
                context="Variable may contain spaces and should be quoted"
            ))

    # W006: Network operation without timeout
    if re.match(r"ping\s+[^-]*$", stripped, re.IGNORECASE):
        issues.append(LintIssue(
            line_number=line_num,
            rule=RULES["W006"],
            context="PING command without timeout parameter"
        ))

    # W008: Permanent PATH modification
    if re.match(r"setx\s+path", stripped, re.IGNORECASE):
        issues.append(LintIssue(
            line_number=line_num,
            rule=RULES["W008"],
            context="SETX modifies PATH permanently"
        ))

    # W009: Windows version compatibility
    for cmd in OLDER_WINDOWS_COMMANDS:
        if re.match(rf"{cmd}\s", stripped, re.IGNORECASE):
            issues.append(LintIssue(
                line_number=line_num,
                rule=RULES["W009"],
                context=f"Command '{cmd}' may not be available on older Windows versions"
            ))
            break

    # W010: Architecture-specific operation
    for pattern in ARCHITECTURE_SPECIFIC_PATTERNS:
        if pattern in stripped:
            issues.append(LintIssue(
                line_number=line_num,
                rule=RULES["W010"],
                context=f"Architecture-specific reference: {pattern}"
            ))
            break

    # W011: Unicode handling issue
    for cmd in UNICODE_PROBLEMATIC_COMMANDS:
        if re.match(rf"{cmd}\s", stripped, re.IGNORECASE):
            issues.append(LintIssue(
                line_number=line_num,
                rule=RULES["W011"],
                context=f"Command '{cmd}' may have Unicode handling issues"
            ))
            break

    # W012: Non-ASCII characters detected
    if not all(ord(c) < 128 for c in stripped):
        issues.append(LintIssue(
            line_number=line_num,
            rule=RULES["W012"],
            context="Line contains non-ASCII characters"
        ))

    return issues


def _check_style_issues(line: str, line_num: int, file_lines: List[str]) -> List[LintIssue]:  # pylint: disable=unused-argument
    """Check for style level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # S003: Inconsistent command capitalization
    for keyword in COMMAND_CASING_KEYWORDS:
        pattern = rf"\b{keyword}\b"
        if re.search(pattern, stripped, re.IGNORECASE):
            # Check if it's not uppercase
            if not re.search(rf"\b{keyword.upper()}\b", stripped):
                issues.append(LintIssue(
                    line_number=line_num,
                    rule=RULES["S003"],
                    context=f"Command '{keyword}' should be uppercase for consistency"
                ))
            break

    # S004: Trailing whitespace
    if line.rstrip("\n") != line.rstrip():
        issues.append(LintIssue(
            line_number=line_num,
            rule=RULES["S004"],
            context="Line has trailing spaces or tabs"
        ))

    # S009: Magic numbers used (simple heuristic)
    number_patterns = [r"timeout\s+/t\s+(\d+)", r"ping\s+.*\s+-n\s+(\d+)"]
    for pattern in number_patterns:
        match = re.search(pattern, stripped, re.IGNORECASE)
        if match:
            number = match.group(1)
            if int(number) > 10:  # Only flag larger numbers
                issues.append(LintIssue(
                    line_number=line_num,
                    rule=RULES["S009"],
                    context=f"Magic number '{number}' should be defined as a variable"
                ))

    # S011: Line exceeds maximum length
    if len(line.rstrip("\n")) > 120:
        issues.append(LintIssue(
            line_number=line_num,
            rule=RULES["S011"],
            context=f"Line is {len(line.rstrip())} characters (max 120)"
        ))

    return issues


def _check_security_issues(line: str, line_num: int) -> List[LintIssue]:
    """Check for security level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # SEC001: Potential command injection vulnerability
    if re.search(r"set\s+/p\s+[^=]+=.*%.*%", stripped, re.IGNORECASE):
        issues.append(LintIssue(
            line_number=line_num,
            rule=RULES["SEC001"],
            context="User input used in command without validation"
        ))

    # SEC002: Unsafe SET command usage
    set_match = re.match(r"set\s+([A-Za-z0-9_]+)=(.+)", stripped, re.IGNORECASE)
    if set_match:
        var_val_text: str = set_match.group(2)
        var_val: str = var_val_text.strip()
        if not (var_val.startswith('"') and var_val.endswith('"')):
            issues.append(LintIssue(
                line_number=line_num,
                rule=RULES["SEC002"],
                context="SET command value should be quoted for safety"
            ))

    # SEC003: Dangerous command without confirmation
    for pattern, rule_code in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern, stripped, re.IGNORECASE):
            issues.append(LintIssue(
                line_number=line_num,
                rule=RULES[rule_code],
                context="Destructive command should have user confirmation"
            ))
            break

    # SEC004: Dangerous registry operation (covered by patterns above)

    # SEC005: Missing privilege check for admin operations
    admin_commands = ["reg add hklm", "reg delete hklm", "sc ", "net "]
    for cmd in admin_commands:
        if cmd in stripped.lower():
            issues.append(LintIssue(
                line_number=line_num,
                rule=RULES["SEC005"],
                context=f"Command '{cmd.strip()}' may require administrator privileges"
            ))
            break

    # SEC006: Hardcoded absolute path
    hardcoded_paths = [r"C:\\", r"D:\\", r"E:\\", r"/Users/", r"/home/"]
    for path_pattern in hardcoded_paths:
        if re.search(path_pattern, stripped):
            issues.append(LintIssue(
                line_number=line_num,
                rule=RULES["SEC006"],
                context="Hardcoded absolute path may not exist on other systems"
            ))
            break

    # SEC007: Hardcoded temporary directory
    temp_paths = [r"C:\\temp", r"C:\\tmp", r"/tmp"]
    for temp_path in temp_paths:
        if temp_path in stripped:
            issues.append(LintIssue(
                line_number=line_num,
                rule=RULES["SEC007"],
                context="Use %TEMP% instead of hardcoded temporary paths"
            ))
            break

    return issues


def _check_performance_issues(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        lines: List[str], line_num: int, line: str,  # pylint: disable=unused-argument
        has_setlocal: bool, has_set_commands: bool,
        has_delayed_expansion: bool, uses_delayed_vars: bool) -> List[LintIssue]:
    """Check for performance level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # P003: Unnecessary SETLOCAL
    if "setlocal" in stripped.lower() and not has_set_commands:
        issues.append(LintIssue(
            line_number=line_num,
            rule=RULES["P003"],
            context="SETLOCAL used without any SET commands"
        ))

    # P004: Unnecessary ENABLEDELAYEDEXPANSION
    if "enabledelayedexpansion" in stripped.lower() and not uses_delayed_vars:
        issues.append(LintIssue(
            line_number=line_num,
            rule=RULES["P004"],
            context="ENABLEDELAYEDEXPANSION used without !variables!"
        ))

    # P005: ENDLOCAL without SETLOCAL
    if "endlocal" in stripped.lower() and not has_setlocal:
        issues.append(LintIssue(
            line_number=line_num,
            rule=RULES["P005"],
            context="ENDLOCAL used without corresponding SETLOCAL"
        ))

    # P007: Temporary file without random name
    temp_patterns = [r"temp\.txt", r"tmp\.txt", r"temp\.log"]
    for pattern in temp_patterns:
        if re.search(pattern, stripped, re.IGNORECASE) and "random" not in stripped.lower():
            issues.append(LintIssue(
                line_number=line_num,
                rule=RULES["P007"],
                context="Temporary file should use %RANDOM% to prevent collisions"
            ))
            break

    # P008: Delayed expansion without enablement (moved from old delayed expansion check)
    if not has_delayed_expansion and re.search(r"![A-Z0-9_]+!", stripped, re.IGNORECASE):
        issues.append(LintIssue(
            line_number=line_num,
            rule=RULES["P008"],
            context="Delayed expansion variables used without ENABLEDELAYEDEXPANSION"
        ))

    return issues


def _check_undefined_variables(lines: List[str], set_vars: Set[str]) -> List[LintIssue]:
    """Check for usage of undefined variables."""
    issues: List[LintIssue] = []
    var_usage_pattern = re.compile(r"%([A-Z0-9_]+)%|!([A-Z0-9_]+)!", re.IGNORECASE)

    for i, line in enumerate(lines, start=1):
        for match in var_usage_pattern.finditer(line):
            var_match_1: Optional[str] = match.group(1)
            var_match_2: Optional[str] = match.group(2)
            var_name: str = (var_match_1 or var_match_2 or "").upper()
            if var_name not in set_vars:
                issues.append(LintIssue(
                    line_number=i,
                    rule=RULES["E006"],  # Undefined variable reference
                    context=f"Variable '{var_name}' is used but never defined"
                ))

    return issues


def lint_batch_file(file_path: str) -> List[LintIssue]:
    """Lint a batch file and return list of issues.

    Args:
        file_path: Path to the batch file (.bat or .cmd) to lint

    Returns:
        List of LintIssue objects containing detailed issue information

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

    issues: List[LintIssue] = []

    if not lines:
        return issues  # Empty file, no issues

    # Analyze script structure for context-aware checking
    has_setlocal = any("setlocal" in line.lower() for line in lines)
    has_set_commands = any(re.match(r"\s*set\s+[^=]+=.*", line, re.IGNORECASE) for line in lines)
    has_delayed_expansion = any(
        re.search(r"setlocal\s+enabledelayedexpansion", line, re.IGNORECASE) for line in lines
    )
    uses_delayed_vars = any(re.search(r"![A-Z0-9_]+!", line, re.IGNORECASE) for line in lines)

    # S001: Missing @ECHO OFF at file start
    if not lines[0].strip().lower().startswith("@echo off"):
        issues.append(LintIssue(
            line_number=1,
            rule=RULES["S001"],
            context="Script should start with @ECHO OFF"
        ))

    # S002: ECHO OFF without @ prefix
    first_line = lines[0].strip().lower()
    if first_line.startswith("echo off") and not first_line.startswith("@echo off"):
        issues.append(LintIssue(
            line_number=1,
            rule=RULES["S002"],
            context="Use @ECHO OFF instead of ECHO OFF"
        ))

    # S007: File extension recommendation
    if file_path.lower().endswith(".bat"):
        issues.append(LintIssue(
            line_number=1,
            rule=RULES["S007"],
            context="Consider using .cmd extension instead of .bat for scripts targeting Windows 2000 and newer"
        ))

    # Collect labels and check for duplicates
    labels, label_issues = _collect_labels(lines)
    issues.extend(label_issues)

    # Collect set variables for undefined variable checking
    set_vars = _collect_set_variables(lines)

    # Check each line with all rule categories
    for i, line in enumerate(lines, start=1):
        # Error level checks
        issues.extend(_check_syntax_errors(line, i, labels))

        # Warning level checks
        issues.extend(_check_warning_issues(line, i, set_vars, has_delayed_expansion))

        # Style level checks
        issues.extend(_check_style_issues(line, i, lines))

        # Security level checks
        issues.extend(_check_security_issues(line, i))

        # Performance level checks
        issues.extend(_check_performance_issues(lines, i, line, has_setlocal,
                                              has_set_commands, has_delayed_expansion,
                                              uses_delayed_vars))

    # Global checks (across all lines)
    issues.extend(_check_undefined_variables(lines, set_vars))

    # Check for unreachable code (E008)
    issues.extend(_check_unreachable_code(lines))

    # Check for redundant operations (P001)
    issues.extend(_check_redundant_operations(lines))

    # Check for code duplication (P002)
    issues.extend(_check_code_duplication(lines))

    return issues


def _check_unreachable_code(lines: List[str]) -> List[LintIssue]:
    """Check for unreachable code after EXIT or GOTO statements."""
    issues: List[LintIssue] = []

    for i, line in enumerate(lines):
        stripped = line.strip().lower()
        if re.match(r"(exit\s|goto\s)", stripped):
            # Check if there's executable code after this line (not just labels or comments)
            for j in range(i + 1, len(lines)):
                next_line = lines[j].strip()
                if next_line and not next_line.startswith(":") and not next_line.startswith("rem"):
                    issues.append(LintIssue(
                        line_number=j + 1,
                        rule=RULES["E008"],
                        context=f"Code after {stripped.split()[0].upper()} on "
                                f"line {i + 1} will never execute"
                    ))
                    break

    return issues


def _check_redundant_operations(lines: List[str]) -> List[LintIssue]:
    """Check for redundant file operations."""
    issues: List[LintIssue] = []

    for i, line in enumerate(lines):
        stripped = line.strip().lower()
        # Look for repeated IF EXIST checks on the same file
        exist_match = re.search(r"if\s+exist\s+(\S+)", stripped)
        if exist_match:
            filename = exist_match.group(1)
            # Check subsequent lines for same file
            for j in range(i + 1, min(i + 5, len(lines))):
                next_stripped = lines[j].strip().lower()
                if f"if exist {filename}" in next_stripped:
                    issues.append(LintIssue(
                        line_number=j + 1,
                        rule=RULES["P001"],
                        context=f"Redundant existence check for {filename} "
                                f"(first check on line {i + 1})"
                    ))
                    break

    return issues


def _check_code_duplication(lines: List[str]) -> List[LintIssue]:
    """Check for code duplication that could be refactored."""
    issues: List[LintIssue] = []

    # Simple heuristic: look for repeated command patterns
    command_blocks: Dict[str, List[int]] = defaultdict(list)

    for i, line in enumerate(lines):
        stripped = line.strip().lower()
        if stripped and not stripped.startswith(":") and not stripped.startswith("rem"):
            # Normalize the command for comparison
            normalized = re.sub(r"\S+\.(txt|log|bat|cmd)", "FILE", stripped)
            normalized = re.sub(r"%\w+%", "VAR", normalized)

            if len(normalized) > 20:  # Only consider substantial commands
                command_blocks[normalized].append(i + 1)

    for _normalized_cmd, line_numbers in command_blocks.items():
        if len(line_numbers) > 2:  # Found 3+ similar commands
            for line_num in line_numbers[1:]:  # Flag all but the first
                issues.append(LintIssue(
                    line_number=line_num,
                    rule=RULES["P002"],
                    context=f"Similar command pattern repeated (also on lines {line_numbers[0]})"
                ))

    return issues


def group_issues(issues: List[LintIssue]) -> DefaultDict[RuleSeverity, List[LintIssue]]:
    """Group issues by severity level.

    Args:
        issues: List of LintIssue objects

    Returns:
        Dictionary mapping severity levels to lists of issues
    """
    grouped: DefaultDict[RuleSeverity, List[LintIssue]] = defaultdict(list)
    for issue in issues:
        grouped[issue.rule.severity].append(issue)
    return grouped


def print_summary(issues: List[LintIssue]) -> None:
    """Print summary statistics of linting issues.

    Args:
        issues: List of LintIssue objects
    """
    total_issues = len(issues)

    # Group by rule for most common error
    rule_counts: DefaultDict[str, int] = defaultdict(int)
    for issue in issues:
        rule_counts[issue.rule.code] += 1

    most_common_rule: Tuple[str, int] = ("", 0)
    if rule_counts:
        max_count = 0
        max_rule = ""
        for rule_code, count in rule_counts.items():
            if count > max_count:
                max_count = count
                max_rule = rule_code
        most_common_rule = (max_rule, max_count)

    # Count by severity
    severity_counts: DefaultDict[RuleSeverity, int] = defaultdict(int)
    for issue in issues:
        severity_counts[issue.rule.severity] += 1

    print("\nSUMMARY:")
    print(f"Total issues: {total_issues}")
    if most_common_rule[0]:
        most_common_rule_obj = RULES[most_common_rule[0]]
        print(f"Most common issue: '{most_common_rule_obj.name}' "
              f"({most_common_rule[0]}) - {most_common_rule[1]} occurrences")
    else:
        print("No issues found")

    print("\nIssues by severity:")
    severity_order = [RuleSeverity.ERROR, RuleSeverity.WARNING, RuleSeverity.STYLE,
                     RuleSeverity.SECURITY, RuleSeverity.PERFORMANCE]
    for severity in severity_order:
        count = severity_counts.get(severity, 0)
        if count > 0:
            print(f"  {severity.value}: {count}")


def print_detailed(issues: List[LintIssue]) -> None:
    """Print detailed issue information in the new format.

    Args:
        issues: List of LintIssue objects
    """
    if not issues:
        print("\nDETAILED ISSUES:")
        print("----------------")
        print("No issues found! ?\n")
        return

    # Group by severity
    grouped = group_issues(issues)

    print("\nDETAILED ISSUES:")
    print("----------------")

    severity_order = [RuleSeverity.ERROR, RuleSeverity.WARNING, RuleSeverity.STYLE,
                     RuleSeverity.SECURITY, RuleSeverity.PERFORMANCE]

    for severity in severity_order:
        if severity not in grouped:
            continue

        severity_issues = grouped[severity]
        print(f"\n{severity.value.upper()} LEVEL ISSUES:")
        print("=" * (len(severity.value) + 14))

        # Group by rule within severity
        rule_groups: DefaultDict[str, List[LintIssue]] = defaultdict(list)
        for issue in severity_issues:
            rule_groups[issue.rule.code].append(issue)

        for rule_code in sorted(rule_groups.keys()):
            rule_issues = rule_groups[rule_code]
            rule = rule_issues[0].rule
            line_numbers = sorted([issue.line_number for issue in rule_issues])

            print(f"\nLine {', '.join(map(str, line_numbers))}: {rule.name} ({rule_code})")
            print(f"- Explanation: {rule.explanation}")
            print(f"- Recommendation: {rule.recommendation}")

            # Add context if available
            contexts = [issue.context for issue in rule_issues if issue.context]
            if contexts:
                # Remove duplicates while preserving order
                unique_contexts: List[str] = []
                seen: Set[str] = set()
                for context in contexts:
                    if context not in seen:
                        unique_contexts.append(context)
                        seen.add(context)
                for context in unique_contexts:
                    print(f"- Context: {context}")

        print()  # Extra spacing between severity levels


def print_severity_info(issues: List[LintIssue]) -> None:
    """Print severity level information.

    Args:
        issues: List of LintIssue objects
    """
    severity_counts: DefaultDict[RuleSeverity, int] = defaultdict(int)
    for issue in issues:
        severity_counts[issue.rule.severity] += 1

    descriptions: Dict[RuleSeverity, str] = {
        RuleSeverity.ERROR: "Critical issues that will cause script failure or incorrect behavior.",
        RuleSeverity.WARNING: "Issues that may cause problems or unexpected behavior.",
        RuleSeverity.STYLE: "Code style and formatting issues that affect readability.",
        RuleSeverity.SECURITY: "Security vulnerabilities and potential risks.",
        RuleSeverity.PERFORMANCE: "Performance issues and optimization opportunities.",
    }

    print("\nSEVERITY BREAKDOWN:")
    print("====================")

    severity_order = [RuleSeverity.ERROR, RuleSeverity.WARNING, RuleSeverity.STYLE,
                     RuleSeverity.SECURITY, RuleSeverity.PERFORMANCE]

    for severity in severity_order:
        count = severity_counts.get(severity, 0)
        if count == 0:
            continue
        issue_word = "issue" if count == 1 else "issues"
        print(f"\n{severity.value}: {count} {issue_word}")
        print(f"  {descriptions.get(severity, 'No description available.')}")


def main() -> None:  # pylint: disable=too-many-branches
    """Main entry point for the blint application."""
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print_help()
        return

    batch_file: Optional[str] = None
    show_summary = False

    for arg in sys.argv[1:]:
        if arg.lower().endswith((".bat", ".cmd")):
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

    # Display results in new format
    print(f"\n?? Batch File Analysis: {batch_file}")
    print("=" * (25 + len(batch_file)))

    print_detailed(issues)

    if show_summary:
        print_summary(issues)

    print_severity_info(issues)

    # Exit with appropriate code
    error_count = sum(1 for issue in issues if issue.rule.severity == RuleSeverity.ERROR)
    if error_count > 0:
        print(f"\n??  Found {error_count} critical "
              f"error{'s' if error_count != 1 else ''} that must be fixed.")
        sys.exit(1)
    elif issues:
        print(f"\n? No critical errors found, but {len(issues)} "
              f"issue{'s' if len(issues) != 1 else ''} detected.")
        sys.exit(0)
    else:
        print("\n?? No issues found! Your batch file looks great!")
        sys.exit(0)


if __name__ == "__main__":
    main()
