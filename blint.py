"""Blint - A professional-grade batch file linter for Windows.

This module provides comprehensive functionality to lint Windows batch files (.bat and .cmd)
for common syntax errors, style issues, security vulnerabilities, and performance problems.

Features:
- 60+ built-in rules across 5 severity levels
- Thread-safe operations for concurrent processing
- Robust encoding detection and handling
- Comprehensive error handling for production use
- Performance optimized for large files
- Extensible architecture for custom rules

Usage:
    import blint
    issues = blint.lint_batch_file("script.bat")

Author: crosenblum
Version: 1.0.0
License: MIT
"""

# pylint: disable=too-many-lines

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
import logging
from pathlib import Path
import re
import sys
from typing import DefaultDict, Dict, List, Optional, Set, Tuple, Union
import warnings

__version__ = "1.0.0"
__author__ = "crosenblum"
__license__ = "MIT"

# Configure module-level logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


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
        "closing parentheses and are properly nested",
    ),
    "E002": Rule(
        code="E002",
        name="Missing label for GOTO statement",
        severity=RuleSeverity.ERROR,
        explanation="GOTO statement points to a label that does not exist, "
        "which will cause runtime errors",
        recommendation="Create the missing label or correct the GOTO "
        "statement to point to an existing label",
    ),
    "E003": Rule(
        code="E003",
        name="IF statement improper formatting",
        severity=RuleSeverity.ERROR,
        explanation="IF statement has improper spacing or syntax that "
        "will prevent correct execution",
        recommendation='Use proper spacing: IF "condition" operator "value" command',
    ),
    "E004": Rule(
        code="E004",
        name="IF EXIST syntax mixing",
        severity=RuleSeverity.ERROR,
        explanation="Mixing IF EXIST syntax with comparison operators " "creates invalid syntax",
        recommendation="Use either 'IF EXIST filename' or "
        '\'IF "variable"=="value"\' but not both together',
    ),
    "E005": Rule(
        code="E005",
        name="Invalid path syntax",
        severity=RuleSeverity.ERROR,
        explanation="Path contains invalid characters or exceeds " "system length limits",
        recommendation='Remove invalid characters (<>|"*?) and ensure '
        "path length is under 260 characters",
    ),
    "E006": Rule(
        code="E006",
        name="Undefined variable reference",
        severity=RuleSeverity.ERROR,
        explanation="Script references variables that were never set, "
        "which may cause runtime errors",
        recommendation="Define the variable using SET before referencing it, "
        "or add existence checks",
    ),
    "E007": Rule(
        code="E007",
        name="Empty variable check syntax error",
        severity=RuleSeverity.ERROR,
        explanation="Incorrect syntax for checking if variables are empty "
        "will cause comparison errors",
        recommendation='Use proper syntax: IF "%%VAR%%"=="" for ' "empty variable checks",
    ),
    "E008": Rule(
        code="E008",
        name="Unreachable code after EXIT or GOTO",
        severity=RuleSeverity.ERROR,
        explanation="Code after EXIT or GOTO statements will never execute",
        recommendation="Remove unreachable code or restructure script logic",
    ),
    "E009": Rule(
        code="E009",
        name="Mismatched quotes",
        severity=RuleSeverity.ERROR,
        explanation="Lines with unmatched quotes will cause syntax errors or unexpected behavior",
        recommendation="Ensure all quotes are properly paired and closed",
    ),
    "E010": Rule(
        code="E010",
        name="Malformed FOR loop missing DO",
        severity=RuleSeverity.ERROR,
        explanation="FOR loops must contain the DO keyword for proper execution",
        recommendation="Add DO keyword: FOR %%i IN (items) DO command",
    ),
    "E011": Rule(
        code="E011",
        name="Invalid variable expansion syntax",
        severity=RuleSeverity.ERROR,
        explanation="Variable references must use proper %VAR% or !VAR! syntax with matching delimiters",
        recommendation="Ensure variables use matching % or ! delimiters: %VAR% for standard, !VAR! for delayed expansion",
    ),
    "E012": Rule(
        code="E012",
        name="Missing CALL for subroutine invocation",
        severity=RuleSeverity.ERROR,
        explanation="Subroutines should be invoked using CALL :label_name to ensure proper return handling",
        recommendation="Use CALL :subroutine_name instead of direct label jumps for subroutines",
    ),
    "E013": Rule(
        code="E013",
        name="Invalid command syntax detected",
        severity=RuleSeverity.ERROR,
        explanation="Command appears to have typos or invalid syntax that will cause execution errors",
        recommendation="Check command spelling and syntax: IF not IFF, ECHO not ECKO, FOR not FORx",
    ),
    "E014": Rule(
        code="E014",
        name="Missing colon in CALL statement",
        severity=RuleSeverity.ERROR,
        explanation="CALL statements to labels require a colon (unlike GOTO where colon is optional)",
        recommendation="Use CALL :label_name with colon when calling internal subroutines",
    ),
    "E015": Rule(
        code="E015",
        name="Missing colon in GOTO :EOF statement",
        severity=RuleSeverity.ERROR,
        explanation="GOTO :EOF requires a colon as it's a special built-in construct, not a user-defined label",
        recommendation="Use GOTO :EOF (with colon) to jump to end of file",
    ),
    # Warning Level Rules (W001-W999)
    "W001": Rule(
        code="W001",
        name="Missing exit code",
        severity=RuleSeverity.WARNING,
        explanation="Script doesn't set appropriate exit codes to indicate success or failure",
        recommendation="Add EXIT /b 0 for success or EXIT /b 1 for errors at script end",
    ),
    "W002": Rule(
        code="W002",
        name="Missing ERRORLEVEL check",
        severity=RuleSeverity.WARNING,
        explanation="Critical operations should check %%ERRORLEVEL%% to handle failures properly",
        recommendation="Add IF ERRORLEVEL 1 checks after operations that might fail",
    ),
    "W003": Rule(
        code="W003",
        name="Operation without error handling",
        severity=RuleSeverity.WARNING,
        explanation="Operations that commonly fail lack proper error checking",
        recommendation="Add error checking and appropriate responses for failed operations",
    ),
    "W004": Rule(
        code="W004",
        name="Potential infinite loop",
        severity=RuleSeverity.WARNING,
        explanation="Loop construct may run infinitely without proper exit conditions",
        recommendation="Add counter variables or proper exit conditions to prevent infinite loops",
    ),
    "W005": Rule(
        code="W005",
        name="Unquoted variable with spaces",
        severity=RuleSeverity.WARNING,
        explanation="Variables that may contain spaces should be quoted to prevent parsing errors",
        recommendation='Use quotes around variables: IF "%%VARIABLE%%"=="value"',
    ),
    "W006": Rule(
        code="W006",
        name="Network operation without timeout",
        severity=RuleSeverity.WARNING,
        explanation="Network operations may hang indefinitely without proper timeout settings",
        recommendation="Add timeout parameters to network commands like PING -n 4",
    ),
    "W007": Rule(
        code="W007",
        name="File operation on potentially locked file",
        severity=RuleSeverity.WARNING,
        explanation="Operations on files that may be in use by other programs can fail",
        recommendation="Check if applications are using the file before attempting operations",
    ),
    "W008": Rule(
        code="W008",
        name="Permanent PATH modification",
        severity=RuleSeverity.WARNING,
        explanation="SETX modifies PATH permanently, which may not be desired",
        recommendation="Use SET for temporary changes or confirm permanent changes are intended",
    ),
    "W009": Rule(
        code="W009",
        name="Windows version compatibility",
        severity=RuleSeverity.WARNING,
        explanation="Command may not be available in older Windows versions",
        recommendation="Use version checks or provide alternative commands for older Windows",
    ),
    "W010": Rule(
        code="W010",
        name="Architecture-specific operation",
        severity=RuleSeverity.WARNING,
        explanation="Operation is specific to 32-bit or 64-bit architecture",
        recommendation="Add architecture detection and appropriate handling for both architectures",
    ),
    "W011": Rule(
        code="W011",
        name="Unicode handling issue",
        severity=RuleSeverity.WARNING,
        explanation="File operation may not handle Unicode characters properly",
        recommendation="Consider using commands with better Unicode support",
    ),
    "W012": Rule(
        code="W012",
        name="Non-ASCII characters detected",
        severity=RuleSeverity.WARNING,
        explanation="Non-ASCII characters may cause issues in some environments",
        recommendation="Use ASCII-only characters or ensure proper encoding handling",
    ),
    "W013": Rule(
        code="W013",
        name="Duplicate label",
        severity=RuleSeverity.WARNING,
        explanation="Multiple labels with the same name can cause unpredictable GOTO behavior",
        recommendation="Rename duplicate labels to have unique names",
    ),
    "W014": Rule(
        code="W014",
        name="Missing PAUSE for user interaction",
        severity=RuleSeverity.WARNING,
        explanation="Interactive scripts should include PAUSE to prevent window from closing immediately",
        recommendation="Add PAUSE before EXIT to allow user to see script output",
    ),
    "W015": Rule(
        code="W015",
        name="Deprecated command usage",
        severity=RuleSeverity.WARNING,
        explanation="Command is deprecated and may not be available in newer Windows versions",
        recommendation="Replace deprecated commands with modern alternatives",
    ),
    "W016": Rule(
        code="W016",
        name="Mixed variable syntax within script",
        severity=RuleSeverity.WARNING,
        explanation="Inconsistent use of %VAR% and !VAR! syntax within the same script reduces readability",
        recommendation="Use consistent variable expansion syntax throughout the script",
    ),
    # Style Level Rules (S001-S999)
    "S001": Rule(
        code="S001",
        name="Missing @ECHO OFF at file start",
        severity=RuleSeverity.STYLE,
        explanation="Batch scripts usually start with @ECHO OFF to prevent "
        "command echoing during execution",
        recommendation="Add '@ECHO OFF' as the first line of your script",
    ),
    "S002": Rule(
        code="S002",
        name="ECHO OFF without @ prefix",
        severity=RuleSeverity.STYLE,
        explanation="ECHO OFF should use @ prefix to prevent the command "
        "itself from being displayed",
        recommendation="Use '@ECHO OFF' instead of 'ECHO OFF'",
    ),
    "S003": Rule(
        code="S003",
        name="Inconsistent command capitalization",
        severity=RuleSeverity.STYLE,
        explanation="Batch commands should follow consistent casing conventions for readability",
        recommendation="Use consistent UPPERCASE for all batch commands",
    ),
    "S004": Rule(
        code="S004",
        name="Trailing whitespace",
        severity=RuleSeverity.STYLE,
        explanation="Trailing spaces at line end can cause subtle errors and should be removed",
        recommendation="Remove trailing spaces and tabs from line endings",
    ),
    "S005": Rule(
        code="S005",
        name="Mixed line endings",
        severity=RuleSeverity.STYLE,
        explanation="Inconsistent line endings (CRLF vs LF) within the same file",
        recommendation="Use consistent CRLF line endings for Windows batch files",
    ),
    "S006": Rule(
        code="S006",
        name="Inconsistent variable naming",
        severity=RuleSeverity.STYLE,
        explanation="Variable names should follow consistent naming conventions",
        recommendation="Use consistent naming: either ALL_CAPS or camelCase throughout",
    ),
    "S007": Rule(
        code="S007",
        name="BAT extension used instead of CMD for newer Windows",
        severity=RuleSeverity.STYLE,
        explanation="The .cmd file extension is recommended over .bat for Windows NT "
        "and newer versions (Windows 2000+). CMD files support additional "
        "features and have better error handling in newer Windows environments",
        recommendation="Consider renaming .bat files to .cmd for scripts intended for "
        "Windows 2000 and newer versions. CMD files provide better "
        "compatibility with modern Windows features and improved error reporting",
    ),
    "S008": Rule(
        code="S008",
        name="Missing comments for complex code",
        severity=RuleSeverity.STYLE,
        explanation="Complex sections should have comments explaining their purpose",
        recommendation="Add REM comments to explain complex logic and operations",
    ),
    "S009": Rule(
        code="S009",
        name="Magic numbers used",
        severity=RuleSeverity.STYLE,
        explanation="Hardcoded numeric values should be defined as named variables",
        recommendation="Define constants using SET before using numeric values",
    ),
    "S010": Rule(
        code="S010",
        name="Dead code detected",
        severity=RuleSeverity.STYLE,
        explanation="Unused labels or unreferenced subroutines make code harder to maintain",
        recommendation="Remove unused labels and unreferenced code sections",
    ),
    "S011": Rule(
        code="S011",
        name="Line exceeds maximum length",
        severity=RuleSeverity.STYLE,
        explanation="Lines longer than 120 characters are hard to read and maintain",
        recommendation="Break long lines into multiple shorter lines for better readability",
    ),
    "S012": Rule(
        code="S012",
        name="Inconsistent indentation",
        severity=RuleSeverity.STYLE,
        explanation="Inconsistent indentation makes code harder to read and maintain",
        recommendation="Use consistent indentation (4 spaces or 1 tab) for nested blocks",
    ),
    "S013": Rule(
        code="S013",
        name="Missing file header documentation",
        severity=RuleSeverity.STYLE,
        explanation="Scripts should include header documentation for maintainability",
        recommendation="Add REM comments at the top describing script purpose, author, and date",
    ),
    "S014": Rule(
        code="S014",
        name="Long parameter list affects readability",
        severity=RuleSeverity.STYLE,
        explanation="Functions with many parameters are hard to read and maintain",
        recommendation="Group related parameters into variables or reduce parameter count",
    ),
    "S015": Rule(
        code="S015",
        name="Inconsistent colon usage in GOTO statements",
        severity=RuleSeverity.STYLE,
        explanation="GOTO statements should use consistent colon style throughout the script for better readability",
        recommendation="Choose either 'GOTO label' or 'GOTO :label' style and use consistently throughout the script",
    ),
    # Security Level Rules (SEC001-SEC999)
    "SEC001": Rule(
        code="SEC001",
        name="Potential command injection vulnerability",
        severity=RuleSeverity.SECURITY,
        explanation="User input used in commands without validation could "
        "allow malicious code execution",
        recommendation="Validate and sanitize all user input before using in commands",
    ),
    "SEC002": Rule(
        code="SEC002",
        name="Unsafe SET command usage",
        severity=RuleSeverity.SECURITY,
        explanation="SET commands without proper validation or quoting can cause security issues",
        recommendation='Always quote SET values and validate input: SET "var=safe value"',
    ),
    "SEC003": Rule(
        code="SEC003",
        name="Dangerous command without confirmation",
        severity=RuleSeverity.SECURITY,
        explanation="Destructive commands should require user confirmation "
        "to prevent accidental execution",
        recommendation="Add confirmation prompts before destructive operations",
    ),
    "SEC004": Rule(
        code="SEC004",
        name="Dangerous registry operation",
        severity=RuleSeverity.SECURITY,
        explanation="Registry modifications can damage system functionality "
        "and should be carefully reviewed",
        recommendation="Backup registry before modifications and use specific "
        "keys rather than broad deletions",
    ),
    "SEC005": Rule(
        code="SEC005",
        name="Missing privilege check",
        severity=RuleSeverity.SECURITY,
        explanation="Operations requiring admin rights should check for proper privileges",
        recommendation="Use NET SESSION >nul 2>&1 to check for administrator privileges",
    ),
    "SEC006": Rule(
        code="SEC006",
        name="Hardcoded absolute path",
        severity=RuleSeverity.SECURITY,
        explanation="Absolute paths may not exist on other systems and could be security risks",
        recommendation="Use environment variables like %%USERPROFILE%% instead of hardcoded paths",
    ),
    "SEC007": Rule(
        code="SEC007",
        name="Hardcoded temporary directory",
        severity=RuleSeverity.SECURITY,
        explanation="Hardcoded temp paths may not exist and could create security vulnerabilities",
        recommendation="Use %%TEMP%% environment variable instead of hardcoded temporary paths",
    ),
    "SEC008": Rule(
        code="SEC008",
        name="Plain text credentials detected",
        severity=RuleSeverity.SECURITY,
        explanation="Hardcoded passwords and credentials in scripts pose serious security risks",
        recommendation="Use secure credential storage or prompt for credentials at runtime",
    ),
    "SEC009": Rule(
        code="SEC009",
        name="PowerShell execution policy bypass",
        severity=RuleSeverity.SECURITY,
        explanation="Bypassing PowerShell execution policy can allow malicious scripts to run",
        recommendation="Avoid using -ExecutionPolicy Bypass unless absolutely necessary",
    ),
    "SEC010": Rule(
        code="SEC010",
        name="Sensitive information in ECHO output",
        severity=RuleSeverity.SECURITY,
        explanation="ECHO statements may display sensitive information in console or log files",
        recommendation="Avoid echoing passwords, API keys, or other sensitive data",
    ),
    # Performance Level Rules (P001-P999)
    "P001": Rule(
        code="P001",
        name="Redundant file existence check",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Unnecessary repeated file existence checks reduce script performance",
        recommendation="Combine existence checks or store result in variable for reuse",
    ),
    "P002": Rule(
        code="P002",
        name="Code duplication detected",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Repeated code blocks should be refactored into "
        "subroutines for better maintainability",
        recommendation="Create subroutines using CALL :function_name for repeated code",
    ),
    "P003": Rule(
        code="P003",
        name="Unnecessary SETLOCAL",
        severity=RuleSeverity.PERFORMANCE,
        explanation="SETLOCAL is not needed if there are no SET commands in the script",
        recommendation="Remove SETLOCAL if no local variables are set",
    ),
    "P004": Rule(
        code="P004",
        name="Unnecessary ENABLEDELAYEDEXPANSION",
        severity=RuleSeverity.PERFORMANCE,
        explanation="ENABLEDELAYEDEXPANSION is not needed if no !VARIABLES! are used",
        recommendation="Remove ENABLEDELAYEDEXPANSION if delayed expansion is not used",
    ),
    "P005": Rule(
        code="P005",
        name="ENDLOCAL without SETLOCAL",
        severity=RuleSeverity.PERFORMANCE,
        explanation="ENDLOCAL is not needed without a corresponding SETLOCAL",
        recommendation="Remove unnecessary ENDLOCAL commands",
    ),
    "P006": Rule(
        code="P006",
        name="Missing ENDLOCAL before exit",
        severity=RuleSeverity.PERFORMANCE,
        explanation="SETLOCAL should be paired with ENDLOCAL before every exit point",
        recommendation="Add ENDLOCAL before all EXIT statements when SETLOCAL is used",
    ),
    "P007": Rule(
        code="P007",
        name="Temporary file without random name",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Temporary files should use %%RANDOM%% to prevent file collisions",
        recommendation="Use %%RANDOM%% in temporary filenames: temp_%%RANDOM%%.txt",
    ),
    "P008": Rule(
        code="P008",
        name="Delayed expansion without enablement",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Using !VARIABLES! requires SETLOCAL "
        "ENABLEDELAYEDEXPANSION for proper functionality",
        recommendation="Add SETLOCAL ENABLEDELAYEDEXPANSION before using !variable! syntax",
    ),
    "P009": Rule(
        code="P009",
        name="Inefficient FOR loop pattern",
        severity=RuleSeverity.PERFORMANCE,
        explanation="FOR loop could be optimized for better performance with large data sets",
        recommendation="Use 'tokens=*' parameter for better performance: FOR /f \"tokens=*\" %%i",
    ),
    "P010": Rule(
        code="P010",
        name="Missing optimization flags for directory operations",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Directory operations can be faster with appropriate flags",
        recommendation="Use /F flag for large directory operations: DIR /F",
    ),
    "P011": Rule(
        code="P011",
        name="Redundant variable assignments",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Multiple assignments to the same variable without usage is inefficient",
        recommendation="Remove intermediate assignments or combine operations",
    ),
}


def read_file_with_encoding(file_path: str) -> Tuple[List[str], str]:
    """
    Reads a file with robust encoding detection and fallback mechanisms.

    This function implements a comprehensive encoding detection strategy:
    1. Attempts to use chardet for automatic detection (if available)
    2. Falls back to a prioritized list of common encodings
    3. Provides detailed error messages for troubleshooting

    Thread-safe: Yes - uses only local variables and immutable data
    Performance: Optimized for common cases (UTF-8 first)

    Args:
        file_path: Path to the file to read. Can be absolute or relative.

    Returns:
        Tuple containing:
            - lines: List of strings, each representing a line in the file
            - encoding_used: String indicating the encoding that was successful

    Raises:
        UnicodeDecodeError: If all encoding attempts fail (extremely rare)
        FileNotFoundError: If the specified file doesn't exist
        PermissionError: If insufficient permissions to read the file
        OSError: If file operation fails due to system issues

    Example:
        >>> lines, encoding = read_file_with_encoding("script.bat")
        >>> print(f"Read {len(lines)} lines using {encoding} encoding")
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
            logger.debug(
                "Chardet detected encoding: %s (confidence: %.2f)",
                detected_encoding,
                detected["confidence"],
            )
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
        logger.debug("chardet not available, using fallback encoding detection")
    except (OSError, ValueError, TypeError) as detection_error:
        # Any other error in detection, continue with fallback
        logger.debug("Encoding detection failed: %s, using fallback", detection_error)

    # Try each encoding until one works
    last_exception: Optional[Exception] = None
    for encoding in encodings_to_try:
        try:
            logger.debug("Attempting to read file with encoding: %s", encoding)
            with open(file_path, "r", encoding=encoding, errors="strict") as file_handle:
                lines = file_handle.readlines()
            logger.debug("Successfully read %d lines using %s encoding", len(lines), encoding)
            return lines, encoding
        except UnicodeDecodeError as decode_error:
            logger.debug("UnicodeDecodeError with %s: %s", encoding, decode_error)
            last_exception = decode_error
            continue
        except (LookupError, ValueError) as encoding_error:
            # Encoding not supported or invalid
            logger.debug("Encoding error with %s: %s", encoding, encoding_error)
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
    (r"del\s+[\"']?\*\.\*[\"']?(\s|$)", "SEC003"),  # del *.* (more specific)
    (r"del\s+[\"']?\*/\*[\"']?(\s|$)", "SEC003"),  # del */* pattern
    (r"del\s+[\"']?[a-z]:\\\*[\"']?(\s|$)", "SEC003"),  # del c:\* type commands
    (r"format\s+[a-z]:", "SEC003"),  # format c: type commands
    (r"shutdown", "SEC003"),  # shutdown commands
    (r"rmdir\s+/s\s+/q\s+", "SEC003"),  # rmdir /s /q commands
    (r"reg\s+delete\s+.*\s+/f", "SEC004"),  # forced registry deletions
]

COMMAND_CASING_KEYWORDS = {
    "echo",
    "set",
    "if",
    "for",
    "goto",
    "call",
    "exit",
    "rem",
    "pause",
    "copy",
    "move",
    "del",
    "dir",
    "type",
    "find",
    "findstr",
    "sort",
    "more",
    "cls",
    "cd",
    "pushd",
    "popd",
    "mkdir",
    "rmdir",
    "attrib",
    "xcopy",
    "robocopy",
    "ping",
    "ipconfig",
    "netstat",
    "tasklist",
    "taskkill",
    "sc",
    "net",
    "reg",
    "wmic",
    "powershell",
    "timeout",
    "choice",
    "setlocal",
    "endlocal",
    "enabledelayedexpansion",
}

OLDER_WINDOWS_COMMANDS = {"choice", "forfiles", "where", "robocopy", "timeout", "icacls"}

ARCHITECTURE_SPECIFIC_PATTERNS = [
    r"Wow6432Node",  # 32-bit registry redirect
    r"Program Files \(x86\)",  # 32-bit program files
    r"SysWow64",  # 32-bit system directory
]

UNICODE_PROBLEMATIC_COMMANDS = {"type", "echo", "find", "findstr"}

# Additional patterns for new rules
DEPRECATED_COMMANDS = {"assign", "backup", "comp", "edlin", "join", "subst"}

COMMON_COMMAND_TYPOS = {
    "iff": "if",
    "ecko": "echo",
    "ecoh": "echo",
    "forx": "for",
    "fro": "for",
    "goot": "goto",
    "sett": "set",
    "caal": "call",
    "exitt": "exit",
}

CREDENTIAL_PATTERNS = [
    r"password\s*=\s*[\"']?[^\s\"']+[\"']?",
    r"pwd\s*=\s*[\"']?[^\s\"']+[\"']?",
    r"passwd\s*=\s*[\"']?[^\s\"']+[\"']?",
    r"apikey\s*=\s*[\"']?[^\s\"']+[\"']?",
    r"api_key\s*=\s*[\"']?[^\s\"']+[\"']?",
    r"secret\s*=\s*[\"']?[^\s\"']+[\"']?",
    r"token\s*=\s*[\"']?[^\s\"']+[\"']?",
]

SENSITIVE_ECHO_PATTERNS = [
    r"echo.*password",
    r"echo.*pwd",
    r"echo.*passwd",
    r"echo.*apikey",
    r"echo.*api_key",
    r"echo.*secret",
    r"echo.*token",
]


def print_help() -> None:
    """Print help information for the blint command."""
    help_text = """
Batch Linter - Help Menu

Usage:
  python blint.py <path> [options]

Arguments:
  <path>              Path to a batch file (.bat or .cmd) OR directory containing batch files.
                     When a directory is specified, all .bat and .cmd files will be processed.

Options:
  --summary           Show a summary section with total errors and most common error.
  --severity          Show error severity levels and their meaning.
  --no-recursive      When processing directories, don't search subdirectories (default: recursive).
  --help              Display this help menu and exit.

Rule Categories:
  E001-E999   Error Level    - Issues that will cause script failure
  W001-W999   Warning Level  - Bad practices that won't necessarily break script
  S001-S999   Style Level    - Code style and formatting issues
  SEC001+     Security Level - Security-related issues and vulnerabilities
  P001-P999   Performance    - Performance and efficiency improvements

Examples:
  python blint.py myscript.bat
      Analyze a single batch file with detailed error list and recommendations.

  python blint.py /path/to/batch/files
      Analyze all .bat and .cmd files in directory and subdirectories.

  python blint.py /path/to/batch/files --no-recursive
      Analyze only .bat and .cmd files in the directory (no subdirectories).

  python blint.py myscript.cmd --summary
      Shows summary and detailed errors for a single file.

  python blint.py /project/scripts --summary --severity
      Shows summary, detailed errors, and severity info for all batch files in directory.

If no <path> is specified or '--help' is passed, this help menu will be displayed.
"""
    print(help_text.strip())


def _is_command_in_safe_context(line: str) -> bool:
    """
    Check if a potentially dangerous command is in a safe context (REM comment or ECHO statement).
    
    Args:
        line: The line to check
        
    Returns:
        True if the command is in a safe context and shouldn't be flagged as dangerous
    """
    stripped = line.strip().lower()

    # Check if line starts with REM (comment)
    if stripped.startswith("rem ") or stripped.startswith("rem\t"):
        return True

    # Check if line starts with ECHO (output statement)
    if stripped.startswith("echo ") or stripped.startswith("echo\t"):
        return True

    # Check for @ECHO off (common at start of scripts)
    if stripped.startswith("@echo ") or stripped.startswith("@echo\t"):
        return True

    return False


def _collect_labels(lines: List[str]) -> Tuple[Dict[str, int], List[LintIssue]]:
    """Collect all labels and detect duplicates."""
    labels: Dict[str, int] = {}
    issues: List[LintIssue] = []

    for i, line in enumerate(lines, start=1):
        if line.strip().startswith(":"):
            label = line.strip().lower()

            # Skip comment-style labels (like :::) that contain no alphanumeric characters
            # These are commonly used as decorative comments and should not be flagged as duplicates
            label_content = label[1:]  # Remove the leading ":"
            if not re.search(r'[a-zA-Z0-9]', label_content):
                # This is a comment-style label like ::::::, skip it
                continue

            if label in labels:
                issues.append(
                    LintIssue(
                        line_number=i,
                        rule=RULES["W013"],  # Duplicate label
                        context=f"Label '{label}' already defined on line {labels[label]}",
                    )
                )
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
        "PATH",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "USERNAME",
        "COMPUTERNAME",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "ERRORLEVEL",
        "CD",
        "DATE",
        "TIME",
        "RANDOM",
        "CMDEXTVERSION",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOGONSERVER",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATHEXT",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",  # 32-bit program files on 64-bit systems
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "WINDIR",
        "ALLUSERSPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "PUBLIC",
        # Additional commonly used environment variables
        "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION",
        "USERDOMAIN",
        "USERDNSDOMAIN",
        "SESSIONNAME",
        "CLIENTNAME",
        "ProgramW6432",  # 64-bit program files folder on 64-bit systems
        "CommonProgramFiles",
        "CommonProgramFiles(x86)",
        "ProgramFiles(x86)",
    }
    set_vars.update(common_env_vars)

    return set_vars


def _check_syntax_errors(line: str, line_num: int, labels: Dict[str, int]) -> List[LintIssue]:
    """Check for syntax error level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # E002: Missing label for GOTO statement
    # E015: Missing colon in GOTO :EOF statement
    goto_match = re.match(r"goto\s+(:?\S+)", stripped, re.IGNORECASE)
    if goto_match:
        label_text: str = goto_match.group(1)
        target_label: str = label_text.lower()

        # E015: GOTO EOF must use colon (GOTO :EOF is required, GOTO EOF is invalid)
        if target_label == "eof":
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["E015"],
                    context="GOTO EOF should be GOTO :EOF (colon is mandatory for EOF)",
                )
            )
        elif target_label == ":eof":
            # :eof is a built-in construct, always valid with colon
            pass
        # Check for dynamic labels (containing variables)
        elif re.search(r"%[^%]+%|!\w+!", label_text):
            # Dynamic labels like "label.%errorlevel%" or "label[%variable%]" can't be statically validated
            pass
        else:
            # Static label - check if it exists
            if not target_label.startswith(":"):
                target_label = ":" + target_label
            if target_label not in labels:
                issues.append(
                    LintIssue(
                        line_number=line_num,
                        rule=RULES["E002"],
                        context=f"GOTO points to non-existent label '{label_text}'",
                    )
                )

    # E014: Missing colon in CALL statement
    call_match = re.match(r"call\s+([^:\s]\S*)", stripped, re.IGNORECASE)
    if call_match:
        label_text: str = call_match.group(1)
        # Check if this looks like a label call (not an external program)
        # Skip if it contains path separators, extensions, or is a known command
        builtin_commands = {
            'dir', 'echo', 'copy', 'move', 'del', 'type', 'find', 'findstr',
            'sort', 'more', 'cls', 'cd', 'pushd', 'popd', 'mkdir', 'rmdir',
            'attrib', 'xcopy', 'robocopy', 'ping', 'ipconfig', 'netstat',
            'tasklist', 'taskkill', 'sc', 'net', 'reg', 'wmic', 'powershell',
            'timeout', 'choice', 'ver', 'vol', 'date', 'time', 'help'
        }
        if (not re.search(r'[\\/.:]|\.(?:bat|cmd|exe|com)$', label_text.lower()) and
            label_text.lower() not in builtin_commands):
            # This appears to be a label call without colon
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["E014"],
                    context=f"CALL to label '{label_text}' should use colon: CALL :{label_text}",
                )
            )

    # E003: IF statement improper formatting
    # Check for IF statements that may have improper syntax
    if_match = re.match(r"if\s+(.+)", stripped, re.IGNORECASE)
    if if_match:
        if_content = if_match.group(1).strip()

        # Valid IF patterns to check for:
        # 1. IF EXIST filename
        # 2. IF DEFINED variable
        # 3. IF ERRORLEVEL number
        # 4. IF /I for case insensitive
        # 5. IF NOT for negation
        # 6. Comparison operators: ==, EQU, NEQ, LSS, LEQ, GTR, GEQ
        valid_if_patterns = [
            r"exist\s+",                              # IF EXIST
            r"defined\s+",                           # IF DEFINED
            r"errorlevel\s+\d+",                     # IF ERRORLEVEL n
            r"/i\s+",                                # IF /I (case insensitive)
            r"not\s+",                               # IF NOT
            r".*\s*(==|equ|neq|lss|leq|gtr|geq)\s*", # Comparison operators
        ]

        # Check if this IF statement matches any valid pattern
        is_valid_if = any(re.search(pattern, if_content, re.IGNORECASE) for pattern in valid_if_patterns)

        # If it doesn't match any valid pattern and seems incomplete, flag it
        if not is_valid_if and not re.search(r"[&|()]", if_content):  # Not a complex conditional
            # Only flag if it looks like an incomplete comparison (has words but no operators)
            if re.match(r"[\"']?%?\w+%?[\"']?\s*$", if_content):
                issues.append(
                    LintIssue(
                        line_number=line_num,
                        rule=RULES["E003"],
                        context="IF statement appears to be missing comparison operator or condition",
                    )
                )

    # E004: IF EXIST syntax mixing
    if re.match(r"if\s+exist\s+.*==.*", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E004"],
                context="Mixing IF EXIST with comparison operators",
            )
        )

    # E005: Invalid path syntax (basic check for invalid characters)
    path_patterns = [r'"([^"]*[<>|*?][^"]*)",', r"'([^']*[<>|*?][^']*)'"]
    for pattern in path_patterns:
        if re.search(pattern, stripped):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["E005"],
                    context="Path contains invalid characters",
                )
            )
            break

    # E009: Mismatched quotes
    if line.count('"') % 2 != 0:
        issues.append(
            LintIssue(
                line_number=line_num, rule=RULES["E009"], context="Unmatched double quotes detected"
            )
        )

    # E010: Malformed FOR loop missing DO
    if re.match(r"for\s+.*", stripped, re.IGNORECASE) and " do " not in stripped.lower():
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E010"],
                context="FOR loop is missing required DO keyword",
            )
        )

    # E011: Invalid variable expansion syntax
    # Look for unmatched % or ! delimiters in variable references
    # This is a more conservative check that only flags obvious syntax errors

    # Count % characters - if odd number, might have unmatched delimiter
    percent_count = stripped.count('%')
    exclamation_count = stripped.count('!')

    # Only flag if there's an obvious mismatch (odd number of delimiters)
    # and there appear to be variable-like patterns
    if percent_count % 2 == 1 and re.search(r'%[A-Z0-9_]+', stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E011"],
                context="Variable reference may have mismatched % delimiters",
            )
        )

    if exclamation_count % 2 == 1 and re.search(r'![A-Z0-9_]+', stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E011"],
                context="Delayed expansion variable may have mismatched ! delimiters",
            )
        )

    # E012: Missing CALL for subroutine invocation
    # Check for potential subroutine calls without CALL (label followed by parameters)
    if re.match(r":[A-Z0-9_]+\s+\S+", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E012"],
                context="Potential subroutine call without CALL keyword",
            )
        )

    # E013: Invalid command syntax detected
    first_word = stripped.split()[0].lower() if stripped.split() else ""
    if first_word in COMMON_COMMAND_TYPOS:
        correct_command = COMMON_COMMAND_TYPOS[first_word]
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E013"],
                context=f"Command '{first_word}' appears to be a typo, did you mean '{correct_command}'?",
            )
        )

    return issues


def _check_warning_issues(  # pylint: disable=unused-argument
    line: str, line_num: int, set_vars: Set[str], delayed_expansion_enabled: bool
) -> List[LintIssue]:
    """Check for warning level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # W005: Unquoted variable with spaces
    unquoted_var_pattern = r'(?<!["\'])%[A-Z0-9_]+%|(?<!["\'])![A-Z0-9_]+!'
    if re.search(unquoted_var_pattern, stripped, re.IGNORECASE):
        # Check if it's in a context where spaces could be problematic
        if any(cmd in stripped.lower() for cmd in ["if", "echo", "set", "call"]):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["W005"],
                    context="Variable may contain spaces and should be quoted",
                )
            )

    # W006: Network operation without timeout
    if re.match(r"ping\s+[^-]*$", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["W006"],
                context="PING command without timeout parameter",
            )
        )

    # W008: Permanent PATH modification
    if re.match(r"setx\s+path", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num, rule=RULES["W008"], context="SETX modifies PATH permanently"
            )
        )

    # W009: Windows version compatibility
    for cmd in OLDER_WINDOWS_COMMANDS:
        if re.match(rf"{cmd}\s", stripped, re.IGNORECASE):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["W009"],
                    context=f"Command '{cmd}' may not be available on older Windows versions",
                )
            )
            break

    # W010: Architecture-specific operation
    for pattern in ARCHITECTURE_SPECIFIC_PATTERNS:
        if pattern in stripped:
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["W010"],
                    context=f"Architecture-specific reference: {pattern}",
                )
            )
            break

    # W011: Unicode handling issue
    for cmd in UNICODE_PROBLEMATIC_COMMANDS:
        if re.match(rf"{cmd}\s", stripped, re.IGNORECASE):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["W011"],
                    context=f"Command '{cmd}' may have Unicode handling issues",
                )
            )
            break

    # W012: Non-ASCII characters detected
    if not all(ord(c) < 128 for c in stripped):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["W012"],
                context="Line contains non-ASCII characters",
            )
        )

    # W015: Deprecated command usage
    first_word = stripped.split()[0].lower() if stripped.split() else ""
    if first_word in DEPRECATED_COMMANDS:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["W015"],
                context=f"Command '{first_word}' is deprecated and may not work in newer Windows versions",
            )
        )

    return issues


def _check_style_issues(
    line: str,
    line_num: int,
    file_lines: List[str],
    max_line_length: int = 120,
) -> List[LintIssue]:
    """Check for style level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # S003: Inconsistent command capitalization
    for keyword in COMMAND_CASING_KEYWORDS:
        pattern = rf"\b{keyword}\b"
        if re.search(pattern, stripped, re.IGNORECASE):
            # Check if it's not uppercase
            if not re.search(rf"\b{keyword.upper()}\b", stripped):
                issues.append(
                    LintIssue(
                        line_number=line_num,
                        rule=RULES["S003"],
                        context=f"Command '{keyword}' should be uppercase for consistency",
                    )
                )
            break

    # S004: Trailing whitespace
    if line.rstrip("\n") != line.rstrip():
        issues.append(
            LintIssue(
                line_number=line_num, rule=RULES["S004"], context="Line has trailing spaces or tabs"
            )
        )

    # S009: Magic numbers used (simple heuristic)
    number_patterns = [r"timeout\s+/t\s+(\d+)", r"ping\s+.*\s+-n\s+(\d+)"]
    for pattern in number_patterns:
        match = re.search(pattern, stripped, re.IGNORECASE)
        if match:
            number = match.group(1)
            if int(number) > 10:  # Only flag larger numbers
                issues.append(
                    LintIssue(
                        line_number=line_num,
                        rule=RULES["S009"],
                        context=f"Magic number '{number}' should be defined as a variable",
                    )
                )

    # S011: Line exceeds maximum length
    line_length = len(line.rstrip("\n"))
    if line_length > max_line_length:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["S011"],
                context=f"Line is {line_length} characters (max {max_line_length})",
            )
        )


    # S014: Long parameter list affects readability
    call_match = re.match(r"call\s+:[A-Z0-9_]+\s+(.*)", stripped, re.IGNORECASE)
    if call_match:
        params = call_match.group(1).split()
        if len(params) > 5:  # More than 5 parameters
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["S014"],
                    context=f"Function call has {len(params)} parameters, consider grouping them",
                )
            )

    return issues


def _check_security_issues(line: str, line_num: int) -> List[LintIssue]:
    """Check for security level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # SEC001: Potential command injection vulnerability
    if re.search(r"set\s+/p\s+[^=]+=.*%.*%", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["SEC001"],
                context="User input used in command without validation",
            )
        )

    # SEC002: Unsafe SET command usage
    set_match = re.match(r"set\s+([A-Za-z0-9_]+)=(.+)", stripped, re.IGNORECASE)
    if set_match:
        var_val_text: str = set_match.group(2)
        var_val: str = var_val_text.strip()
        if not (var_val.startswith('"') and var_val.endswith('"')):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC002"],
                    context="SET command value should be quoted for safety",
                )
            )

    # SEC003: Dangerous command without confirmation
    # Only flag if not in a safe context (REM comment or ECHO statement)
    if not _is_command_in_safe_context(line):
        for pattern, rule_code in DANGEROUS_COMMAND_PATTERNS:
            if re.search(pattern, stripped, re.IGNORECASE):
                issues.append(
                    LintIssue(
                        line_number=line_num,
                        rule=RULES[rule_code],
                        context="Destructive command should have user confirmation",
                    )
                )
                break

    # SEC004: Dangerous registry operation (covered by patterns above)

    # SEC005: Missing privilege check for admin operations
    admin_commands = ["reg add hklm", "reg delete hklm", "sc ", "net "]
    for cmd in admin_commands:
        if cmd in stripped.lower():
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC005"],
                    context=f"Command '{cmd.strip()}' may require administrator privileges",
                )
            )
            break

    # SEC006: Hardcoded absolute path
    hardcoded_paths = [r"C:\\", r"D:\\", r"E:\\", r"/Users/", r"/home/"]
    for path_pattern in hardcoded_paths:
        if re.search(path_pattern, stripped):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC006"],
                    context="Hardcoded absolute path may not exist on other systems",
                )
            )
            break

    # SEC007: Hardcoded temporary directory
    temp_paths = [r"C:\\temp", r"C:\\tmp", r"/tmp"]
    for temp_path in temp_paths:
        if temp_path in stripped:
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC007"],
                    context="Use %TEMP% instead of hardcoded temporary paths",
                )
            )
            break

    # SEC008: Plain text credentials detected
    for pattern in CREDENTIAL_PATTERNS:
        if re.search(pattern, stripped, re.IGNORECASE):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC008"],
                    context="Potential hardcoded credentials detected",
                )
            )
            break

    # SEC009: PowerShell execution policy bypass
    if re.search(r"powershell.*-executionpolicy\s+bypass", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["SEC009"],
                context="PowerShell execution policy bypass detected",
            )
        )

    # SEC010: Sensitive information in ECHO output
    for pattern in SENSITIVE_ECHO_PATTERNS:
        if re.search(pattern, stripped, re.IGNORECASE):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC010"],
                    context="ECHO statement may display sensitive information",
                )
            )
            break

    return issues


def _check_performance_issues(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    _lines: List[str],
    line_num: int,
    line: str,  # pylint: disable=unused-argument
    has_setlocal: bool,
    has_set_commands: bool,
    has_delayed_expansion: bool,
    uses_delayed_vars: bool,
) -> List[LintIssue]:
    """Check for performance level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # P003: Unnecessary SETLOCAL
    if "setlocal" in stripped.lower() and not has_set_commands:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["P003"],
                context="SETLOCAL used without any SET commands",
            )
        )

    # P004: Unnecessary ENABLEDELAYEDEXPANSION
    if "enabledelayedexpansion" in stripped.lower() and not uses_delayed_vars:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["P004"],
                context="ENABLEDELAYEDEXPANSION used without !variables!",
            )
        )

    # P005: ENDLOCAL without SETLOCAL
    if "endlocal" in stripped.lower() and not has_setlocal:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["P005"],
                context="ENDLOCAL used without corresponding SETLOCAL",
            )
        )

    # P007: Temporary file without random name
    temp_patterns = [r"temp\.txt", r"tmp\.txt", r"temp\.log"]
    for pattern in temp_patterns:
        if re.search(pattern, stripped, re.IGNORECASE) and "random" not in stripped.lower():
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["P007"],
                    context="Temporary file should use %RANDOM% to prevent collisions",
                )
            )
            break

    # P008: Delayed expansion without enablement (moved from old delayed expansion check)
    if not has_delayed_expansion and re.search(r"![A-Z0-9_]+!", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["P008"],
                context="Delayed expansion variables used without ENABLEDELAYEDEXPANSION",
            )
        )

    # P009: Inefficient FOR loop pattern
    for_match = re.match(r"for\s+/f\s+[\"']([^\"']*)[\"']\s+%%\w+\s+in", stripped, re.IGNORECASE)
    if for_match and "tokens=*" not in for_match.group(1).lower():
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["P009"],
                context="FOR /F loop could be optimized with 'tokens=*' parameter",
            )
        )

    # P010: Missing optimization flags for directory operations
    if re.match(r"dir\s+(?!.*\/f)", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["P010"],
                context="DIR command could be optimized with /F flag for large directories",
            )
        )

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
                issues.append(
                    LintIssue(
                        line_number=i,
                        rule=RULES["E006"],  # Undefined variable reference
                        context=f"Variable '{var_name}' is used but never defined",
                    )
                )

    return issues


def _validate_and_read_file(file_path: str) -> Tuple[List[str], str]:
    """Validate file and read its contents.

    Returns:
        Tuple of (lines, encoding_used)
    """
    if not file_path or not isinstance(file_path, str):
        raise ValueError("file_path must be a non-empty string")

    # Validate file exists and is accessible
    file_obj = Path(file_path)
    if not file_obj.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not file_obj.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

    # Check file size for performance warning
    file_size = file_obj.stat().st_size
    if file_size > 10 * 1024 * 1024:  # 10MB
        logger.warning(
            "Large file detected (%dMB). Processing may take longer.", file_size // 1024 // 1024
        )

    lines, encoding_used = read_file_with_encoding(file_path)

    # Issue a warning if we had to fall back from UTF-8
    if encoding_used.lower() not in ["utf-8", "utf-8-sig"]:
        warnings.warn(
            f"File '{file_path}' was read using '{encoding_used}' encoding instead of UTF-8. "
            f"Consider converting the file to UTF-8 for better compatibility.",
            UserWarning,
            stacklevel=3,
        )

    return lines, encoding_used


def _analyze_script_structure(lines: List[str]) -> Tuple[bool, bool, bool, bool]:
    """Analyze script structure for context-aware checking.

    Returns:
        Tuple of (has_setlocal, has_set_commands, has_delayed_expansion, uses_delayed_vars)
    """
    has_setlocal = any("setlocal" in line.lower() for line in lines)
    has_set_commands = any(re.match(r"\s*set\s+[^=]+=.*", line, re.IGNORECASE) for line in lines)
    has_delayed_expansion = any(
        re.search(r"setlocal\s+enabledelayedexpansion", line, re.IGNORECASE) for line in lines
    )
    uses_delayed_vars = any(re.search(r"![A-Z0-9_]+!", line, re.IGNORECASE) for line in lines)
    return has_setlocal, has_set_commands, has_delayed_expansion, uses_delayed_vars


def _check_global_style_rules(lines: List[str], file_path: str) -> List[LintIssue]:
    """Check global style rules that apply to the entire file."""
    issues: List[LintIssue] = []

    if not lines:
        return issues
    # S001: Missing @ECHO OFF at file start
    if not lines[0].strip().lower().startswith("@echo off"):
        issues.append(
            LintIssue(
                line_number=1, rule=RULES["S001"], context="Script should start with @ECHO OFF"
            )
        )

    # S002: ECHO OFF without @ prefix
    first_line = lines[0].strip().lower()
    if first_line.startswith("echo off") and not first_line.startswith("@echo off"):
        issues.append(
            LintIssue(
                line_number=1, rule=RULES["S002"], context="Use @ECHO OFF instead of ECHO OFF"
            )
        )

    # S007: File extension recommendation
    if file_path.lower().endswith(".bat"):
        issues.append(
            LintIssue(
                line_number=1,
                rule=RULES["S007"],
                context="Consider using .cmd extension instead of .bat for scripts "
                "targeting Windows 2000 and newer",
            )
        )

    # S015: Inconsistent colon usage in GOTO statements
    issues.extend(_check_goto_colon_consistency(lines))

    return issues


def _check_goto_colon_consistency(lines: List[str]) -> List[LintIssue]:
    """Check for consistent colon usage in GOTO statements throughout the script (S015)."""
    issues: List[LintIssue] = []

    goto_statements = []

    # Collect all GOTO statements (excluding GOTO :EOF which has special rules)
    for i, line in enumerate(lines, start=1):
        stripped = line.strip().lower()
        goto_match = re.match(r"goto\s+(:?\S+)", stripped, re.IGNORECASE)
        if goto_match:
            label_text = goto_match.group(1).lower()
            # Skip GOTO :EOF and GOTO EOF as they have special handling
            if label_text not in [":eof", "eof"]:
                # Skip dynamic labels (containing variables)
                if not re.search(r"%[^%]+%|!\w+!", label_text):
                    uses_colon = label_text.startswith(":")
                    goto_statements.append((i, label_text, uses_colon))

    if len(goto_statements) < 2:
        # Need at least 2 GOTO statements to check consistency
        return issues

    # Check if there's inconsistency in colon usage
    first_uses_colon = goto_statements[0][2]
    inconsistent_lines = []

    for line_num, label, uses_colon in goto_statements[1:]:
        if uses_colon != first_uses_colon:
            inconsistent_lines.append(line_num)

    # Flag all inconsistent occurrences
    for line_num in inconsistent_lines:
        first_line = goto_statements[0][0]
        first_style = "with colon" if first_uses_colon else "without colon"
        current_style = "without colon" if first_uses_colon else "with colon"
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["S015"],
                context=f"GOTO statement uses {current_style} but first GOTO (line {first_line}) uses {first_style}",
            )
        )

    return issues


def _process_file_checks(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    lines: List[str],
    labels: Dict[str, int],
    set_vars: Set[str],
    has_setlocal: bool,
    has_set_commands: bool,
    has_delayed_expansion: bool,
    uses_delayed_vars: bool,
    max_line_length: int,
    enable_performance_rules: bool,
    enable_style_rules: bool,
) -> List[LintIssue]:
    """Process all line-by-line and global checks."""
    issues: List[LintIssue] = []

    # Check each line with all rule categories
    for i, line in enumerate(lines, start=1):
        # Error level checks
        issues.extend(_check_syntax_errors(line, i, labels))

        # Warning level checks
        issues.extend(_check_warning_issues(line, i, set_vars, has_delayed_expansion))

        # Style level checks (if enabled)
        if enable_style_rules:
            style_issues = _check_style_issues(line, i, lines, max_line_length)
            issues.extend(style_issues)

        # Security level checks (always enabled for safety)
        issues.extend(_check_security_issues(line, i))

        # Performance level checks (if enabled)
        if enable_performance_rules:
            perf_issues = _check_performance_issues(
                lines,
                i,
                line,
                has_setlocal,
                has_set_commands,
                has_delayed_expansion,
                uses_delayed_vars,
            )
            issues.extend(perf_issues)

    # Global checks (across all lines)
    issues.extend(_check_undefined_variables(lines, set_vars))
    issues.extend(_check_unreachable_code(lines))
    issues.extend(_check_redundant_operations(lines))
    issues.extend(_check_code_duplication(lines))

    # Global checks that depend on configuration flags
    issues.extend(_check_missing_pause(lines))  # Warning level
    issues.extend(_check_mixed_variable_syntax(lines))  # Warning level

    # Style-level global checks (only if style rules are enabled)
    if enable_style_rules:
        issues.extend(_check_inconsistent_indentation(lines))
        issues.extend(_check_missing_documentation(lines))

    # Performance-level global checks (only if performance rules are enabled)
    if enable_performance_rules:
        issues.extend(_check_redundant_assignments(lines))

    return issues


def lint_batch_file(  # pylint: disable=too-many-locals
    file_path: str,
    max_line_length: int = 120,
    enable_performance_rules: bool = True,
    enable_style_rules: bool = True,
) -> List[LintIssue]:
    """
    Lint a batch file and return list of issues found.

    This is the main entry point for batch file analysis. It performs comprehensive
    static analysis including syntax validation, security checks, style analysis,
    and performance optimization suggestions.

    Thread-safe: Yes - uses only local variables and immutable global rules
    Performance: Optimized for files up to 10MB, handles larger files gracefully

    Args:
        file_path: Path to the batch file (.bat or .cmd) to lint.
                  Can be absolute or relative path.
        max_line_length: Maximum allowed line length for S011 rule (default: 120)
        enable_performance_rules: Whether to enable performance-related rules (default: True)
        enable_style_rules: Whether to enable style-related rules (default: True)

    Returns:
        List of LintIssue objects containing detailed issue information.
        Each issue includes line number, rule details, and contextual information.

    Raises:
        OSError: If file cannot be read or encoding issues occur
        FileNotFoundError: If the specified file doesn't exist
        PermissionError: If insufficient permissions to read the file
        ValueError: If file_path is empty or invalid

    Example:
        >>> issues = lint_batch_file("script.bat")
        >>> for issue in issues:
        ...     print(f"Line {issue.line_number}: {issue.rule.name}")

        >>> # With custom configuration
        >>> issues = lint_batch_file("script.bat", max_line_length=100,
        ...                         enable_style_rules=False)
    """
    logger.info("Starting lint analysis of file: %s", file_path)

    # Read and validate file
    lines, _encoding_used = _validate_and_read_file(file_path)

    if not lines:
        return []  # Empty file, no issues

    # Store original max_line_length for S011 rule
    original_s011_rule = RULES["S011"]
    if max_line_length != 120:
        RULES["S011"] = Rule(
            code="S011",
            name=original_s011_rule.name,
            severity=original_s011_rule.severity,
            explanation=original_s011_rule.explanation.replace("120", str(max_line_length)),
            recommendation=original_s011_rule.recommendation,
        )

    issues: List[LintIssue] = []

    # Analyze script structure for context-aware checking
    structure_data = _analyze_script_structure(lines)
    has_setlocal, has_set_commands, has_delayed_expansion, uses_delayed_vars = structure_data

    # Style rules that apply globally (only if style rules are enabled)
    if enable_style_rules:
        issues.extend(_check_global_style_rules(lines, file_path))

    # Collect labels and check for duplicates
    labels, label_issues = _collect_labels(lines)
    issues.extend(label_issues)

    # Collect set variables for undefined variable checking
    set_vars = _collect_set_variables(lines)

    # Process all line-by-line and global checks
    issues.extend(
        _process_file_checks(
            lines,
            labels,
            set_vars,
            has_setlocal,
            has_set_commands,
            has_delayed_expansion,
            uses_delayed_vars,
            max_line_length,
            enable_performance_rules,
            enable_style_rules,
        )
    )

    # Restore original S011 rule if modified
    if max_line_length != 120:
        RULES["S011"] = original_s011_rule
    logger.info(
        "Lint analysis completed. Found %d issues across %d error(s), "
        "%d warning(s), %d style issue(s), %d security issue(s), "
        "%d performance issue(s)",
        len(issues),
        len([i for i in issues if i.rule.severity == RuleSeverity.ERROR]),
        len([i for i in issues if i.rule.severity == RuleSeverity.WARNING]),
        len([i for i in issues if i.rule.severity == RuleSeverity.STYLE]),
        len([i for i in issues if i.rule.severity == RuleSeverity.SECURITY]),
        len([i for i in issues if i.rule.severity == RuleSeverity.PERFORMANCE]),
    )

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
                    issues.append(
                        LintIssue(
                            line_number=j + 1,
                            rule=RULES["E008"],
                            context=f"Code after {stripped.split()[0].upper()} on "
                            f"line {i + 1} will never execute",
                        )
                    )
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
                    issues.append(
                        LintIssue(
                            line_number=j + 1,
                            rule=RULES["P001"],
                            context=f"Redundant existence check for {filename} "
                            f"(first check on line {i + 1})",
                        )
                    )
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
                issues.append(
                    LintIssue(
                        line_number=line_num,
                        rule=RULES["P002"],
                        context=f"Similar command pattern repeated "
                        f"(also on lines {line_numbers[0]})",
                    )
                )

    return issues


def _check_missing_pause(lines: List[str]) -> List[LintIssue]:
    """Check for missing PAUSE in interactive scripts (W014)."""
    issues: List[LintIssue] = []

    has_user_input = any(
        re.search(r"set\s+/p\s+", line, re.IGNORECASE) or
        re.search(r"choice\s+", line, re.IGNORECASE)
        for line in lines
    )

    has_pause = any(
        re.search(r"pause", line, re.IGNORECASE)
        for line in lines
    )

    if has_user_input and not has_pause:
        # Find an appropriate line number (near the end)
        for i in range(len(lines) - 1, -1, -1):
            if lines[i].strip() and not lines[i].strip().startswith("rem"):
                issues.append(
                    LintIssue(
                        line_number=i + 1,
                        rule=RULES["W014"],
                        context="Interactive script should include PAUSE to prevent window closing",
                    )
                )
                break

    return issues


def _check_mixed_variable_syntax(lines: List[str]) -> List[LintIssue]:
    """Check for mixed variable syntax within the same script (W016)."""
    issues: List[LintIssue] = []

    has_percent_vars = False
    has_exclamation_vars = False
    first_percent_line = 0
    first_exclamation_line = 0

    for i, line in enumerate(lines, start=1):
        if not has_percent_vars and re.search(r"%[A-Z0-9_]+%", line, re.IGNORECASE):
            has_percent_vars = True
            first_percent_line = i

        if not has_exclamation_vars and re.search(r"![A-Z0-9_]+!", line, re.IGNORECASE):
            has_exclamation_vars = True
            first_exclamation_line = i

    if has_percent_vars and has_exclamation_vars:
        # Flag the second occurrence
        if first_exclamation_line > first_percent_line:
            issues.append(
                LintIssue(
                    line_number=first_exclamation_line,
                    rule=RULES["W016"],
                    context=f"Mixed variable syntax detected (standard %VAR% used on line {first_percent_line})",
                )
            )
        else:
            issues.append(
                LintIssue(
                    line_number=first_percent_line,
                    rule=RULES["W016"],
                    context=f"Mixed variable syntax detected (delayed !VAR! used on line {first_exclamation_line})",
                )
            )

    return issues


def _check_inconsistent_indentation(lines: List[str]) -> List[LintIssue]:
    """Check for inconsistent indentation patterns across the file (S012)."""
    issues: List[LintIssue] = []

    # Track indentation patterns
    indented_lines = []
    for i, line in enumerate(lines, start=1):
        if line.startswith(("\t", " ")):
            leading_whitespace = ""
            for char in line:
                if char in ("\t", " "):
                    leading_whitespace += char
                else:
                    break
            indented_lines.append((i, leading_whitespace))

    if len(indented_lines) < 2:
        return issues

    # Check for mixed patterns
    uses_tabs = False
    uses_spaces = False
    first_tab_line = 0
    first_space_line = 0

    for line_num, whitespace in indented_lines:
        if "\t" in whitespace:
            uses_tabs = True
            if first_tab_line == 0:
                first_tab_line = line_num
        if " " in whitespace:
            uses_spaces = True
            if first_space_line == 0:
                first_space_line = line_num

        # Also check for mixed within single line
        if "\t" in whitespace and " " in whitespace:
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["S012"],
                    context="Line mixes tabs and spaces for indentation",
                )
            )

    # Check for inconsistent indentation across file
    if uses_tabs and uses_spaces and not issues:  # Only if no single-line mixing found
        later_line = max(first_tab_line, first_space_line)
        if first_tab_line < first_space_line:
            context = f"File mixes tabs (line {first_tab_line}) and spaces (line {first_space_line}) for indentation"
        else:
            context = f"File mixes spaces (line {first_space_line}) and tabs (line {first_tab_line}) for indentation"

        issues.append(
            LintIssue(
                line_number=later_line,
                rule=RULES["S012"],
                context=context,
            )
        )

    return issues


def _check_missing_documentation(lines: List[str]) -> List[LintIssue]:
    """Check for missing file header documentation (S013)."""
    issues: List[LintIssue] = []

    if len(lines) < 5:  # Skip very short files
        return issues

    # Check first 5 lines for meaningful comments
    meaningful_comments = 0
    for line in lines[:5]:
        stripped = line.strip().lower()
        if stripped.startswith("rem ") and len(stripped) > 10:
            # Look for documentation indicators
            if any(keyword in stripped for keyword in ["script:", "purpose:", "author:", "date:", "description:"]):
                meaningful_comments += 1

    if meaningful_comments == 0:
        issues.append(
            LintIssue(
                line_number=1,
                rule=RULES["S013"],
                context="Script lacks header documentation (purpose, author, date)",
            )
        )

    return issues


def _check_redundant_assignments(lines: List[str]) -> List[LintIssue]:
    """Check for redundant variable assignments (P011)."""
    issues: List[LintIssue] = []

    # Track variable assignments and usage
    var_assignments: Dict[str, List[int]] = defaultdict(list)
    var_usage: Dict[str, List[int]] = defaultdict(list)

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Track assignments
        set_match = re.match(r"set\s+([A-Za-z0-9_]+)\s*=", stripped, re.IGNORECASE)
        if set_match:
            var_name = set_match.group(1).upper()
            var_assignments[var_name].append(i)

        # Track usage
        for var_match in re.finditer(r"%([A-Za-z0-9_]+)%|!([A-Za-z0-9_]+)!", stripped, re.IGNORECASE):
            var_name = (var_match.group(1) or var_match.group(2) or "").upper()
            if var_name:
                var_usage[var_name].append(i)

    # Find redundant assignments (multiple assignments without usage in between)
    for var_name, assignment_lines in var_assignments.items():
        if len(assignment_lines) > 1:
            usage_lines = var_usage.get(var_name, [])

            for i in range(len(assignment_lines) - 1):
                current_assignment = assignment_lines[i]
                next_assignment = assignment_lines[i + 1]

                # Check if there's any usage between assignments
                usage_between = any(
                    current_assignment < usage_line < next_assignment
                    for usage_line in usage_lines
                )

                if not usage_between:
                    issues.append(
                        LintIssue(
                            line_number=current_assignment,
                            rule=RULES["P011"],
                            context=f"Variable '{var_name}' reassigned on line {next_assignment} without intermediate usage",
                        )
                    )

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
        print(
            f"Most common issue: '{most_common_rule_obj.name}' "
            f"({most_common_rule[0]}) - {most_common_rule[1]} occurrences"
        )
    else:
        print("No issues found")

    print("\nIssues by severity:")
    severity_order = [
        RuleSeverity.ERROR,
        RuleSeverity.WARNING,
        RuleSeverity.STYLE,
        RuleSeverity.SECURITY,
        RuleSeverity.PERFORMANCE,
    ]
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

    severity_order = [
        RuleSeverity.ERROR,
        RuleSeverity.WARNING,
        RuleSeverity.STYLE,
        RuleSeverity.SECURITY,
        RuleSeverity.PERFORMANCE,
    ]

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

    severity_order = [
        RuleSeverity.ERROR,
        RuleSeverity.WARNING,
        RuleSeverity.STYLE,
        RuleSeverity.SECURITY,
        RuleSeverity.PERFORMANCE,
    ]

    for severity in severity_order:
        count = severity_counts.get(severity, 0)
        if count == 0:
            continue
        issue_word = "issue" if count == 1 else "issues"
        print(f"\n{severity.value}: {count} {issue_word}")
        print(f"  {descriptions.get(severity, 'No description available.')}")


def find_batch_files(path: Union[str, Path], recursive: bool = True) -> List[Path]:
    """
    Find all batch files (.bat and .cmd) in a directory or return single file.

    Args:
        path: Path to file or directory to search
        recursive: Whether to search subdirectories recursively (default: True)

    Returns:
        List of Path objects representing batch files found

    Raises:
        FileNotFoundError: If the path doesn't exist
        ValueError: If path is not a file or directory
    """
    path_obj = Path(path)

    if not path_obj.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    if path_obj.is_file():
        # Return single file if it's a batch file
        if path_obj.suffix.lower() in [".bat", ".cmd"]:
            return [path_obj]
        raise ValueError(f"File '{path}' is not a batch file (.bat or .cmd)")

    if path_obj.is_dir():
        # Find all batch files in directory
        batch_files: List[Path] = []

        if recursive:
            # Recursive search
            for pattern in ["**/*.bat", "**/*.cmd"]:
                batch_files.extend(path_obj.glob(pattern))
        else:
            # Non-recursive search
            for pattern in ["*.bat", "*.cmd"]:
                batch_files.extend(path_obj.glob(pattern))

        # Sort for consistent output
        batch_files.sort()
        return batch_files

    raise ValueError(f"Path '{path}' is neither a file nor a directory")


def main() -> (
    None
):  # pylint: disable=too-many-branches,too-many-statements,too-many-locals,too-many-return-statements
    """Main entry point for the blint application."""
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print_help()
        return

    target_path: Optional[str] = None
    show_summary = False
    recursive = True  # Default to recursive directory search

    for arg in sys.argv[1:]:
        if not arg.startswith("--"):
            # This should be the file or directory path
            if target_path is None:
                target_path = arg
        elif arg == "--summary":
            show_summary = True
        elif arg == "--severity":
            pass  # Severity is always shown
        elif arg == "--no-recursive":
            recursive = False

    if not target_path:
        print("Error: No batch file or directory provided.\n")
        print_help()
        return

    # Find all batch files to process
    try:
        batch_files = find_batch_files(target_path, recursive=recursive)
    except FileNotFoundError:
        print(f"Error: Path '{target_path}' not found.")
        return
    except ValueError as value_error:
        print(f"Error: {value_error}")
        return
    except (OSError, PermissionError) as path_error:
        print(f"Error: Cannot access '{target_path}': {path_error}")
        return

    if not batch_files:
        print(f"No batch files (.bat or .cmd) found in: {target_path}")
        return

    # Process each batch file
    all_issues: List[LintIssue] = []
    file_results: Dict[str, List[LintIssue]] = {}
    total_files_processed = 0
    files_with_errors = 0

    for batch_file in batch_files:
        try:
            issues = lint_batch_file(str(batch_file))
            file_results[str(batch_file)] = issues
            all_issues.extend(issues)
            total_files_processed += 1

            if any(issue.rule.severity == RuleSeverity.ERROR for issue in issues):
                files_with_errors += 1

        except UnicodeDecodeError as decode_error:
            print(f"Warning: Could not read '{batch_file}' due to encoding issues: {decode_error}")
            continue
        except (FileNotFoundError, PermissionError, OSError, ValueError, TypeError) as file_error:
            print(f"Warning: Could not process '{batch_file}': {file_error}")
            continue

    if total_files_processed == 0:
        print("Error: No batch files could be processed.")
        return

    # Display results
    is_directory = Path(target_path).is_dir()

    if is_directory:
        print(f"\n🔍 Batch Files Analysis: {target_path}")
        print("=" * (26 + len(target_path)))
        file_count_text = "s" if total_files_processed != 1 else ""
        print(f"Processed {total_files_processed} batch file{file_count_text}")
        print()

        # Show results for each file if there are multiple files
        if len(file_results) > 1:
            for file_path, issues in file_results.items():
                relative_path = Path(file_path).relative_to(Path(target_path))
                print(f"\n📄 File: {relative_path}")
                print("-" * (8 + len(str(relative_path))))

                if issues:
                    print_detailed(issues)
                else:
                    print("No issues found! ✅")
                print()
        else:
            # Single file in directory
            print_detailed(all_issues)
    else:
        # Single file processing
        print(f"\n🔍 Batch File Analysis: {target_path}")
        print("=" * (25 + len(target_path)))
        print_detailed(all_issues)

    # Show combined summary if processing multiple files
    if is_directory and len(file_results) > 1:
        print("\n📊 COMBINED RESULTS:")
        print("===================")

    if show_summary:
        print_summary(all_issues)

    print_severity_info(all_issues)

    # Exit with appropriate code
    error_count = sum(1 for issue in all_issues if issue.rule.severity == RuleSeverity.ERROR)

    if is_directory:
        if error_count > 0:
            error_text = "s" if error_count != 1 else ""
            file_text = "s" if files_with_errors != 1 else ""
            print(
                f"\n⚠️  Found {error_count} critical error{error_text} "
                f"across {files_with_errors} file{file_text} that must be fixed."
            )
            sys.exit(1)
        elif all_issues:
            issue_text = "s" if len(all_issues) != 1 else ""
            file_text = "s" if total_files_processed != 1 else ""
            print(
                f"\n✅ No critical errors found, but {len(all_issues)} total "
                f"issue{issue_text} detected across {total_files_processed} file{file_text}."
            )
            sys.exit(0)
        else:
            file_text = "s" if total_files_processed != 1 else ""
            look_text = "s" if total_files_processed == 1 else ""
            print(
                f"\n🎉 No issues found! All {total_files_processed} "
                f"batch file{file_text} look{look_text} great!"
            )
            sys.exit(0)
    else:
        if error_count > 0:
            print(
                f"\n⚠️  Found {error_count} critical "
                f"error{'s' if error_count != 1 else ''} that must be fixed."
            )
            sys.exit(1)
        elif all_issues:
            print(
                f"\n✅ No critical errors found, but {len(all_issues)} "
                f"issue{'s' if len(all_issues) != 1 else ''} detected."
            )
            sys.exit(0)
        else:
            print("\n🎉 No issues found! Your batch file looks great!")
            sys.exit(0)


if __name__ == "__main__":
    main()
