# Blint 🚀

**Blint** is a linter for Windows batch files (`.bat` and `.cmd`). It provides comprehensive static analysis to identify syntax errors, security vulnerabilities, performance issues, and style problems. Blint helps you write safer, more reliable, and maintainable batch scripts. Even in 2025, batch files deserve professional tooling! 💻
 
✅ **Thread-Safe Design** - Uses immutable rules and local variables for safe concurrent usage  
✅ **Performance Optimized** - Handles large files (10MB+) efficiently  
✅ **Enterprise Features** - Configurable rules, logging, robust error handling  
✅ **Unicode Support** - International characters and filenames  
✅ **Memory Efficient** - Optimized for production environments

## Features ✨

### 🔍 **Rule Coverage**
- **49 Built-in Rules** across 5 severity levels
- **Error Level (E001-E999)**: Critical syntax errors that prevent execution
- **Warning Level (W001-W999)**: Potential runtime issues and bad practices
- **Style Level (S001-S999)**: Code formatting and readability improvements
- **Security Level (SEC001+)**: Security vulnerabilities and dangerous operations
- **Performance Level (P001-P999)**: Optimization opportunities and efficiency improvements

### 📋 **Output Format**
- **Rule Codes**: Each issue has a unique identifier (e.g., E002, W005, SEC003)
- **Clear Explanations**: Detailed descriptions of why each issue matters
- **Actionable Recommendations**: Specific guidance on how to fix problems
- **Line-by-Line Analysis**: Precise location of every issue
- **Context Information**: Additional details about detected problems

### 🚀 **Advanced Analysis**
- **Static Code Analysis**: Detects unreachable code and logic errors
- **Variable Tracking**: Identifies undefined variables and unsafe usage
- **Security Scanning**: Finds command injection risks and dangerous operations
- **Performance Optimization**: Suggests efficiency improvements
- **Cross-Platform Compatibility**: Warns about Windows version issues
- **Thread-Safe Design**: Safe for concurrent usage with immutable rules and local state
- **Large File Handling**: Efficiently processes files up to 10MB+ with performance warnings
- **Robust Encoding Detection**: Handles UTF-8, UTF-16, Latin-1, and 9+ encoding formats

## Installation 🛠️

### Prerequisites
- **Python 3.9+** (required)

### Quick Install

1. Clone the repository:
```cmd
git clone https://github.com/crosenblum/blint.git
cd blint
```

2. (Optional) Create a virtual environment:
```cmd
python -m venv venv
venv\Scripts\activate
```

3. (Optional but recommended) Install dependencies:
```cmd
pip install -r requirements.txt
```

## Usage 📟

### Basic Usage

```cmd
# Analyze a batch file
python blint.py script.bat

# Analyze with summary
python blint.py script.bat --summary

# Get help
python blint.py --help
```

### Command Line Options

- `<batch_file>`: Path to the `.bat` or `.cmd` file to analyze
- `--summary`: Display summary statistics of issues found
- `--severity`: Show detailed severity level breakdown (always included)
- `--help`: Show help menu and rule categories

### 🐍 **Programmatic API Usage**

Blint provides a powerful Python API for integration into your applications:

```python
import blint

# Basic usage
issues = blint.lint_batch_file("script.bat")
for issue in issues:
    print(f"Line {issue.line_number}: {issue.rule.name} ({issue.rule.code})")
    print(f"  {issue.rule.explanation}")
    print(f"  Fix: {issue.rule.recommendation}")

# Advanced configuration
issues = blint.lint_batch_file(
    "script.bat",
    max_line_length=100,           # Custom line length limit  
    enable_style_rules=False,      # Disable style checks
    enable_performance_rules=True  # Keep performance checks
)

# Thread-safe design allows safe concurrent usage
# You can implement your own concurrent processing if needed
from concurrent.futures import ThreadPoolExecutor

files = ["script1.bat", "script2.cmd", "script3.bat"]
with ThreadPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(blint.lint_batch_file, files))
```

### 🔧 **Configuration Options**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | `str` | Required | Path to batch file to analyze |
| `max_line_length` | `int` | `120` | Maximum line length for S011 rule |
| `enable_style_rules` | `bool` | `True` | Enable/disable style-related rules |
| `enable_performance_rules` | `bool` | `True` | Enable/disable performance rules |

*Note: Security rules are always enabled for safety.*

### Supported File Types
- `.bat` files (traditional batch files)
- `.cmd` files (recommended for modern Windows)
- **Unicode filenames** and international characters supported
- **Large files** (10MB+) handled efficiently with performance monitoring

## Rule Categories 📋

### Error Level Rules (E001-E999)
**Critical issues that will cause script failure**

- **E001**: Nested parentheses mismatch
- **E002**: Missing label for GOTO statement
- **E003**: IF statement improper formatting
- **E004**: IF EXIST syntax mixing
- **E005**: Invalid path syntax
- **E006**: Undefined variable reference
- **E007**: Empty variable check syntax error
- **E008**: Unreachable code after EXIT or GOTO
- **E009**: Mismatched quotes
- **E010**: Malformed FOR loop missing DO

### Warning Level Rules (W001-W999)
**Issues that may cause problems**

- **W001**: Missing exit code
- **W002**: Missing ERRORLEVEL check
- **W003**: Operation without error handling
- **W004**: Potential infinite loop
- **W005**: Unquoted variable with spaces
- **W006**: Network operation without timeout
- **W007**: File operation on potentially locked file
- **W008**: Permanent PATH modification
- **W009**: Windows version compatibility
- **W010**: Architecture-specific operation
- **W011**: Unicode handling issue
- **W012**: Non-ASCII characters detected
- **W013**: Duplicate label

### Style Level Rules (S001-S999)
**Code style and formatting issues**

- **S001**: Missing @ECHO OFF at file start
- **S002**: ECHO OFF without @ prefix
- **S003**: Inconsistent command capitalization
- **S004**: Trailing whitespace
- **S005**: Mixed line endings
- **S006**: Inconsistent variable naming
- **S007**: BAT extension used instead of CMD for newer Windows
- **S008**: Missing comments for complex code
- **S009**: Magic numbers used
- **S010**: Dead code detected
- **S011**: Line exceeds maximum length

### Security Level Rules (SEC001+)
**Security vulnerabilities and risks**

- **SEC001**: Potential command injection vulnerability
- **SEC002**: Unsafe SET command usage
- **SEC003**: Dangerous command without confirmation
- **SEC004**: Dangerous registry operation
- **SEC005**: Missing privilege check
- **SEC006**: Hardcoded absolute path
- **SEC007**: Hardcoded temporary directory

### Performance Level Rules (P001-P999)
**Performance and efficiency improvements**

- **P001**: Redundant file existence check
- **P002**: Code duplication detected
- **P003**: Unnecessary SETLOCAL
- **P004**: Unnecessary ENABLEDELAYEDEXPANSION
- **P005**: ENDLOCAL without SETLOCAL
- **P006**: Missing ENDLOCAL before exit
- **P007**: Temporary file without random name
- **P008**: Delayed expansion without enablement

## 🔥 **Advanced Features**

### Enterprise Integration
```python
# Custom logging configuration
import logging
logging.getLogger('blint').setLevel(logging.DEBUG)

# Batch processing with error handling
import os
from pathlib import Path

def lint_directory(directory_path):
    """Lint all batch files in a directory."""
    results = {}
    for bat_file in Path(directory_path).glob("*.bat"):
        try:
            issues = blint.lint_batch_file(str(bat_file))
            results[bat_file.name] = {
                'issues': len(issues),
                'errors': len([i for i in issues if i.rule.severity.value == 'Error']),
                'security': len([i for i in issues if i.rule.severity.value == 'Security'])
            }
        except Exception as e:
            results[bat_file.name] = {'error': str(e)}
    return results
```

### CI/CD Integration
```yaml
# Example GitHub Actions workflow
- name: Lint Batch Files
  run: |
    python -c "
    import blint
    import sys
    issues = blint.lint_batch_file('deploy.bat')
    errors = [i for i in issues if i.rule.severity.value == 'Error']
    if errors:
        print(f'Found {len(errors)} critical errors!')
        sys.exit(1)
    print(f'✅ Batch file passed with {len(issues)} total issues')
    "
```

## Contributing 🤝

**Contributions are welcome!** 

### Ways to Contribute
- 🐛 Report bugs or issues
- 💡 Suggest new rules or features
- 📖 Improve documentation
- 🧪 Add test cases
- 🔧 Submit bug fixes or enhancements

## License 📄

This project is licensed under the MIT License - see the LICENSE file for details.
