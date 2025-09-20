# Blint 🚀

**Blint** is a linter for Windows batch files (`.bat` and `.cmd`). It helps you identify syntax errors, security vulnerabilities, performance issues, and style problems to write safer, more reliable, and maintainable batch scripts. Even in 2025, batch files deserve professional tooling! 💻

## Features ✨

### 🔍 **Rule Coverage**
- **70+ Built-in Rules** across 5 severity levels
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

## Installation 🛠️

### Prerequisites
- **Python 3.13+** (required)
- **Windows 10/11** (recommended, but works on older versions)
- **PowerShell 5.1+** or Command Prompt

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

### Supported File Types
- `.bat` files (traditional batch files)
- `.cmd` files (recommended for modern Windows)

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
- **S007**: BAT extension used instead of CMD
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

## Best Practices 🎯

### Essential Practices
1. **Always start with `@ECHO OFF`** to prevent command echoing
2. **Quote all variables** that might contain spaces: `"%VAR%"`
3. **Check `%ERRORLEVEL%`** after critical operations
4. **Use `.cmd` extension** instead of `.bat` for modern Windows
5. **Set proper exit codes** (`EXIT /b 0` for success, `EXIT /b 1` for errors)

### Security Guidelines
1. **Validate user input** before using in commands
2. **Quote all SET commands**: `SET "VAR=value"`
3. **Add confirmation prompts** for destructive operations
4. **Check for admin privileges** when needed
5. **Use environment variables** instead of hardcoded paths

### Performance Tips
1. **Use `%RANDOM%`** in temporary filenames
2. **Avoid redundant operations** and duplicate code
3. **Only use `SETLOCAL ENABLEDELAYEDEXPANSION`** when needed
4. **Pair `SETLOCAL` with `ENDLOCAL`** properly

## Contributing 🤝

**Contributions are welcome!** 

### Ways to Contribute
- 🐛 Report bugs or issues
- 💡 Suggest new rules or features  
- 📖 Improve documentation
- 🧪 Add test cases
- 🔧 Submit bug fixes or enhancements

### Development Guidelines
- Follow existing code style and patterns
- Add tests for new features
- Update documentation for rule changes
- Ensure all tests pass before submitting

## License 📄

This project is licensed under the MIT License - see the LICENSE file for details.
