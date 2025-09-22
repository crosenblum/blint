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
# Analyze a single batch file
python blint.py script.bat

# Analyze all batch files in a directory (recursive)
python blint.py /path/to/batch/files

# Analyze batch files in directory only (non-recursive)
python blint.py /path/to/batch/files --no-recursive

# Analyze with summary
python blint.py script.bat --summary

# Get help
python blint.py --help
```

### Command Line Options

- `<path>`: Path to a batch file (`.bat` or `.cmd`) OR directory containing batch files
- `--summary`: Display summary statistics of issues found
- `--severity`: Show detailed severity level breakdown (always included)
- `--no-recursive`: When processing directories, only analyze files in the specified directory (not subdirectories)
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

### 📁 **Directory Processing**

Blint can analyze entire directories of batch files with powerful options:

- **Recursive Analysis**: Automatically finds and processes all `.bat` and `.cmd` files in directories and subdirectories
- **Non-Recursive Mode**: Use `--no-recursive` to analyze only files in the specified directory
- **Batch Processing**: Handles multiple files efficiently with consolidated reporting
- **Error Resilience**: Continues processing other files even if some files have encoding or permission issues
- **Progress Tracking**: Shows detailed results for each file plus combined summary statistics

**Examples:**
```cmd
# Analyze all batch files in project directory and subdirectories
python blint.py ./my-batch-scripts

# Analyze only batch files in current directory (no subdirectories)  
python blint.py . --no-recursive

# Get combined summary for entire directory
python blint.py ./scripts --summary
```

## Rule Categories 📋

Blint provides comprehensive static analysis with **49 Built-in Rules** across 5 severity levels:

- **Error Level (E001-E999)**: Critical syntax errors that prevent execution
- **Warning Level (W001-W999)**: Potential runtime issues and bad practices  
- **Style Level (S001-S999)**: Code formatting and readability improvements
- **Security Level (SEC001+)**: Security vulnerabilities and dangerous operations
- **Performance Level (P001-P999)**: Optimization opportunities and efficiency improvements

📖 **For complete rule descriptions with examples and implementation details, see [docs/Batch-File-Linter-Requirements.md](docs/Batch-File-Linter-Requirements.md)**

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
