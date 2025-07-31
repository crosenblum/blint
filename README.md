# blint

**blint** is a lightweight and easy-to-use linter for Windows batch files (`.bat`). It helps you identify syntax errors and enforce best practices to write cleaner and more reliable batch scripts.

## Features

- Detects common syntax errors in batch scripts
- Warns about potential pitfalls and style issues
- Simple command-line usage
- Provides clear, actionable feedback

## Installation

Clone the repository:

\`\`\`bash
git clone https://github.com/crosenblum/blint.git
cd blint
\`\`\`

(Optional) It’s recommended to create a virtual environment and install any dependencies:

\`\`\`cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt  # If you have dependencies
\`\`\`

## Usage

> **Note:** \`blint\` is designed to run on Windows systems since batch files (\`.bat\`) are Windows-specific scripts.

Run \`blint\` by executing the Python script and passing the batch file path as an argument from Command Prompt:

\`\`\`cmd
python blint.py path\to\script.bat
\`\`\`

## Example Output

\`\`\`
DETAILED ERRORS:
----------------
WARNING ISSUES:
   Line numbers: 1
   Missing '@echo off' at top of file
   - Explanation: Batch scripts usually start with '@echo off' to prevent command echoing during execution.
   - Recommendation: (optional) Review and fix the issue on these lines.

   Line numbers: 4
   'if' statement missing comparison operator '=='
   - Explanation: An 'if' statement must have a comparison operator '==' to work correctly.
   - Recommendation: (optional) Review and fix the issue on these lines.

   Line numbers: 5
   Potential unsafe 'set' command usage
   - Explanation: Using 'set' to assign variables without proper quoting or checks can cause unexpected results.
   - Recommendation: (optional) Review and fix the issue on these lines.

ERROR SEVERITY:
---------------
WARNING: 3 errors
    Should fix; can cause unexpected behavior.
\`\`\`

## Example Output with Summary

Running \`blint\` with the \`--summary\` flag on the following batch file:

\`\`\`bat
REM example.bat

echo Starting process
if exist file.txt echo File exists
set var=Hello
if "%var%"=="Hello" echo Variable says hello
\`\`\`

Produces this output:

\`\`\`
DETAILED ERRORS:
----------------
WARNING ISSUES:
   Line numbers: 1
   Missing '@echo off' at top of file
   - Explanation: Batch scripts usually start with '@echo off' to prevent command echoing during execution.
   - Recommendation: (optional) Review and fix the issue on these lines.

   Line numbers: 4
   'if' statement missing comparison operator '=='
   - Explanation: An 'if' statement must have a comparison operator '==' to work correctly.
   - Recommendation: (optional) Review and fix the issue on these lines.

   Line numbers: 5
   Potential unsafe 'set' command usage
   - Explanation: Using 'set' to assign variables without proper quoting or checks can cause unexpected results.
   - Recommendation: (optional) Review and fix the issue on these lines.

SUMMARY:
Total errors: 3
Most common error: 'Missing '@echo off' at top of file' (1 occurrences)

Errors by severity:
  WARNING: 3

ERROR SEVERITY:
---------------
WARNING: 3 errors
    Should fix; can cause unexpected behavior.
\`\`\`

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License.
