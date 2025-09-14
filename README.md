# Blint 🚀

**Blint** is a lightweight, easy-to-use linter for Windows batch files (`.bat` and `.cmd`). It helps you spot syntax errors, enforce best practices, and write cleaner, more reliable batch scripts. Even in 2025, batch files deserve some TLC! 💻

I created Blint because I love linters for other languages, and batch files were feeling neglected. Sure, batch might be &quot;vintage,&quot; but let's make it awesome. Suggestions welcome – feel free to contribute! 😎

## Features ✨

- 🔍 Detects common syntax errors in batch scripts
- ⚠️ Warns about potential pitfalls and style issues
- 🖥️ Simple command-line interface
- 📝 Provides clear, actionable feedback

## Installation 🛠️

Clone the repository:

```cmd
git clone https://github.com/crosenblum/blint.git
cd blint
```

(Optional) Create a virtual environment and install dependencies:

```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt  # Optional but recommended
```

## Usage 📟

**Note:** Blint is designed for Windows systems, just like batch files!

Run it from the Command Prompt:

```cmd
python blint.py path\to\script.bat
# or
python blint.py path\to\script.cmd
```

For a summary view, add the `--summary` flag.

## Example Output 📊

Here's a sample output with detailed errors and severity:

```
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
```

And with `--summary`:

```
SUMMARY:
Total errors: 3
Most common error: 'Missing '@echo off' at top of file' (1 occurrences)

Errors by severity:
  WARNING: 3
```

## Contributing 🤝

Contributions are welcome! Open issues or submit pull requests to help improve Blint.

## License 📄

This project is licensed under the MIT License.
