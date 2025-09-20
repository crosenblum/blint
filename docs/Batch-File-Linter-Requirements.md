# Batch File Linter Requirements

## Implementation Guidelines
*Each rule should provide clear explanations and actionable recommendations*

### Output Format
- **Line number**: Specify exact line where issue occurs
- **Rule code**: Unique identifier (e.g., E001, W001, S001, P001) 
- **Explanation**: Clear description of why this is an issue
- **Recommendation**: Specific guidance on how to fix the problem
- **Severity level**: Error, Warning, Style, Security, or Performance

### Example Output Structure
```
Line 5: Missing '@ECHO OFF' at top of file (S001)
- Explanation: Batch scripts usually start with '@ECHO OFF' to prevent command echoing during execution
- Recommendation: Add '@ECHO OFF' as the first line of your script
```

## Error Level Rules
*Issues that will cause the script to fail or behave incorrectly*

### Syntax Errors
- **Nested parentheses**: Error on improper nesting and matching of parentheses
  ```batch
  # Bad
  if exist "file.txt" (
      echo Found file
  # Missing closing parenthesis
  
  # Good
  if exist "file.txt" (
      echo Found file
  )
  ```

- **Missing labels**: Error on `GOTO` statements pointing to non-existent labels
  ```batch
  # Bad
  GOTO nonexistent_label
  
  # Good
  GOTO end
  :end
  ```

- **IF statement formatting**: Error on improper spacing and syntax in conditional statements
  ```batch
  # Bad
  IF"%VAR%"=="value"ECHO Match
  
  # Good
  IF "%VAR%"=="value" ECHO Match
  ```

- **IF EXIST vs comparison**: Error when mixing IF EXIST and comparison syntax
  ```batch
  # Bad
  IF EXIST file.txt == true ECHO Found
  IF %FILE_EXISTS% EXIST ECHO Invalid
  
  # Good
  IF EXIST file.txt ECHO Found
  IF "%FILE_EXISTS%"=="true" ECHO Found
  ```

- **Path validation**: Error on invalid path syntax and paths exceeding length limits
  ```batch
  # Bad
  COPY "C:\invalid<>path\file.txt" dest
  
  # Good
  COPY "C:\valid\path\file.txt" dest
  ```

### Variable Errors
- **Undefined variables**: Error on references to variables that were never set
  ```batch
  # Bad
  ECHO %UNDEFINED_VAR%
  
  # Good
  SET MY_VAR=value
  ECHO %MY_VAR%
  ```

- **Empty variable checks**: Error on incorrect syntax for checking if variables are empty
  ```batch
  # Bad
  IF %VAR%=="" ECHO Empty
  
  # Good
  IF "%VAR%"=="" ECHO Empty
  ```

### Control Flow Errors
- **Unreachable code**: Error on code after `EXIT` or `GOTO` statements
  ```batch
  # Bad
  EXIT /b 0
  ECHO This will never execute
  
  # Good
  ECHO This executes
  EXIT /b 0
  ```

## Warning Level Rules
*Issues that are bad practice but won't necessarily break the script*

### Missing Error Handling
- **Exit codes**: Warn when scripts don't set appropriate exit codes
  ```batch
  # Bad
  COPY file1.txt file2.txt
  # Script ends without exit code
  
  # Good
  COPY file1.txt file2.txt
  IF ERRORLEVEL 1 EXIT /b 1
  EXIT /b 0
  ```

- **Error checking**: Suggest checking `%ERRORLEVEL%` after critical operations
  ```batch
  # Bad
  DEL important_file.txt
  ECHO File deleted
  
  # Good
  DEL important_file.txt
  IF ERRORLEVEL 1 (
      ECHO Error deleting file
      EXIT /b 1
  )
  ECHO File deleted successfully
  ```

- **Missing error handling**: Flag operations that commonly fail without error checks
  ```batch
  # Bad
  COPY source.txt destination.txt
  
  # Good
  COPY source.txt destination.txt
  IF NOT ERRORLEVEL 1 ECHO Copy successful
  ```

### Potential Issues
- **Infinite loops**: Warn about potential infinite loops
  ```batch
  # Bad
  :loop
  ECHO Running
  GOTO loop
  
  # Good
  SET /a counter=0
  :loop
  SET /a counter+=1
  IF "%counter%" LSS 10 GOTO loop
  ```

- **Quoting**: Warn when variables containing spaces aren't properly quoted
  ```batch
  # Bad
  IF %PROGRAM_FILES%==C:\Program Files ECHO Match
  
  # Good
  IF "%PROGRAM_FILES%"=="C:\Program Files" ECHO Match
  ```

- **Network operations**: Warn about operations that may hang without timeouts
  ```batch
  # Bad
  PING google.com
  
  # Good
  PING -n 4 google.com
  ```

- **File locking**: Warn about operations on files that may be in use
  ```batch
  # Potentially problematic
  COPY "C:\Program Files\MyApp\config.ini" backup\
  
  # Better
  TASKLIST | FIND "myapp.exe" >nul
  IF NOT ERRORLEVEL 1 (
      ECHO Warning: MyApp may be using this file
  )
  COPY "C:\Program Files\MyApp\config.ini" backup\
  ```

- **PATH modifications**: Warn about permanent PATH changes vs temporary ones
  ```batch
  # Bad (permanent)
  SETX PATH "%PATH%;C:\MyApp"
  
  # Good (temporary)
  SET "PATH=%PATH%;C:\MyApp"
  ```

### Compatibility Issues
- **Windows version**: Flag commands not available in older Windows versions
  ```batch
  # May not work on older Windows
  CHOICE /c yn /m "Continue?"
  
  # More compatible
  SET /p answer="Continue? (y/n): "
  ```

- **Architecture**: Warn about 32-bit vs 64-bit specific operations
  ```batch
  # Architecture-specific
  REG QUERY "HKLM\SOFTWARE\Wow6432Node\MyApp"
  
  # Architecture-aware
  IF "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
      REG QUERY "HKLM\SOFTWARE\Wow6432Node\MyApp"
  ) ELSE (
      REG QUERY "HKLM\SOFTWARE\MyApp"
  )
  ```

- **Unicode support**: Check for proper Unicode handling in file operations
  ```batch
  # May have issues with Unicode
  TYPE file.txt
  
  # Better Unicode support
  TYPE file.txt | MORE
  ```

- **Encoding**: Warn about non-ASCII characters that may cause issues
  ```batch
  # Bad
  ECHO Héllo Wörld
  
  # Good
  ECHO Hello World
  ```

## Style Level Rules
*Code style and formatting issues*

### Code Style
- **Echo statements**: Error on `ECHO OFF` without `@` prefix (should be `@ECHO OFF`)
  ```batch
  # Bad
  ECHO OFF
  
  # Good
  @ECHO OFF
  ```

- **File header**: Warn when `@ECHO OFF` is missing at the top of the file
  ```batch
  # Bad
  REM This script does something
  ECHO Hello World
  
  # Good
  @ECHO OFF
  REM This script does something
  ECHO Hello World
  ```

- **Command capitalization**: Recommend uppercase for all batch commands following standard conventions
  ```batch
  # Bad
  echo Hello
  set var=value
  if exist file.txt del file.txt
  
  # Good
  ECHO Hello
  SET var=value
  IF EXIST file.txt DEL file.txt
  ```

- **Case sensitivity**: Flag inconsistent casing in commands
  ```batch
  # Inconsistent (warn)
  ECHO Hello
  echo World
  
  # Consistent
  ECHO Hello
  ECHO World
  ```

- **Trailing whitespace**: Detect and warn about trailing spaces/tabs
  ```batch
  # Bad (spaces after command)
  ECHO Hello   
  
  # Good
  ECHO Hello
  ```

- **Line endings**: Warn about mixed line endings (CRLF vs LF)
  ```batch
  # Bad: Mixed line endings in same file
  ECHO Line 1\r\n
  ECHO Line 2\n
  
  # Good: Consistent CRLF line endings
  ECHO Line 1\r\n
  ECHO Line 2\r\n
  ```

### Variable Naming
- **Variable naming**: Enforce consistent naming conventions
  ```batch
  # Inconsistent
  SET myvar=value
  SET ANOTHER_VAR=value2
  
  # Consistent
  SET MY_VAR=value
  SET ANOTHER_VAR=value2
  ```

### File Extensions
- The `.cmd` file extension is recommended over the `.bat` file extension
  ```batch
  # Recommended: script.cmd
  # Not recommended: script.bat
  ```

### Code Quality
- **Comments**: Encourage documentation for complex sections
  ```batch
  # Bad
  FOR /f "tokens=2 delims==" %%a IN ('WMIC os get localdatetime /value') DO SET dt=%%a
  
  # Good
  REM Get current date/time in format YYYYMMDDHHMMSS
  FOR /f "tokens=2 delims==" %%a IN ('WMIC os get localdatetime /value') DO SET dt=%%a
  ```

- **Magic numbers**: Flag hardcoded values that should be variables
  ```batch
  # Bad
  TIMEOUT /t 30
  
  # Good
  SET TIMEOUT_SECONDS=30
  TIMEOUT /t "%TIMEOUT_SECONDS%"
  ```

- **Dead code**: Detect unused labels or unreferenced subroutines
  ```batch
  # Bad
  GOTO main
  :unused_label
  ECHO This is never called
  :main
  ECHO Hello
  
  # Good
  ECHO Hello
  ```

## Security Level Rules
*Security-related issues that could pose risks*

### Input Validation
- **Command injection**: Detect potential injection vulnerabilities
  ```batch
  # Bad
  SET /p input="Enter filename: "
  DEL %input%
  
  # Good
  SET /p input="Enter filename: "
  IF DEFINED input DEL "%input%"
  ```

- **Unsafe SET usage**: Warn about SET commands without proper validation or quoting
  ```batch
  # Bad
  SET var=Hello World
  SET /p userfile="Enter file: "
  COPY %userfile% backup\
  
  # Good  
  SET "var=Hello World"
  SET /p userfile="Enter file: "
  IF DEFINED userfile COPY "%userfile%" backup\
  ```

### Dangerous Operations
- **Dangerous commands**: Warn about destructive commands without confirmation
  ```batch
  # Bad
  DEL *.* /q
  
  # Good
  SET /p confirm="Delete all files? (y/n): "
  IF /i "%confirm%"=="y" DEL *.* /q
  ```

- **Registry operations**: Flag potentially dangerous registry modifications
  ```batch
  # Dangerous
  REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" /f
  
  # Safer
  REG QUERY "HKLM\SOFTWARE\MyApp" >nul 2>&1
  ```

### Privilege Issues
- **Elevated privileges**: Warn when scripts require admin rights but don't check
  ```batch
  # Bad
  REG ADD "HKLM\SOFTWARE\MyApp" /v Value /d Data
  
  # Good
  NET SESSION >nul 2>&1
  IF ERRORLEVEL 1 (
      ECHO This script requires administrator privileges
      EXIT /b 1
  )
  REG ADD "HKLM\SOFTWARE\MyApp" /v Value /d Data
  ```

### Path Security
- **Hardcoded paths**: Flag absolute paths that may not exist on other systems
  ```batch
  # Bad
  COPY "C:\Users\John\file.txt" dest
  
  # Good
  COPY "%USERPROFILE%\file.txt" dest
  ```

- **Temporary directory**: Suggest using `%TEMP%` instead of hardcoded temp paths
  ```batch
  # Bad
  ECHO data > C:\temp\myfile.txt
  
  # Good
  ECHO data > "%TEMP%\myfile.txt"
  ```

## Performance Level Rules
*Performance-related suggestions and optimizations*

### Redundancy
- **Redundant operations**: Detect unnecessary file existence checks
  ```batch
  # Bad
  IF EXIST file.txt DEL file.txt
  IF EXIST file.txt ECHO File still exists
  
  # Good
  IF EXIST file.txt (
      DEL file.txt
      IF EXIST file.txt ECHO File still exists
  )
  ```

- **Code duplication**: Identify repeated code blocks that could be functions
  ```batch
  # Bad
  ECHO Processing file1
  COPY file1.txt backup\
  IF ERRORLEVEL 1 ECHO Error copying file1
  ECHO Processing file2
  COPY file2.txt backup\
  IF ERRORLEVEL 1 ECHO Error copying file2
  
  # Good
  CALL :backup_file file1.txt
  CALL :backup_file file2.txt
  GOTO :EOF
  
  :backup_file
  ECHO Processing %1
  COPY "%1" backup\
  IF ERRORLEVEL 1 ECHO Error copying %1
  GOTO :EOF
  ```

### Resource Management
- **Unnecessary setlocal**: `SETLOCAL` is not needed if there is no `SET` command
  ```batch
  # Bad
  SETLOCAL
  ECHO Hello World
  
  # Good
  ECHO Hello World
  ```

- **Unnecessary enabledelayedexpansion**: `SETLOCAL ENABLEDELAYEDEXPANSION` is not needed if there are no `!VARIABLES!`
  ```batch
  # Bad
  SETLOCAL ENABLEDELAYEDEXPANSION
  ECHO "%PATH%"
  
  # Good
  SETLOCAL
  ECHO "%PATH%"
  ```

- **Unnecessary endlocal**: `ENDLOCAL` is not needed if there is no `SETLOCAL`
  ```batch
  # Bad
  ECHO Hello World
  ENDLOCAL
  
  # Good
  ECHO Hello World
  ```

- **Missing endlocal before exit**: If there is a `SETLOCAL` in the script, there should be an `ENDLOCAL` before every exit
  ```batch
  # Bad
  SETLOCAL
  SET MY_VAR=value
  IF ERRORLEVEL 1 EXIT /b 1
  ECHO Success
  EXIT /b 0
  
  # Good
  SETLOCAL
  SET MY_VAR=value
  IF ERRORLEVEL 1 (
      ENDLOCAL
      EXIT /b 1
  )
  ECHO Success
  ENDLOCAL
  EXIT /b 0
  ```

### File Operations
- Temporary files should have %RANDOM% in their name to prevent file collisions
  ```batch
  # Bad
  ECHO data > temp.txt
  
  # Good
  ECHO data > "temp_%RANDOM%.txt"
  ```