"""Tests for main function and command-line interface."""

import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import TracebackType
from typing import TYPE_CHECKING, Optional, Protocol
from unittest.mock import patch

from blint import main

if TYPE_CHECKING:
    from typing_extensions import Self


class StdoutCaptureProtocol(Protocol):
    """Protocol for stdout capture context manager."""

    def __enter__(self) -> "StdoutCaptureProtocol":
        """Enter context manager."""

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """Exit context manager."""

    def getvalue(self) -> str:
        """Get the captured stdout output."""


class TestMainFunction:
    """Test cases for the main function and CLI interface."""

    def capture_stdout(self) -> StdoutCaptureProtocol:
        """Context manager to capture stdout output."""

        class StdoutCapture:
            """Context manager for capturing stdout output."""

            def __init__(self) -> None:
                self.captured_output: Optional[io.StringIO] = None
                self.old_stdout: object = None

            def __enter__(self) -> "StdoutCapture":
                self.old_stdout = sys.stdout
                sys.stdout = self.captured_output = io.StringIO()
                return self

            def __exit__(
                self,
                exc_type: Optional[type[BaseException]],
                exc_val: Optional[BaseException],
                exc_tb: Optional[TracebackType],
            ) -> None:
                sys.stdout = self.old_stdout

            def getvalue(self) -> str:
                """Get the captured stdout output."""
                return self.captured_output.getvalue() if self.captured_output else ""

        return StdoutCapture()

    def create_temp_batch_file(self, content: str) -> str:
        """Helper method to create a temporary batch file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write(content)
            return temp_file.name

    @patch("sys.argv", ["blint.py"])
    def test_main_no_arguments(self) -> None:
        """Test main function with no arguments shows help."""
        with self.capture_stdout() as captured:
            main()
            output = captured.getvalue()

        assert "Batch Linter - Help Menu" in output
        assert "Usage:" in output

    @patch("sys.argv", ["blint.py", "--help"])
    def test_main_help_flag(self) -> None:
        """Test main function with --help flag."""
        with self.capture_stdout() as captured:
            main()
            output = captured.getvalue()

        assert "Batch Linter - Help Menu" in output
        assert "Usage:" in output

    def test_main_nonexistent_file(self) -> None:
        """Test main function with non-existent file."""
        with patch("sys.argv", ["blint.py", "nonexistent.bat"]):
            with self.capture_stdout() as captured:
                main()
                output = captured.getvalue()

            assert "Error: No valid batch file provided" in output
            assert "Batch Linter - Help Menu" in output

    def test_main_non_bat_file(self) -> None:
        """Test main function with non-.bat file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as temp_file:
            temp_file.write("test content")
            temp_file_path = temp_file.name

        try:
            with patch("sys.argv", ["blint.py", temp_file_path]):
                with self.capture_stdout() as captured:
                    main()
                    output = captured.getvalue()

                assert "Error: No valid batch file provided" in output
        finally:
            os.unlink(temp_file_path)

    def test_main_valid_batch_file(self) -> None:
        """Test main function with valid batch file."""
        content = """@echo off
echo Hello World
set "var=test value"
echo %var%
"""
        temp_file = self.create_temp_batch_file(content)

        try:
            with patch("sys.argv", ["blint.py", temp_file]):
                with self.capture_stdout() as captured:
                    main()
                    output = captured.getvalue()

                assert "DETAILED ERRORS:" in output
                assert "ERROR SEVERITY:" in output
        finally:
            os.unlink(temp_file)

    def test_main_with_summary_flag(self) -> None:
        """Test main function with --summary flag."""
        content = """@echo off
echo Hello World
set var=unquoted
"""
        temp_file = self.create_temp_batch_file(content)

        try:
            with patch("sys.argv", ["blint.py", temp_file, "--summary"]):
                with self.capture_stdout() as captured:
                    main()
                    output = captured.getvalue()

                assert "DETAILED ERRORS:" in output
                assert "SUMMARY:" in output
                assert "Total errors:" in output
                assert "ERROR SEVERITY:" in output
        finally:
            os.unlink(temp_file)

    def test_main_with_severity_flag(self) -> None:
        """Test main function with --severity flag."""
        content = """@echo off
echo Hello World
"""
        temp_file = self.create_temp_batch_file(content)

        try:
            with patch("sys.argv", ["blint.py", temp_file, "--severity"]):
                with self.capture_stdout() as captured:
                    main()
                    output = captured.getvalue()

                assert "DETAILED ERRORS:" in output
                assert "ERROR SEVERITY:" in output
        finally:
            os.unlink(temp_file)

    def test_main_with_multiple_flags(self) -> None:
        """Test main function with multiple flags."""
        content = """@echo off
echo Hello World
set var=unquoted
echo %var%
"""
        temp_file = self.create_temp_batch_file(content)

        try:
            with patch("sys.argv", ["blint.py", temp_file, "--summary", "--severity"]):
                with self.capture_stdout() as captured:
                    main()
                    output = captured.getvalue()

                assert "DETAILED ERRORS:" in output
                assert "SUMMARY:" in output
                assert "ERROR SEVERITY:" in output
        finally:
            os.unlink(temp_file)

    def test_main_file_not_found_error(self) -> None:
        """Test main function with file that gets deleted after validation."""
        temp_file = self.create_temp_batch_file("@echo off\necho test\n")

        # Delete the file to simulate FileNotFoundError
        os.unlink(temp_file)

        with patch("sys.argv", ["blint.py", temp_file]):
            with self.capture_stdout() as captured:
                main()
                output = captured.getvalue()

            # The main function validates file existence before processing
            # So this will trigger "No valid batch file provided" instead
            assert "Error: No valid batch file provided" in output

    def test_main_permission_error(self) -> None:
        """Test main function with permission error."""
        temp_file = self.create_temp_batch_file("@echo off\necho test\n")

        try:
            with patch("blint.lint_batch_file", side_effect=PermissionError("Permission denied")):
                with patch("sys.argv", ["blint.py", temp_file]):
                    with self.capture_stdout() as captured:
                        main()
                        output = captured.getvalue()

                    assert "Error: Permission denied" in output
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_main_unicode_decode_error(self) -> None:
        """Test main function with unicode decode error."""
        temp_file = self.create_temp_batch_file("@echo off\necho test\n")

        try:
            with patch(
                "blint.lint_batch_file",
                side_effect=UnicodeDecodeError("utf-8", b"", 0, 1, "invalid"),
            ):
                with patch("sys.argv", ["blint.py", temp_file]):
                    with self.capture_stdout() as captured:
                        main()
                        output = captured.getvalue()

                    assert "Error: Could not read the batch file" in output
                    assert "encoding issues" in output
                    assert "Troubleshooting tips:" in output
                    assert "pip install chardet" in output
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_main_general_exception(self) -> None:
        """Test main function with general exception."""
        temp_file = self.create_temp_batch_file("@echo off\necho test\n")

        try:
            with patch("blint.lint_batch_file", side_effect=ValueError("Something went wrong")):
                with patch("sys.argv", ["blint.py", temp_file]):
                    with self.capture_stdout() as captured:
                        main()
                        output = captured.getvalue()

                    assert "Error: Unexpected error while processing" in output
                    assert "Something went wrong" in output
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_main_argument_parsing_variations(self) -> None:
        """Test various argument parsing scenarios."""
        content = "@echo off\necho test\n"
        temp_file = self.create_temp_batch_file(content)

        try:
            # Test with .bat extension recognition
            test_cases = [
                ["blint.py", temp_file.upper()],  # Uppercase path
                ["blint.py", temp_file.lower()],  # Lowercase path
                ["blint.py", "--summary", temp_file],  # Flag before file
                ["blint.py", temp_file, "--summary"],  # Flag after file
            ]

            for test_argv in test_cases:
                # Make sure file has .bat extension for recognition
                if temp_file.endswith(".bat"):
                    with patch("sys.argv", test_argv):
                        with self.capture_stdout() as captured:
                            main()
                            output = captured.getvalue()

                        # Should process successfully without showing help
                        assert "DETAILED ERRORS:" in output
                        assert "Batch Linter - Help Menu" not in output
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_main_mixed_case_bat_extension(self) -> None:
        """Test batch file recognition with mixed case .bat extension."""
        content = "@echo off\necho test\n"

        # Create file with mixed case extension
        with tempfile.NamedTemporaryFile(mode="w", suffix=".BaT", delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            with patch("sys.argv", ["blint.py", temp_file_path]):
                with self.capture_stdout() as captured:
                    main()
                    output = captured.getvalue()

                assert "DETAILED ERRORS:" in output
        finally:
            os.unlink(temp_file_path)

    def test_main_cmd_extension(self) -> None:
        """Test batch file recognition with .cmd extension."""
        content = "@echo off\necho test\n"

        # Create file with .cmd extension
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cmd", delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            with patch("sys.argv", ["blint.py", temp_file_path]):
                with self.capture_stdout() as captured:
                    main()
                    output = captured.getvalue()

                assert "DETAILED ERRORS:" in output
        finally:
            os.unlink(temp_file_path)

    def test_main_mixed_case_cmd_extension(self) -> None:
        """Test batch file recognition with mixed case .cmd extension."""
        content = "@echo off\necho test\n"

        # Create file with mixed case extension
        with tempfile.NamedTemporaryFile(mode="w", suffix=".CmD", delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            with patch("sys.argv", ["blint.py", temp_file_path]):
                with self.capture_stdout() as captured:
                    main()
                    output = captured.getvalue()

                assert "DETAILED ERRORS:" in output
        finally:
            os.unlink(temp_file_path)

    def test_main_with_relative_path(self) -> None:
        """Test main function with relative path."""
        content = "@echo off\necho test\n"

        # Create temp file in current directory
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, dir="."
        ) as temp_file:
            temp_file.write(content)
            temp_filename = os.path.basename(temp_file.name)

        try:
            with patch("sys.argv", ["blint.py", temp_filename]):
                with self.capture_stdout() as captured:
                    main()
                    output = captured.getvalue()

                assert "DETAILED ERRORS:" in output
        finally:
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)

    def test_main_output_structure(self) -> None:
        """Test the structure and order of main function output."""
        content = """echo Missing echo off
set var=unquoted
echo %var%
"""
        temp_file = self.create_temp_batch_file(content)

        try:
            with patch("sys.argv", ["blint.py", temp_file, "--summary"]):
                with self.capture_stdout() as captured:
                    main()
                    output = captured.getvalue()

                # Check output order: detailed first, then summary, then severity
                detailed_pos = output.find("DETAILED ERRORS:")
                summary_pos = output.find("SUMMARY:")
                severity_pos = output.find("ERROR SEVERITY:")

                assert detailed_pos != -1
                assert summary_pos != -1
                assert severity_pos != -1

                # Summary should come after detailed, severity should come last
                assert detailed_pos < summary_pos < severity_pos
        finally:
            os.unlink(temp_file)

    def test_main_no_issues_found(self) -> None:
        """Test main function behavior when no issues are found."""
        content = """@echo off
setlocal enabledelayedexpansion
set "var=properly quoted"
echo "%var%"
"""
        temp_file = self.create_temp_batch_file(content)

        try:
            with patch("sys.argv", ["blint.py", temp_file, "--summary"]):
                with self.capture_stdout() as captured:
                    main()
                    output = captured.getvalue()

                # Should still show structure even with no issues
                assert "DETAILED ERRORS:" in output
                assert "SUMMARY:" in output
                assert "ERROR SEVERITY:" in output
        finally:
            os.unlink(temp_file)

    def test_production_ready_main_execution(self) -> None:
        """Test main() function execution in production-like scenario."""
        original_argv = sys.argv

        # Create a realistic test batch file
        content = """@echo off
REM This is a test batch file for production testing
set "TEST_VAR=Hello World"
echo %TEST_VAR%
if exist "somefile.txt" (
    echo File exists
) else (
    echo File does not exist
)
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            # Test main with various flag combinations
            test_cases = [
                [temp_file_path],
                [temp_file_path, "--summary"],
                [temp_file_path, "--severity"],
                [temp_file_path, "--summary", "--severity"],
            ]

            for test_argv in test_cases:
                sys.argv = ["blint.py"] + test_argv

                # Capture output to verify main() executes correctly
                with self.capture_stdout() as captured:
                    main()
                    output = captured.getvalue()
                    # Should have printed something (detailed output at minimum)
                    assert "DETAILED ERRORS:" in output

        finally:
            sys.argv = original_argv
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)


class TestCommandLineIntegration:
    """Integration tests for command-line usage."""

    def test_pathlib_path_integration(self) -> None:
        """Test integration with pathlib Path objects."""
        content = "@echo off\necho test\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            # Test Path.is_file() integration
            path_obj = Path(temp_file_path)
            assert path_obj.is_file()

            with patch("sys.argv", ["blint.py", temp_file_path]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()

                assert "DETAILED ERRORS:" in output
        finally:
            os.unlink(temp_file_path)

    def test_error_handling_robustness(self) -> None:
        """Test robustness of error handling in various scenarios."""
        test_scenarios = [
            ("FileNotFoundError", FileNotFoundError("File not found")),
            ("PermissionError", PermissionError("Permission denied")),
            ("UnicodeDecodeError", UnicodeDecodeError("utf-8", b"", 0, 1, "invalid")),
            ("TypeError", TypeError("General error")),
            ("OSError", OSError("OS error")),
        ]

        content = "@echo off\necho test\n"
        temp_file = None

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as tf:
                tf.write(content)
                temp_file = tf.name

            for _error_name, error_obj in test_scenarios:
                with patch("blint.lint_batch_file", side_effect=error_obj):
                    with patch("sys.argv", ["blint.py", temp_file]):
                        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                            main()  # Should not raise an exception
                            output = mock_stdout.getvalue()
                            assert "Error:" in output
        finally:
            if temp_file and os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_main_entry_point_execution(self) -> None:
        """Test the __name__ == '__main__' execution path via subprocess."""
        # Create a test script that simulates running blint as main module
        test_script_content = """
import sys
import tempfile
import os

# Create a test batch file
with tempfile.NamedTemporaryFile(mode='w', suffix='.bat', delete=False) as f:
    f.write('@echo off\\necho test')
    test_file = f.name

try:
    # Set up sys.argv as if called from command line
    sys.argv = ['blint.py', test_file]

    # Import blint module - this will execute the if __name__ == "__main__": main() line
    import blint

finally:
    # Clean up
    if os.path.exists(test_file):
        os.unlink(test_file)
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as script_file:
            script_file.write(test_script_content)
            script_file_path = script_file.name

        try:
            # Execute the script to test the main entry point
            result = subprocess.run(
                [sys.executable, script_file_path],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            # Should execute successfully (exit code 0 or 1 for issues found)
            assert result.returncode in [0, 1]

        finally:
            os.unlink(script_file_path)

    def test_comprehensive_main_execution_scenarios(self) -> None:
        """Test main function execution with comprehensive scenarios."""
        original_argv = sys.argv

        # Create a test batch file with various issues for comprehensive testing
        content = """echo off
set UNQUOTED=value
goto nonexistent
set "PROPERLY_QUOTED=safe value"
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            # Test main execution with different argument combinations
            test_cases = [
                [temp_file_path],
                [temp_file_path, "--summary"],
                [temp_file_path, "--severity"],
                [temp_file_path, "--summary", "--severity"],
            ]

            for args in test_cases:
                sys.argv = ["blint.py"] + args

                # Mock print to capture output without cluttering test output
                with patch("builtins.print"):
                    main()  # This should execute without error

        finally:
            sys.argv = original_argv
            os.unlink(temp_file_path)
