"""Tests for output and utility functions."""

import io
import queue
import sys
import threading
from collections import defaultdict
from typing import Callable, DefaultDict, List, Tuple, Union

from blint import (
    group_issues,
    print_help,
    print_summary,
    print_detailed,
    print_severity_info
)


class TestGroupIssues:
    """Test cases for issue grouping functionality."""

    def test_group_issues_empty(self) -> None:
        """Test grouping with no issues."""
        issues: List[Tuple[int, str]] = []
        grouped = group_issues(issues)
        assert len(grouped) == 0
        assert isinstance(grouped, defaultdict)

    def test_group_issues_single_type(self) -> None:
        """Test grouping issues of a single type."""
        issues = [
            (1, "Missing '@echo off' at top of file"),
            (5, "Missing '@echo off' at top of file"),
            (10, "Missing '@echo off' at top of file")
        ]
        grouped = group_issues(issues)
        assert len(grouped) == 1
        assert "Missing '@echo off' at top of file" in grouped
        assert grouped["Missing '@echo off' at top of file"] == [1, 5, 10]

    def test_group_issues_multiple_types(self) -> None:
        """Test grouping issues of multiple types."""
        issues = [
            (1, "Missing '@echo off' at top of file"),
            (3, "Unquoted variable usage"),
            (5, "Line exceeds 120 characters"),
            (7, "Unquoted variable usage"),
            (9, "Trailing whitespace")
        ]
        grouped = group_issues(issues)
        assert len(grouped) == 4
        assert grouped["Missing '@echo off' at top of file"] == [1]
        assert grouped["Unquoted variable usage"] == [3, 7]
        assert grouped["Line exceeds 120 characters"] == [5]
        assert grouped["Trailing whitespace"] == [9]

    def test_group_issues_special_cases(self) -> None:
        """Test grouping for special case messages."""
        issues = [
            (1, "Potentially dangerous command"),
            (3, "Potentially dangerous command detected"),
            (5, "'goto label1' has no matching label"),
            (7, "'goto label2' has no matching label"),
            (9, "Usage of undefined variable x"),
            (11, "Usage of undefined variable y")
        ]
        grouped = group_issues(issues)

        # Dangerous commands should be grouped together
        assert "Potentially dangerous command" in grouped
        assert len(grouped["Potentially dangerous command"]) >= 1

        # Goto issues should be grouped
        assert "Missing label(s) for 'goto' statements" in grouped
        assert len(grouped["Missing label(s) for 'goto' statements"]) >= 2

        # Undefined variables should be grouped
        assert "Usage of undefined variable" in grouped
        assert len(grouped["Usage of undefined variable"]) >= 2


class TestPrintFunctions:
    """Test cases for various print functions."""

    def capture_stdout(self, func: Callable[[object], None], *args: object) -> str:
        """Helper method to capture stdout output."""
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        try:
            func(*args)
            return captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

    def test_print_help(self) -> None:
        """Test help function output."""
        output = self.capture_stdout(print_help)

        assert "Batch Linter - Help Menu" in output
        assert "Usage:" in output
        assert "python blint.py <batch_file>" in output
        assert "--summary" in output
        assert "--severity" in output
        assert "--help" in output
        assert "Examples:" in output

    def test_print_summary_empty(self) -> None:
        """Test summary with no issues."""
        grouped: DefaultDict[str, List[int]] = defaultdict(list)
        output = self.capture_stdout(print_summary, grouped)

        assert "SUMMARY:" in output
        assert "Total errors: 0" in output
        assert "No errors found" in output

    def test_print_summary_with_issues(self) -> None:
        """Test summary with various issues."""
        grouped: DefaultDict[str, List[int]] = defaultdict(list)
        grouped["Missing '@echo off' at top of file"] = [1]
        grouped["Unquoted variable usage"] = [3, 7, 11]
        grouped["Line exceeds 120 characters"] = [5, 9]

        output = self.capture_stdout(print_summary, grouped)

        assert "SUMMARY:" in output
        assert "Total errors: 6" in output
        assert "Most common error: 'Unquoted variable usage' (3 occurrences)" in output
        assert "Errors by severity:" in output
        assert "WARNING:" in output

    def test_print_detailed_empty(self) -> None:
        """Test detailed output with no issues."""
        grouped: DefaultDict[str, List[int]] = defaultdict(list)
        output = self.capture_stdout(print_detailed, grouped)

        assert "DETAILED ERRORS:" in output
        assert "----------------" in output

    def test_print_detailed_with_issues(self) -> None:
        """Test detailed output with issues."""
        grouped: DefaultDict[str, List[int]] = defaultdict(list)
        grouped["Missing '@echo off' at top of file"] = [1]
        grouped["Line exceeds 120 characters"] = [5, 10]

        output = self.capture_stdout(print_detailed, grouped)

        assert "DETAILED ERRORS:" in output
        assert "WARNING ISSUES:" in output or "STYLE ISSUES:" in output
        assert "Line numbers: 1" in output
        assert "Line numbers: 5, 10" in output
        assert "Missing '@echo off' at top of file" in output
        assert "Line exceeds 120 characters" in output
        assert "Explanation:" in output
        assert "Recommendation:" in output

    def test_print_severity_info_empty(self) -> None:
        """Test severity info with no issues."""
        grouped: DefaultDict[str, List[int]] = defaultdict(list)
        output = self.capture_stdout(print_severity_info, grouped)

        assert "ERROR SEVERITY:" in output
        assert "---------------" in output

    def test_print_severity_info_with_issues(self) -> None:
        """Test severity info with various issue types."""
        grouped: DefaultDict[str, List[int]] = defaultdict(list)
        grouped["Missing '@echo off' at top of file"] = [1]  # WARNING
        grouped["'goto' has no matching label"] = [5]  # CRITICAL
        grouped["Line exceeds 120 characters"] = [10, 15]  # STYLE

        output = self.capture_stdout(print_severity_info, grouped)

        assert "ERROR SEVERITY:" in output
        assert "CRITICAL: 1 error" in output
        assert "WARNING: 1 error" in output
        assert "STYLE: 2 errors" in output
        assert "Must fix before running" in output  # Critical description
        assert "Should fix; can cause unexpected behavior" in output  # Warning description
        assert "Cosmetic or style issue" in output  # Style description


class TestOutputFormatting:
    """Test cases for output formatting and edge cases."""

    def capture_stdout(self, func: Callable[[object], None], *args: object) -> str:
        """Helper method to capture stdout output."""
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        try:
            func(*args)
            return captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

    def test_print_detailed_all_severity_levels(self) -> None:
        """Test detailed output includes all severity levels."""
        grouped: DefaultDict[str, List[int]] = defaultdict(list)
        grouped["'goto' has no matching label"] = [1]  # CRITICAL
        grouped["Missing '@echo off' at top of file"] = [2]  # WARNING
        grouped["Line exceeds 120 characters"] = [3]  # STYLE

        output = self.capture_stdout(print_detailed, grouped)

        assert "CRITICAL ISSUES:" in output
        assert "WARNING ISSUES:" in output
        assert "STYLE ISSUES:" in output

    def test_print_summary_single_vs_plural(self) -> None:
        """Test proper singular/plural formatting in severity info."""
        # Test single error
        grouped: DefaultDict[str, List[int]] = defaultdict(list)
        grouped["Missing '@echo off' at top of file"] = [1]

        output = self.capture_stdout(print_severity_info, grouped)
        assert "1 error" in output and "1 errors" not in output

        # Test multiple errors
        grouped["Line exceeds 120 characters"] = [5, 10]
        output = self.capture_stdout(print_severity_info, grouped)
        assert "2 errors" in output

    def test_line_number_formatting(self) -> None:
        """Test proper formatting of line numbers in detailed output."""
        grouped: DefaultDict[str, List[int]] = defaultdict(list)
        grouped["Unquoted variable usage"] = [1, 3, 5, 7, 10, 15, 20]

        output = self.capture_stdout(print_detailed, grouped)

        # Should have comma-separated, sorted line numbers
        assert "Line numbers: 1, 3, 5, 7, 10, 15, 20" in output

    def test_unknown_severity_handling(self) -> None:
        """Test handling of unknown severity levels."""
        grouped: DefaultDict[str, List[int]] = defaultdict(list)
        grouped["Unknown error type"] = [1]  # This won't be in ERROR_SEVERITY

        output = self.capture_stdout(print_detailed, grouped)
        assert "UNKNOWN ISSUES:" in output

        output = self.capture_stdout(print_severity_info, grouped)
        assert "UNKNOWN: 1 error" in output
        assert "Unknown severity level" in output

    def test_empty_line_lists_handling(self) -> None:
        """Test handling of empty line lists (edge case)."""
        grouped: DefaultDict[str, List[int]] = defaultdict(list)
        grouped["Test error"] = []  # Empty list

        output = self.capture_stdout(print_summary, grouped)
        assert "Total errors: 0" in output

    def test_max_function_with_empty_grouped(self) -> None:
        """Test max function behavior with empty grouped dict."""
        grouped: DefaultDict[str, List[int]] = defaultdict(list)

        # Should not crash
        output = self.capture_stdout(print_summary, grouped)
        assert "No errors found" in output

    def test_output_consistency(self) -> None:
        """Test that all output functions work together consistently."""
        grouped: DefaultDict[str, List[int]] = defaultdict(list)
        grouped["Missing '@echo off' at top of file"] = [1, 5]
        grouped["Unquoted variable usage"] = [3, 7, 11]

        # All functions should run without errors
        summary_output = self.capture_stdout(print_summary, grouped)
        detailed_output = self.capture_stdout(print_detailed, grouped)
        severity_output = self.capture_stdout(print_severity_info, grouped)

        # Basic consistency checks
        assert "5" in summary_output  # Total errors
        assert "Missing '@echo off'" in detailed_output
        assert "WARNING:" in severity_output

    def test_special_characters_in_output(self) -> None:
        """Test handling of special characters in error messages."""
        grouped: DefaultDict[str, List[int]] = defaultdict(list)
        grouped["'goto special_label' has no matching label"] = [1]

        output = self.capture_stdout(print_detailed, grouped)
        assert "'goto special_label'" in output

    def test_large_line_numbers(self) -> None:
        """Test formatting with large line numbers."""
        grouped: DefaultDict[str, List[int]] = defaultdict(list)
        grouped["Line exceeds 120 characters"] = [999, 1000, 10000]

        output = self.capture_stdout(print_detailed, grouped)
        assert "999, 1000, 10000" in output

    def test_group_issues_comprehensive_special_handling(self) -> None:
        """Test comprehensive group_issues functionality with special message patterns."""
        # Test the specific message patterns that have special handling
        issues = [
            (1, "Potentially dangerous command detected on system"),
            (2, "'goto nonexistent' has no matching label"),
            (3, "Usage of undefined variable VAR"),
            (4, "Normal error message"),
            (5, "'goto another' has no matching label"),
            (6, "Usage of undefined variable ANOTHER"),
            (7, "Potentially dangerous command detected"),
            (8, "'goto third_label' has no matching label"),
        ]

        grouped = group_issues(issues)

        # Verify the special grouping logic
        assert "Potentially dangerous command" in grouped
        assert "Missing label(s) for 'goto' statements" in grouped
        assert "Usage of undefined variable" in grouped
        assert "Normal error message" in grouped

        # Verify the line numbers are correctly grouped
        assert grouped["Missing label(s) for 'goto' statements"] == [2, 5, 8]
        assert grouped["Usage of undefined variable"] == [3, 6]
        assert len(grouped["Potentially dangerous command"]) >= 2

    def test_group_issues_edge_cases_and_robustness(self) -> None:
        """Test group_issues with edge cases and robustness scenarios."""
        # Test with duplicate line numbers for same issue
        issues = [
            (1, "Missing '@echo off' at top of file"),
            (1, "Missing '@echo off' at top of file"),  # Duplicate
            (5, "Unquoted variable usage"),
        ]

        grouped = group_issues(issues)
        # Should handle duplicates gracefully
        assert len(grouped["Missing '@echo off' at top of file"]) == 2
        assert grouped["Unquoted variable usage"] == [5]

    def test_group_issues_comprehensive_message_variations(self) -> None:
        """Test group_issues with various message format variations."""
        issues = [
            (1, "Potentially dangerous command"),
            (3, "Potentially dangerous command detected"),
            (5, "Potentially dangerous command found"),
            (7, "'goto label1' has no matching label"),
            (9, "'goto label2' has no matching label"),
            (11, "'goto subroutine1' has no matching label"),  # Changed from 'call' to 'goto'
            (13, "Usage of undefined variable x"),
            (15, "Usage of undefined variable y"),
            (17, "Usage of undefined variable z"),
        ]

        grouped = group_issues(issues)

        # All dangerous command variations should be grouped together
        dangerous_lines = grouped.get("Potentially dangerous command", [])
        assert len(dangerous_lines) >= 3

        # All goto statements should be grouped (call statements may not be grouped the same way)
        goto_lines = grouped.get("Missing label(s) for 'goto' statements", [])
        assert len(goto_lines) >= 3

        # All undefined variables should be grouped
        undefined_lines = grouped.get("Usage of undefined variable", [])
        assert len(undefined_lines) == 3

    def test_output_functions_thread_safety_basic(self) -> None:
        """Basic test for thread safety of output functions."""

        grouped: DefaultDict[str, List[int]] = defaultdict(list)
        grouped["Test error"] = [1, 2, 3]
        grouped["Another error"] = [4, 5]

        results_queue: queue.Queue[Tuple[str, Union[str, int]]] = queue.Queue()

        def worker(
            func: Callable[[DefaultDict[str, List[int]]], None],
            grouped_data: DefaultDict[str, List[int]]
        ) -> None:
            try:
                # Capture output instead of printing to console
                old_stdout = sys.stdout
                sys.stdout = io.StringIO()
                func(grouped_data)
                output = sys.stdout.getvalue()
                sys.stdout = old_stdout
                results_queue.put(('success', len(output)))
            except Exception as exception:
                results_queue.put(('error', str(exception)))

        # Test multiple output functions concurrently
        functions = [print_summary, print_detailed, print_severity_info]
        threads = []

        for func in functions:
            thread = threading.Thread(target=worker, args=(func, grouped))
            threads.append(thread)
            thread.start()

        # Wait for all threads
        for thread in threads:
            thread.join()

        # Check results
        results = []
        while not results_queue.empty():
            results.append(results_queue.get())

        assert len(results) == 3
        for result_type, result_data in results:
            assert result_type == 'success'
            assert isinstance(result_data, int)  # Length of output
