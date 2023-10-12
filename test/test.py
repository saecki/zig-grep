import argparse
import bisect
import os
import re
import subprocess
import sys
from collections import defaultdict
from typing import Set


class Flag:
    def __init__(self, grep: str | None = None, ripgrep: str | None = None, user: str | None = None):
        self.grep = grep
        self.ripgrep = ripgrep
        self.user = user
        self.arg = None

    def __call__(self, *args, **kwargs):
        self.arg = args[0]
        return self

    def for_grep(self) -> str | None:
        return self.format(self.grep)

    def for_ripgrep(self) -> str | None:
        return self.format(self.ripgrep)

    def for_user(self) -> str | None:
        return self.format(self.user)

    def format(self, flag) -> str | None:
        if flag is None:
            return None
        if self.arg is not None:
            if flag.startswith("--"):
                return f"{flag}={self.arg}"
            else:
                return f"{flag}{self.arg}"
        else:
            return flag


class Flags:
    # search case-insensitive
    IGNORE_CASE = Flag("-i", "-i", "-i")

    # for grep, search recursive
    RECURSIVE = Flag(grep="-r")

    # search hidden files
    HIDDEN = Flag(ripgrep="--hidden", user="--hidden")

    # don't search hidden files
    NO_HIDDEN = Flag(grep="--exclude=.*")

    # ignore .gitignore and similar files
    NO_IGNORE = Flag(ripgrep="--no-ignore")

    # show filename for each match
    FILE_NAMES = Flag(grep="--with-filename", ripgrep="--with-filename")

    # show line-numbers for each match
    LINE_NUMBERS = Flag(grep="--line-number", ripgrep="--line-number")

    # for ripgrep, remove the heading, and print the filename on each match
    NO_HEADING = Flag(ripgrep="--no-heading", user="--no-heading")

    # for ripgrep, explicilty add headings
    HEADING = Flag(ripgrep="--heading")

    # ignore binary files
    NO_BINARY = Flag(grep="-I")

    # disable coloring of output
    DISABLE_COLOR = Flag(grep="--color=never", ripgrep="--color=never")

    # for grep, enable regex
    REGEX = Flag(grep="-E")

    CONTEXT_BEFORE = Flag(grep="-B", ripgrep="-B", user="-B")
    CONTEXT_AFTER = Flag(grep="-A", ripgrep="-A", user="-A")
    CONTEXT = Flag(grep="-C", ripgrep="-C", user="-C")


class Ansi:
    """ ANSI color codes """
    RESET = "\033[0m"
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    BROWN = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    CLEAR = "\033[K"


class Match:
    def __init__(self, line: str, duplicate: int = 0):
        self.line = line
        self.duplicate = duplicate

    def __repr__(self):
        if self.duplicate == 0:
            return self.line
        else:
            return f"[duplicate {self.duplicate}]{self.line}"

    def __eq__(self, other):
        return (type(self) is type(other) and
                self.duplicate == other.duplicate and
                self.line == other.line)

    def __lt__(self, other):
        return self.duplicate < other.duplicate and self.line < other.line

    def __hash__(self):
        return hash((self.line, self.duplicate))


def parse(stdout: str, with_headings: bool) -> Set[Match]:
    def parse_with_headings():
        current_file = None
        for line in stdout.splitlines():
            if line == "--":
                continue
            match = re.match("^([0-9]+)([:-])", line)
            if match:
                yield Match(f"{current_file}{match.group(2)}{line}")
            elif len(line) > 0:
                current_file = line

    def parse_without_headings():
        for line in stdout.splitlines():
            if line == "--":
                continue
            yield Match(line)

    if with_headings:
        parser = parse_with_headings
    else:
        parser = parse_without_headings

    matches = set()
    for m in parser():
        while m in matches:
            m.duplicate += 1
        matches.add(m)

    return matches


def group_matches(matches):
    result = defaultdict(list)
    for match in matches:
        bisect.insort(result[match.file], match, key=lambda m: m.line_no)

    return result


def make_cmd(cmd: str, pattern: str, path: str, args: [Flag | str]):
    full_cmd = [cmd]
    default_flags = [Flags.LINE_NUMBERS, Flags.FILE_NAMES, Flags.NO_IGNORE,
                     Flags.NO_BINARY, Flags.DISABLE_COLOR, Flags.REGEX, Flags.RECURSIVE]
    if Flags.HIDDEN not in args and Flags.NO_HIDDEN not in args:
        args.append(Flags.NO_HIDDEN)
    if Flags.HEADING not in args and Flags.NO_HEADING not in args:
        args.append(Flags.NO_HEADING)

    for flag_or_str in [*args, *default_flags]:
        if type(flag_or_str) is str:
            arg = flag_or_str
        elif cmd == "grep":
            arg = flag_or_str.for_grep()
        elif cmd == "rg":
            arg = flag_or_str.for_ripgrep()
        else:
            arg = flag_or_str.for_user()
        if arg is not None:
            full_cmd.append(arg)
    full_cmd.append(pattern)
    full_cmd.append(path)

    return full_cmd


def test(name: str, reference_cmd: [str], test_cmd: [str], verbose: bool) -> bool:
    status_str = f"{Ansi.PURPLE}{name}{Ansi.RESET}"

    def execute(cmd: [str]) -> subprocess.CompletedProcess:
        print(f"\r{Ansi.CLEAR}{status_str}...running {' '.join(cmd)}", end='', flush=True)
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode != 0:
            print(f"\r{Ansi.CLEAR}{status_str}...[{Ansi.RED}ERR{Ansi.RESET}]")
            print(f"\tprocess exited with code {result.returncode}")
            print(f"\tcommand: {' '.join(cmd)}")
            print("\tprocess stderr:")
            print(result.stderr.decode())
        return result

    reference_result = execute(reference_cmd)
    if reference_result.returncode != 0:
        print(f"\r{Ansi.CLEAR}{status_str}...[{Ansi.RED}ERR{Ansi.RESET}]")
        return False

    test_result = execute(test_cmd)
    if test_result.returncode != 0:
        print(f"\r{Ansi.CLEAR}{status_str}...[{Ansi.RED}ERR{Ansi.RESET}]")
        return False

    expected_matches = parse(reference_result.stdout.decode(), reference_cmd[0] != "grep" and "--no-heading" not in test_cmd)
    got_matches = parse(test_result.stdout.decode(), test_cmd[0] != "grep" and "--no-heading" not in test_cmd)

    missing_matches = expected_matches - got_matches
    false_matches = got_matches - expected_matches

    if len(missing_matches) > 0 or len(false_matches) > 0:
        print(f"\r{Ansi.CLEAR}{status_str}...[{Ansi.RED}ERR{Ansi.RESET}]")
        print(f"\treference command: {' '.join(reference_cmd)}")
        print(f"\t       vs command: {' '.join(test_cmd)}")
        if verbose:
            missing_matches = list(missing_matches)
            missing_matches.sort()
            false_matches = list(false_matches)
            false_matches.sort()
            for match in missing_matches:
                print(f"\t{Ansi.RED}+{Ansi.RESET}{match}")
            for match in false_matches:
                print(f"\t{Ansi.RED}-{Ansi.RESET}{match}")
        else:
            print(f"\tmissing {len(missing_matches)} matches and found {len(false_matches)} false matches")
        return False
    else:
        print(f"\r{Ansi.CLEAR}{status_str}...[{Ansi.GREEN}OK{Ansi.RESET}]")
        return True


def main():
    parser = argparse.ArgumentParser(prog="searcher-test")
    parser.add_argument("command", help="the search command to be tested")
    parser.add_argument("-d", "--data-dir",
                        help="the folder that contains the test data. Default: test_data",
                        default="test_data")
    parser.add_argument("-t", "--test",
                        help="run only tests that match the given pattern (eg. 'linux' for all tests that search "
                             "the linux source codes)")
    parser.add_argument("-v", "--verbose",
                        action='store_true',
                        help="print all lines that were expected but not found or found but not expected,"
                             " instead of just a count",
                        default=False)
    parser.add_argument("--ripgrep",
                        action='store_true',
                        help="use 'ripgrep' instead of 'grep' as the reference for testing. "
                             "When available, this is a much faster option than grep",
                        default=False)
    parser.add_argument("--fail-fast",
                        action='store_true',
                        help="immediately exit when a test fails",
                        default=False)

    args, rest = parser.parse_known_args()

    def make_cmds(pattern: str, target: str, extra_flags: [Flag | str]):
        ref_cmd = "grep" if not args.ripgrep else "rg"
        return (make_cmd(ref_cmd, pattern, os.path.join(args.data_dir, target), extra_flags),
                make_cmd(args.command, pattern, os.path.join(args.data_dir, target), [*rest, *extra_flags]))

    def t(test_name: str, pattern: str, target: str, *flags: Flag | str):
        return test_name, lambda: test(test_name, *make_cmds(pattern, target, list(flags)), args.verbose)

    tests = [
        t("literal_linux", "PM_RESUME", "linux"),
        t("literal_linux_hidden", "PM_RESUME", "linux", Flags.HIDDEN),
        t("linux_literal_ignore_case", "PM_RESUME", "linux", Flags.IGNORE_CASE),
        t("linux_pattern_prefix", "[A-Z]+_RESUME", "linux"),
        t("linux_pattern_prefix_with_context", "[A-Z]+_RESUME", "linux", Flags.CONTEXT, "3"),
        t("linux_pattern_prefix_ignore_case", "[A-Z]+_RESUME", "linux", Flags.IGNORE_CASE),
        t("linux_pattern_suffix", "PM_[A-Z]+", "linux"),
        t("linux_pattern_suffix_with_context", "PM_[A-Z]+", "linux",
          Flags.CONTEXT_BEFORE, "2", Flags.CONTEXT_AFTER, "4"),
        t("linux_pattern_suffix_ignore_case", "PM_[A-Z]+", "linux", Flags.IGNORE_CASE),
        t("linux_word", r"\wAh", "linux"),
        t("linux_word_with_heading", r"\wAh", "linux", Flags.HEADING),
        t("linux_word_ignore_case", r"\wAh", "linux", Flags.IGNORE_CASE),
        t("linux_no_literal", r"\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}", "linux"),
        t("linux_no_literal_ignore_case", r"\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}", "linux", Flags.IGNORE_CASE),
        t("linux_alternatives", "ERR_SYS|PME_TURN_OFF|LINK_REQ_RST|CFG_BME_EVT", "linux"),
        t("linux_alternatives_with_heading", "ERR_SYS|PME_TURN_OFF|LINK_REQ_RST|CFG_BME_EVT", "linux", Flags.HEADING),
        t("linux_alternatives_ignore_case", "ERR_SYS|PME_TURN_OFF|LINK_REQ_RST|CFG_BME_EVT", "linux",
          Flags.IGNORE_CASE),
        t("subtitles_literal", "Sherlock Holmes", "subtitles.txt"),
        t("subtitles_literal_ignore_case", "Sherlock Holmes", "subtitles.txt", Flags.IGNORE_CASE),
        t("subtitles_alternatives", "Sherlock Holmes|John Watson|Irene Adler|Inspector Lestrade|Professor Moriarty",
          "subtitles.txt"),
        t("subtitles_alternatives_ignore_case",
          "Sherlock Holmes|John Watson|Irene Adler|Inspector Lestrade|Professor Moriarty", "subtitles.txt",
          Flags.IGNORE_CASE),
        t("subtitles_surrounding_words", r"\w+\s+Holmes\s+\w+", "subtitles.txt"),
        t("subtitles_surrounding_words_ignore_case", r"\w+\s+Holmes\s+\w+", "subtitles.txt", Flags.IGNORE_CASE),
        t("subtitles_no_literal", r"\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}", "subtitles.txt"),
        t("subtitles_no_literal_ignore_case", r"\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}",
          "subtitles.txt",
          Flags.IGNORE_CASE)
    ]

    tests_passed = 0
    tests_failed = 0

    for (name, test_fn) in tests:
        if args.test is not None:
            if not re.search(args.test, name):
                continue

        if test_fn():
            tests_passed += 1
        else:
            tests_failed += 1
            if args.fail_fast:
                break

    if tests_failed == 0:
        print(f"test result: {Ansi.GREEN}OK{Ansi.RESET}. ", end="")
    else:
        print(f"test result: {Ansi.RED}FAIL{Ansi.RESET}. ", end="")

    tests_skipped = (len(tests) - (tests_passed + tests_failed))

    print(f"{tests_passed} passed; {tests_failed} failed; {tests_skipped} skipped")

    sys.exit(tests_failed)


if __name__ == "__main__":
    main()
