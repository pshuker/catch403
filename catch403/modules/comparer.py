#!/usr/bin/python3
"""
Comparer — side-by-side diff of two HTTP requests or responses.

Usage:
  ../.venv/bin/python3 modules/comparer.py -a request1.txt -b request2.txt
  ../.venv/bin/python3 modules/comparer.py -a req1.txt -b req2.txt --html diff.html
"""
import argparse
import difflib
import sys

from core.colors import bold, underline, end, red, green, run, good, bad, info, tab


def _read(path: str) -> list[str]:
    with open(path, errors="replace") as f:
        return f.readlines()


def compare(a: str | list[str], b: str | list[str],
            label_a: str = "A", label_b: str = "B") -> str:
    lines_a = _read(a) if isinstance(a, str) else a
    lines_b = _read(b) if isinstance(b, str) else b

    diff = list(difflib.unified_diff(
        lines_a, lines_b,
        fromfile=label_a, tofile=label_b, lineterm=""
    ))

    if not diff:
        print(f"{good} {bold}Files are identical.{end}")
        return ""

    output = []
    for line in diff:
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            output.append(f"{bold}{line}{end}")
        elif line.startswith("+"):
            output.append(f"{green}{line}{end}")
        elif line.startswith("-"):
            output.append(f"{red}{line}{end}")
        else:
            output.append(line)

    result = "\n".join(output)
    print(result)
    return result


def compare_to_html(a: str, b: str, output_file: str,
                    label_a: str = "A", label_b: str = "B") -> None:
    lines_a = _read(a)
    lines_b = _read(b)
    html = difflib.HtmlDiff().make_file(lines_a, lines_b, label_a, label_b)
    with open(output_file, "w") as f:
        f.write(html)
    print(f"{good} HTML diff written to: {bold}{output_file}{end}")


def similarity(a: str, b: str) -> float:
    lines_a = _read(a)
    lines_b = _read(b)
    return difflib.SequenceMatcher(None, lines_a, lines_b).ratio()


def main():
    parser = argparse.ArgumentParser(description="Diff two HTTP request/response files")
    parser.add_argument("-a", required=True, help="First file")
    parser.add_argument("-b", required=True, help="Second file")
    parser.add_argument("--html", dest="html", help="Save diff as HTML to this file")
    parser.add_argument("--similarity", action="store_true", help="Print similarity ratio")
    args = parser.parse_args()

    if args.similarity:
        ratio = similarity(args.a, args.b)
        print(f"{info} Similarity: {bold}{ratio:.1%}{end}")

    if args.html:
        compare_to_html(args.a, args.b, args.html, label_a=args.a, label_b=args.b)
    else:
        compare(args.a, args.b, label_a=args.a, label_b=args.b)


if __name__ == "__main__":
    main()
