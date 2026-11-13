#!/usr/bin/env python3
"""Compare what the window listed with a home's manifest.

    python3 compare.py <manifest.json> <worth.json> <stored.json> [<set-aside.json>]

The list files are what `drive dump` wrote on each page. Prints each
difference under the group it belongs to. It judges by path: where one file
holds several planted items, read the rows it prints for that file.
"""

import json
import sys
from collections import defaultdict

LISTS = ("Worth Reviewing", "Stored Sign-ins", "Set Aside")
RISKS = ("High", "Medium", "Low")


def rows(path, where):
    """Each dumped inspector as a row: its title, risk, subject and files."""
    out = []
    for texts in json.loads(open(path).read()):
        if "Where" not in texts:
            continue
        head = texts[1:texts.index("Where")]
        head = [text for text in head if not text.startswith("Set Aside") and not text.startswith("Move to")]
        files = [text.split(", line ")[0][2:] for text in texts if text.startswith("~/")]
        out.append({
            "list": where,
            "title": head[0] if head else "?",
            "risk": next((text for text in head if text in RISKS), ""),
            "about": next((text for text in head[1:] if text not in RISKS), ""),
            "files": sorted(set(files)),
        })
    return out


def line(row):
    risk = ", " + row["risk"] if row["risk"] else ""
    about = f' ({row["about"]})' if row["about"] else ""
    return f'      [{row["list"]}{risk}] {row["title"]}{about}'


def verdict(item, items, found):
    """The group one planted item belongs to, given every item planted in its
    file and the rows that name the file."""
    lists = {row["list"] for row in found}
    want = item["expect"]
    if item.get("absent"):
        return "not in this guest"
    if want == "debatable":
        return "debatable, shown" if found else "debatable, not shown"
    if want == "not shown" and found and any(other["expect"] != "not shown" for other in items):
        return "same file as a real item: judge by its rows"
    if want == "not shown":
        return "noise" if "Worth Reviewing" in lists else "listed, expected hidden" if found else "as expected"
    if not found:
        return "miss"
    return "as expected" if want in lists else "wrong placement"


def print_differences(planted, by_file):
    groups = defaultdict(list)
    for path, items in planted.items():
        found = by_file.get(path, [])
        for item in items:
            groups[verdict(item, items, found)].append((item, found))
    for key in ("miss", "noise", "wrong placement", "listed, expected hidden",
                "same file as a real item: judge by its rows", "debatable, shown",
                "debatable, not shown", "not in this guest"):
        print(f"\n== {key}: {len(groups[key])}")
        for item, found in groups[key]:
            print(f'  ~/{item["path"]}\n      planted: {item["what"]} (expected {item["expect"]}: {item["why"]})')
            for text in sorted({line(row) for row in found}):
                print(text)
    print(f'\n== as expected: {len(groups["as expected"])}')


def print_duplicates(manifest, planted, by_file, shown):
    extra = [row for row in shown if not any(file in planted for file in row["files"])]
    print(f"\n== rows about files the manifest does not list: {len(extra)}")
    for row in extra:
        print(f'  {", ".join("~/" + file for file in row["files"])}\n{line(row)}')

    print("\n== files with more than one row")
    for file, found in sorted(by_file.items()):
        if len(found) > max(1, len(planted.get(file, []))):
            print(f"  ~/{file}: {len(found)} rows for {len(planted.get(file, []))} planted items")
            for text in sorted(line(row) for row in found):
                print(text)

    print("\n== one credential planted in several files")
    grouped = defaultdict(set)
    for item in manifest["items"]:
        if "group" in item:
            grouped[item["group"]].add(item["path"])
    for group, paths in sorted(grouped.items()):
        holding = [row for row in shown if set(row["files"]) & paths]
        covered = {file for row in holding for file in row["files"]} & paths
        print(f"  {group}: {len(paths)} files, {len(holding)} rows, {len(paths - covered)} files in no row")
        for path in sorted(paths - covered):
            print(f"      not in a row: ~/{path}")


def main():
    if len(sys.argv) not in (4, 5):
        sys.exit(__doc__)
    manifest = json.loads(open(sys.argv[1]).read())
    shown = [row for path, where in zip(sys.argv[2:], LISTS) for row in rows(path, where)]
    by_file = defaultdict(list)
    for row in shown:
        for file in row["files"]:
            by_file[file].append(row)
    planted = defaultdict(list)
    for item in manifest["items"]:
        planted[item["path"]].append(item)
    print_differences(planted, by_file)
    print_duplicates(manifest, planted, by_file, shown)
    count = lambda where: sum(row["list"] == where for row in shown)
    print(f'\nWorth Reviewing: {count("Worth Reviewing")} rows. Stored Sign-ins: {count("Stored Sign-ins")} rows.')


if __name__ == "__main__":
    main()
