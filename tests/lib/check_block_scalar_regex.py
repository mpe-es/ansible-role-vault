"""Flag doubled-backslash regex escapes inside folded/literal YAML scalars.

See tests/assert-jinja-regex-escaping.sh for the measurement this encodes.
"""
import glob
import os
import re
import sys

import yaml

ROOT = os.environ["ROOT"]
REGEX_FILTER = re.compile(r"(regex_search|regex_findall|regex_replace|is\s+search|is\s+match)\s*\(")
DOUBLED = re.compile(r"(?<!\\)\\{2}[sSdDwWbBAZ]")


def block_scalars(node):
    """Yield (value, line) for every scalar written as a > or | block."""
    if isinstance(node, yaml.ScalarNode):
        if node.style in ("|", ">"):
            yield node.value, node.start_mark.line + 1
    elif isinstance(node, yaml.SequenceNode):
        for child in node.value:
            yield from block_scalars(child)
    elif isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            yield from block_scalars(key)
            yield from block_scalars(value)


def main():
    fail = []
    scanned = 0
    targets = []
    for sub in ("tasks", "vars", "defaults", "handlers", "molecule"):
        targets += glob.glob(os.path.join(ROOT, sub, "**", "*.yml"), recursive=True)

    for path in sorted(targets):
        rel = os.path.relpath(path, ROOT)
        with open(path) as fh:
            try:
                docs = list(yaml.compose_all(fh))
            except Exception as exc:  # noqa: BLE001 - report, do not crash the gate
                fail.append(f"{rel}: will not parse ({exc})")
                continue
        for doc in docs:
            if doc is None:
                continue
            for value, line in block_scalars(doc):
                if not REGEX_FILTER.search(value):
                    continue
                scanned += 1
                if DOUBLED.search(value):
                    snippet = " ".join(value.split())[:130]
                    fail.append(
                        f"{rel}:{line}: doubled backslash before a regex class letter inside a "
                        f"FOLDED/LITERAL block scalar. That style performs no escape processing, "
                        f"so the pattern matches a literal backslash and never fires:\n"
                        f"      {snippet}"
                    )

    if scanned == 0:
        fail.append(
            "no regex expressions found inside block scalars -- this lock would pass "
            "vacuously; the scalar-style detection is probably broken."
        )

    if fail:
        print("FAIL: regex escaping inside folded/literal YAML scalars")
        for item in fail:
            print(f"  - {item}")
        return 1
    print(f"ok - {scanned} block-scalar regex expressions escape correctly for their style")
    return 0


if __name__ == "__main__":
    sys.exit(main())
