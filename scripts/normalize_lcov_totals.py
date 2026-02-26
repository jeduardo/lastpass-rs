#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


def normalize_lcov(path: Path) -> tuple[int, int, float]:
    lines = path.read_text(encoding="utf-8").splitlines()

    out: list[str] = []
    in_record = False
    record: list[str] = []

    for line in lines:
        if line.startswith("SF:"):
            if in_record:
                raise RuntimeError("invalid lcov: nested SF record")
            in_record = True
            record = [line]
            continue

        if in_record:
            if line == "end_of_record":
                da = [item for item in record if item.startswith("DA:")]
                lf = len(da)
                lh = 0
                for item in da:
                    parts = item[3:].split(",")
                    if len(parts) < 2:
                        continue
                    if int(parts[1]) > 0:
                        lh += 1

                for item in record:
                    if item.startswith("LF:") or item.startswith("LH:"):
                        continue
                    out.append(item)
                out.append(f"LF:{lf}")
                out.append(f"LH:{lh}")
                out.append("end_of_record")
                in_record = False
                record = []
                continue

            record.append(line)
            continue

        out.append(line)

    if in_record:
        raise RuntimeError("invalid lcov: unterminated SF record")

    path.write_text("\n".join(out) + "\n", encoding="utf-8")

    total = covered = 0
    for line in out:
        if line.startswith("LF:"):
            total += int(line[3:])
        elif line.startswith("LH:"):
            covered += int(line[3:])
    pct = (covered * 100.0 / total) if total else 0.0
    return covered, total, pct


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: normalize_lcov_totals.py LCOV_PATH", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    covered, total, pct = normalize_lcov(path)
    print(f"normalized lcov line coverage: {pct:.2f}% ({covered}/{total})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
