from datetime import datetime
import os
from pathlib import Path
import re
import sys
from zoneinfo import ZoneInfo

label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
domain = re.compile(rf"\.?{label}(?:\.{label})*", re.IGNORECASE | re.ASCII)


def read_rules(path):
    rules = []
    metadata = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("#"):
            key, separator, value = line[1:].partition(":")
            if separator:
                metadata[key.strip()] = value.strip()
            continue
        if len(line.removeprefix(".")) > 253 or not domain.fullmatch(line):
            raise SystemExit(f"{path}:{number}: invalid DOMAIN-SET entry {line!r}")
        rules.append(line)
    return rules, metadata


def optional_rules(filename):
    path = Path("Rules/Manual") / filename
    return read_rules(path)[0] if path.exists() else []


def unique_rules(rules, seen):
    result = []
    for rule in rules:
        key = rule.casefold()
        if key not in seen:
            seen.add(key)
            result.append(rule)
    return result


def main(upstream_path: Path) -> None:
    # 同时校验域名格式和上游声明的条数，防止截断内容被写入。
    upstream, metadata = read_rules(upstream_path)
    declared_total = metadata.get("Total lines")
    actual_total = len(upstream)

    if declared_total is None:
        raise SystemExit(f"上游缺少 Total lines 声明，实际读取 {actual_total} 条规则。")
    if re.fullmatch(r"0|[1-9][0-9]*", declared_total) is None:
        raise SystemExit(
            f"上游 Total lines 声明无效（{declared_total!r}），应为非负整数。"
        )
    if actual_total == 0:
        raise SystemExit(f"上游声明 {declared_total} 条，实际读取 0 条。名单不能为空。")
    if declared_total != str(actual_total):
        raise SystemExit(f"上游声明 {declared_total} 条，实际读取 {actual_total} 条。")

    # 手动规则优先。排除表只作用于上游，并按整条规则比较。
    seen = set()
    manual = unique_rules(optional_rules("REJECT.txt"), seen)
    exclusions = {rule.casefold() for rule in optional_rules("REJECT.exclude.txt")}
    synchronized = unique_rules(upstream, seen | exclusions)
    total = len(manual) + len(synchronized)
    if not total:
        raise SystemExit("No rules remain after applying exclusions")

    repository = os.environ["GITHUB_REPOSITORY"]
    server = os.environ["GITHUB_SERVER_URL"]
    header = [
        "# NAME: REJECT",
        f"# AUTHOR: {os.environ['GITHUB_REPOSITORY_OWNER']}",
        f"# REPO: {server}/{repository}",
        "# UPDATED: ",
        f"# TOTAL: {total}",
    ]
    body = [""]
    if manual:
        body.extend(["# ======= 手动维护规则 ========", *manual])
    body.extend(["# ======= 上游同步规则 ========", *synchronized])

    output = Path("REJECT.list")
    previous = output.read_text(encoding="utf-8").splitlines() if output.exists() else []

    # 内容有变化时才更新时间，避免每天产生空提交。
    if (
        len(previous) >= len(header)
        and previous[3].startswith(header[3])
        and previous[:3] == header[:3]
        and previous[4:] == header[4:] + body
    ):
        print(f"REJECT.list is unchanged ({total} rules).")
        return

    header[3] += f"{datetime.now(ZoneInfo('Asia/Shanghai')):%Y.%m.%d %H:%M:%S}"
    output.write_text("\n".join(header + body) + "\n", encoding="utf-8")
    print(f"Validated {len(synchronized)} upstream rules and {len(manual)} manual rules.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("用法：python3 .github/workflows/scripts/sync_reject.py <上游规则文件>")
    main(Path(sys.argv[1]))
