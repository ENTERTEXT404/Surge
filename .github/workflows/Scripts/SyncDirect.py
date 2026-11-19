from pathlib import Path
import os
import sys

from SyncRules import domain, read_rules

SOURCE_FILES = ("direct.txt", "private.txt", "apple.txt", "icloud.txt")


def read_baseline(path):
    rules = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//")):
            continue
        # 已审核快照使用 RULE-SET。将精确匹配和后缀匹配等价转换成域名集。
        kind, separator, name = line.partition(",")
        if separator and kind in ("DOMAIN", "DOMAIN-SUFFIX"):
            line = ("." if kind == "DOMAIN-SUFFIX" else "") + name
        if len(line.removeprefix(".")) > 253 or not domain.fullmatch(line):
            raise SystemExit(f"{path}:{number} 的基准规则格式无效")
        rules.add(line.casefold())
    if not rules:
        raise SystemExit("已审核的 DIRECT 基准为空")
    return rules


def covered_by_suffix(rule, rules, *, strict=False):
    name = rule.removeprefix(".")
    if strict:
        name = name.partition(".")[2]
    while name:
        if "." + name in rules:
            return True
        name = name.partition(".")[2]
    return False


def covered(rule, rules):
    return rule in rules or covered_by_suffix(rule, rules)


def minimize(rules):
    return {
        rule for rule in rules
        if not covered_by_suffix(rule, rules, strict=rule.startswith("."))
    }


def sort_key(rule):
    return rule.removeprefix("."), rule


def report_candidates(rules, total, raw_total):
    candidates = sorted(rules, key=sort_key)
    lines = [
        "### DIRECT 同步",
        f"- 上游输入：{raw_total:,} 条",
        f"- 发布规则：{total:,} 条",
        f"- 超出已审核范围：{len(candidates):,} 条",
    ]
    lines.extend(f"  - `{rule}`" for rule in candidates[:50])
    if len(candidates) > 50:
        lines.append("  - 仅显示前 50 条")
    report = "\n".join(lines) + "\n"
    print(report)
    if summary := os.getenv("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a", encoding="utf-8") as handle:
            handle.write(report)


def main(upstream_dir, baseline_path):
    upstream = set()
    raw_total = 0
    for filename in SOURCE_FILES:
        rules, _ = read_rules(upstream_dir / filename)
        if not rules:
            raise SystemExit(f"上游 {filename} 没有有效规则")
        raw_total += len(rules)
        upstream.update(rule.casefold() for rule in rules)

    upstream = minimize(upstream)
    baseline = read_baseline(baseline_path)
    # 两条域名规则相交时，交集是完全被另一条覆盖的那条较窄规则。
    from_upstream = {rule for rule in upstream if covered(rule, baseline)}
    from_baseline = {rule for rule in baseline if covered(rule, upstream)}
    result = minimize(from_upstream | from_baseline)
    if not result:
        raise SystemExit("上游与已审核的 DIRECT 基准没有交集")
    if any(not covered(rule, baseline) or not covered(rule, upstream) for rule in result):
        raise SystemExit("生成结果超出了已审核基准或上游范围")

    lines = [
        "# NAME: DIRECT",
        "# SOURCE: Loyalsoldier/surge-rules",
        "# SOURCE_URL: https://github.com/Loyalsoldier/surge-rules",
        "# LICENSE: GPL-3.0",
        "# LICENSE_FILE: LICENSES/Loyalsoldier.md",
        f"# TOTAL: {len(result)}",
        "",
        "# ======= 上游同步规则 ========",
        *sorted(result, key=sort_key),
    ]
    output = Path("DIRECT.list")
    contents = "\n".join(lines) + "\n"
    if not output.exists() or output.read_text(encoding="utf-8") != contents:
        output.write_text(contents, encoding="utf-8")
    report_candidates(upstream - from_upstream, len(result), raw_total)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(f"用法：python3 {sys.argv[0]} <上游目录> <已审核的 DIRECT 基准文件>")
    main(Path(sys.argv[1]), Path(sys.argv[2]))
