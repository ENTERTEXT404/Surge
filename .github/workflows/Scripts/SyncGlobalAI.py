from bisect import bisect_left
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

from SyncDirect import covered, minimize, read_baseline, sort_key
from SyncRules import domain, read_rules, write_rule_list


INDEX_URL = "https://magicrule.pages.dev/data/index/Surge.json"


def fetch(url, prefix):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "magicrule.pages.dev":
        raise SystemExit("MagicRule 发布清单指定了意外的下载域名")
    if not parsed.path.startswith(prefix):
        raise SystemExit("MagicRule 发布清单指定了意外的下载路径")
    try:
        return subprocess.check_output(
            [
                "curl", "--fail", "--silent", "--show-error", "--retry", "2",
                "--proto", "=https", "--connect-timeout", "10", "--max-time", "30", url,
            ]
        )
    except subprocess.CalledProcessError:
        raise SystemExit(f"MagicRule 下载失败：{parsed.path}") from None


def fetch_domains():
    index = json.loads(fetch(INDEX_URL, "/data/index/"))
    matches = [rule for rule in index["rules"] if rule["name"] == "GlobalAI"]
    if len(matches) != 1:
        raise SystemExit("MagicRule 索引中找不到唯一的 GlobalAI 条目")
    manifest = json.loads(fetch(matches[0]["manifest"], "/data/rules/Surge/"))
    if manifest.get("client") != "Surge" or manifest.get("rule") != "GlobalAI":
        raise SystemExit("MagicRule 发布清单的客户端或规则名不符")
    artifacts = [
        item for item in manifest["artifacts"]
        if item.get("role") == "domain-set" and not item.get("empty") and not item.get("binary")
    ]
    if len(artifacts) != 1:
        raise SystemExit("MagicRule 未提供唯一的 GlobalAI 域名集")
    artifact = artifacts[0]
    data = fetch(artifact["url"], "/data/_shared/artifacts/")
    if sha256(data).hexdigest() != artifact["dedupe"]["bytes_sha256"]:
        raise SystemExit("MagicRule GlobalAI 域名集校验值不符")

    rules = []
    for number, raw in enumerate(data.decode("utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//")):
            continue
        if len(line.removeprefix(".")) > 253 or not domain.fullmatch(line):
            raise SystemExit(f"MagicRule GlobalAI 第 {number} 行不是有效域名规则")
        rules.append(line.casefold())
    expected = sum(manifest["type_counts"].get(kind, 0) for kind in ("DOMAIN", "DOMAIN-SUFFIX"))
    if not rules or len(rules) != expected:
        raise SystemExit(f"MagicRule GlobalAI 声明 {expected} 条域名规则，实际读取 {len(rules)} 条")
    return set(rules)


def reverse_labels(name):
    return ".".join(reversed(name.split(".")))


def overlaps_direct(rule, direct, hosts_in_reverse):
    if covered(rule, direct):
        return True
    if not rule.startswith("."):
        return False
    host = rule[1:]
    if host in direct:
        return True
    prefix = reverse_labels(host) + "."
    index = bisect_left(hosts_in_reverse, prefix)
    return index < len(hosts_in_reverse) and hosts_in_reverse[index].startswith(prefix)


def main(baseline_path):
    manual_path = Path("Rules/Manual/GlobalAI.txt")
    manual, _ = read_rules(manual_path)
    if not manual:
        raise SystemExit("GlobalAI 手动基准为空")
    manual_scope = {rule.casefold() for rule in manual}
    approved, _ = read_rules(Path("Rules/Manual/GlobalAI.approved.txt"))
    direct = read_baseline(baseline_path)
    reverse_direct = sorted({reverse_labels(rule.removeprefix(".")) for rule in direct})
    upstream = fetch_domains()

    # 上游仅确认候选当前存在。审批文件限定规则和匹配类型，已审核的直连继续有效。
    available = {rule.casefold() for rule in approved if covered(rule.casefold(), upstream)}
    blocked = {rule for rule in available if overlaps_direct(rule, direct, reverse_direct)}
    added = minimize({rule for rule in available - blocked if not covered(rule, manual_scope)})
    body = ["", "# ======= 手动维护规则 ========", *manual_path.read_text(encoding="utf-8-sig").strip().splitlines()]
    if added:
        body.extend(["", "# ======= 上游同步规则 ========", *sorted(added, key=sort_key)])
    write_rule_list(
        Path("GlobalAI.list"),
        body,
        source="magical404/MagicRule",
        license_file="LICENSES/MagicRule.md",
        license_name="See LICENSE_FILE",
        modified="2026-11-19",
        total=len(manual) + len(added),
    )
    summary = [
        "### GlobalAI 同步",
        f"- 手动基准：{len(manual):,} 条",
        f"- 上游域名：{len(upstream):,} 条",
        f"- 已核验并纳入：{len(added):,} 条",
        f"- 与已审核 DIRECT 重叠而跳过：{len(blocked):,} 条",
    ]
    summary.extend(f"  - `{rule}`" for rule in sorted(added, key=sort_key))
    report = "\n".join(summary) + "\n"
    print(report)
    if destination := os.getenv("GITHUB_STEP_SUMMARY"):
        with Path(destination).open("a", encoding="utf-8") as handle:
            handle.write(report)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"用法：python3 {sys.argv[0]} <已审核的 DIRECT 基准文件>")
    main(Path(sys.argv[1]))
