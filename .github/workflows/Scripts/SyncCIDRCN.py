from ipaddress import collapse_addresses, ip_network
from pathlib import Path
import sys


RULE_TYPES = {4: "IP-CIDR", 6: "IP-CIDR6"}
UPSTREAM_MARKER = "DOMAIN,7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe"


def read_upstream(path, version):
    entries = []
    metadata = {}
    networks = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            key, separator, value = line[1:].partition(":")
            if separator:
                metadata[key.strip()] = value.strip()
            continue
        entries.append(line)
        if line == UPSTREAM_MARKER:
            continue
        rule_type, _, cidr = line.partition(",")
        if rule_type != RULE_TYPES[version]:
            raise ValueError(f"{path}: 意外的规则类型 {line!r}")
        network = ip_network(cidr)
        if network.version != version:
            raise ValueError(f"{path}: 地址族不符 {line!r}")
        networks.append(network)

    if not networks or metadata.get("Size") != str(len(entries)):
        raise ValueError(f"{path}: 上游 Size 与实际条数不一致，或 CIDR 为空")
    if metadata.get("License") != "CC BY-SA 2.0":
        raise ValueError(f"{path}: 上游许可已变化，需核对后再发布")
    return list(collapse_addresses(networks))


def subtract(networks, excluded):
    for block in collapse_addresses(excluded):
        remaining = []
        for network in networks:
            if not network.overlaps(block):
                remaining.append(network)
            elif block.subnet_of(network):
                remaining.extend(network.address_exclude(block))
        networks = remaining
    return list(collapse_addresses(networks))


def main(ipv4_path, ipv6_path):
    ipv4 = read_upstream(ipv4_path, 4)
    ipv6 = read_upstream(ipv6_path, 6)
    exclusions = {4: [], 6: []}
    for line in Path("Rules/Manual/CIDRCN.exclude.txt").read_text(encoding="utf-8").splitlines():
        cidr = line.partition("#")[0].strip()
        if cidr:
            network = ip_network(cidr)
            exclusions[network.version].append(network)

    ipv4 = subtract(ipv4, exclusions[4])
    ipv6 = subtract(ipv6, exclusions[6])
    if not ipv4 or not ipv6:
        raise ValueError("应用排除表后，CIDRCN 必须同时有 IPv4 和 IPv6 规则")
    body = ["# ======= IPv4 ======="]
    body.extend(f"IP-CIDR,{network}" for network in ipv4)
    body.extend(["", "# ======= IPv6 ======="])
    body.extend(f"IP-CIDR6,{network}" for network in ipv6)

    output = Path("CIDRCN.list")
    content = ("\n".join(body) + "\n").encode("utf-8")
    if output.exists() and output.read_bytes() == content:
        print(f"{output.name} is unchanged.")
    else:
        output.write_bytes(content)
    print(f"{output.name}: {len(ipv4)} IPv4 + {len(ipv6)} IPv6")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("用法：SyncCIDRCN.py <Sukka IPv4 规则文件> <Sukka IPv6 规则文件>")
    main(Path(sys.argv[1]), Path(sys.argv[2]))
