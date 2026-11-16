"""堡垒机提权链路检测器。

不按单条事件告警（sudo 起 shell 是运维常态，单条告警必然淹没在噪音里），
而是先把日志解析成带时间戳的事件序列，再做序列关联：

- privilege_escalation: 普通账号 sudo 以 root 起交互 shell 后，短时间窗内
  同主机出现 root 的 SSH 登录成功 —— 单有 sudo 不告警，单有 root 登录也不告警。
- webshell: 同一来源 IP 先成功调用上传接口，随后成功访问上传目录下的脚本文件
  （上传 -> 执行 的完整链路才告警；只上传或只探测不告警）。
- needs_review: 日志本身无法判定的序列（如多次口令失败后成功、被拒绝的敏感
  路径探测），列出缺少哪类上下文才能定性。

输出 findings.json: findings[] 含 rule/first_seen/last_seen/entities/evidence，
evidence 逐条引用原始日志行；needs_review[] 含 missing_context。
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timedelta

LINE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<rest>.*)$")
SUDO = re.compile(r"sudo: (?P<user>\S+) : .*?USER=(?P<runas>\S+) ; COMMAND=(?P<cmd>\S+)")
ACCEPT = re.compile(r"sshd\[\d+\]: Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.]+)")
FAILED = re.compile(r"sshd\[\d+\]: Failed password for (?P<user>\S+) from (?P<ip>[\d.]+)")
NGINX = re.compile(r'nginx: (?P<ip>[\d.]+) - - "(?P<path>\S+)" (?P<status>\d{3})')

SHELL_CMDS = {
    "/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash", "/bin/ksh", "/bin/csh",
    "/usr/bin/bash", "/usr/bin/sh", "/usr/bin/zsh",
}
SCRIPT_EXTS = (".php", ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".pl", ".py", ".war")
EXEC_PARAMS = ("cmd=", "exec=", "command=", "system=", "shell=", "eval(", "assert(")
SENSITIVE_PATHS = ("/.env", "/.git", "/admin", "/wp-admin", "/wp-login",
                   "/phpmyadmin", "/.aws", "/.svn", "/config.")

# sudo 起 shell 与随后 root 登录之间的最大关联窗口
SUDO_ROOT_WINDOW = timedelta(minutes=5)
# 上传与随后执行之间的最大关联窗口
UPLOAD_EXEC_WINDOW = timedelta(hours=1)
# 口令失败与随后成功登录之间的最大关联窗口
FAIL_SUCCESS_WINDOW = timedelta(minutes=10)
# 口令失败达到该次数后成功，单看日志无法区分“输错密码”与“爆破得手”
BRUTE_FORCE_AMBIGUOUS = 2

LOG_YEAR = 2026  # 合成日志无年份，仅用于排序比较


def parse_ts(raw: str) -> datetime:
    return datetime.strptime(f"{LOG_YEAR} {raw}", "%Y %b %d %H:%M:%S")


def parse_events(path: str) -> list[dict]:
    events: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for no, line in enumerate(fh, start=1):
            line = line.rstrip("\n")
            m = LINE.match(line)
            if not m:
                continue
            base = {
                "line": no,
                "ts": parse_ts(m.group("ts")),
                "ts_raw": m.group("ts"),
                "host": m.group("host"),
                "raw": line,
            }
            rest = m.group("rest")
            for kind, rx in (("sudo", SUDO), ("ssh_accept", ACCEPT),
                             ("ssh_failed", FAILED), ("http", NGINX)):
                mm = rx.search(rest)
                if mm:
                    events.append({**base, "kind": kind, **mm.groupdict()})
                    break
    return events


def ev_ref(e: dict) -> str:
    return f"第{e['line']}行 {e['ts_raw']}"


def ev_item(e: dict, note: str) -> dict:
    return {"line": e["line"], "ts": e["ts_raw"], "host": e["host"],
            "event": e["kind"], "note": note, "raw": e["raw"]}


def detect_privilege_escalation(events: list[dict]) -> list[dict]:
    """sudo 以 root 起交互 shell 后，窗口内同主机出现 root 登录成功才成立。"""
    findings = []
    root_logins = [e for e in events if e["kind"] == "ssh_accept" and e["user"] == "root"]
    for sudo in events:
        if sudo["kind"] != "sudo" or sudo["runas"] != "root":
            continue
        if sudo["cmd"] not in SHELL_CMDS:
            continue  # sudo 执行单条命令属正常运维，不起 shell 不看
        follow = [r for r in root_logins
                  if r["host"] == sudo["host"]
                  and timedelta(0) <= r["ts"] - sudo["ts"] <= SUDO_ROOT_WINDOW]
        if not follow:
            continue  # 运维 sudo 起 shell 后没有异常 root 登录，属常态，不告警
        root = follow[0]
        delta = int((root["ts"] - sudo["ts"]).total_seconds())
        findings.append({
            "rule": "privilege_escalation",
            "severity": "high",
            "first_seen": sudo["ts_raw"],
            "last_seen": root["ts_raw"],
            "entities": {"user": sudo["user"], "target_user": "root",
                         "host": sudo["host"], "src_ip": root["ip"]},
            "evidence": [
                ev_item(sudo, f"普通账号 {sudo['user']} 通过 sudo 以 root 身份启动交互 shell {sudo['cmd']}"),
                ev_item(root, f"{delta} 秒后同主机出现 root 的 SSH 登录成功，来源 {root['ip']}"),
            ],
            "reason": (
                f"{ev_ref(sudo)}：账号 {sudo['user']} 执行 sudo 以 root 启动 {sudo['cmd']}；"
                f"{ev_ref(root)}：{delta} 秒后同主机 {sudo['host']} 出现 root 的 "
                f"Accepted publickey 登录（来源 {root['ip']}）。"
                f"单独的 sudo 起 shell 是运维常态，但起 shell 后紧接着出现新的 root 会话，"
                f"说明提权结果可能被用于建立持久 root 通道，提权链路成立。"
            ),
        })
    return findings


def _is_upload_endpoint(path: str) -> bool:
    name = path.split("?")[0].rsplit("/", 1)[-1].lower()
    return "upload" in name


def _is_uploaded_script(path: str) -> bool:
    p = path.split("?")[0].lower()
    return "/upload" in p and p.endswith(SCRIPT_EXTS)


def detect_webshell(events: list[dict]) -> list[dict]:
    """同一 IP 先成功上传、后成功访问上传目录下的脚本，链路完整才告警。"""
    findings = []
    http = [e for e in events if e["kind"] == "http"]
    for up in http:
        if not (_is_upload_endpoint(up["path"]) and up["status"].startswith("2")):
            continue
        for hit in http:
            if hit["ip"] != up["ip"] or hit is up:
                continue
            if not (timedelta(0) <= hit["ts"] - up["ts"] <= UPLOAD_EXEC_WINDOW):
                continue
            if not (_is_uploaded_script(hit["path"]) and hit["status"].startswith("2")):
                continue
            delta = int((hit["ts"] - up["ts"]).total_seconds())
            query = hit["path"].split("?", 1)[1] if "?" in hit["path"] else ""
            has_exec_param = any(k in query.lower() for k in EXEC_PARAMS)
            param_note = (f"，且携带命令执行参数 ?{query}" if has_exec_param
                          else "，上传目录下的脚本被直接请求")
            findings.append({
                "rule": "webshell",
                "severity": "critical",
                "first_seen": up["ts_raw"],
                "last_seen": hit["ts_raw"],
                "entities": {"src_ip": up["ip"], "host": up["host"],
                             "upload_endpoint": up["path"],
                             "webshell_path": hit["path"].split("?")[0]},
                "evidence": [
                    ev_item(up, f"{up['ip']} 成功调用上传接口 {up['path']}（HTTP {up['status']}）"),
                    ev_item(hit, f"{delta} 秒后同一 IP 成功访问上传目录下的脚本 {hit['path']}（HTTP {hit['status']}）"),
                ],
                "reason": (
                    f"{ev_ref(up)}：{up['ip']} 请求上传接口 {up['path']} 返回 {up['status']}；"
                    f"{ev_ref(hit)}：{delta} 秒后同一 IP 请求 {hit['path']} 返回 {hit['status']}"
                    f"{param_note}。上传后紧接着执行上传目录中的脚本，"
                    f"构成“上传 webshell -> 触发执行”的完整链路。"
                ),
            })
            break  # 每个上传事件只产出一条告警，取最早一次执行
    return findings


def detect_needs_review(events: list[dict]) -> list[dict]:
    """日志内证据不足以定性的序列，说明还缺哪类上下文。"""
    review = []

    # 多次口令失败后登录成功：可能是本人输错，也可能是爆破得手
    fails_by_key: dict[tuple, list[dict]] = {}
    for e in events:
        if e["kind"] == "ssh_failed":
            fails_by_key.setdefault((e["user"], e["ip"]), []).append(e)
    for (user, ip), fails in fails_by_key.items():
        if len(fails) < BRUTE_FORCE_AMBIGUOUS:
            continue
        last_fail = fails[-1]
        success = [a for a in events
                   if a["kind"] == "ssh_accept" and a["user"] == user and a["ip"] == ip
                   and timedelta(0) <= a["ts"] - last_fail["ts"] <= FAIL_SUCCESS_WINDOW]
        if not success:
            continue
        ok = success[0]
        review.append({
            "rule": "needs_review",
            "topic": "failed_logins_then_success",
            "first_seen": fails[0]["ts_raw"],
            "last_seen": ok["ts_raw"],
            "entities": {"user": user, "src_ip": ip, "host": ok["host"]},
            "evidence": [
                *[ev_item(f, f"账号 {user} 来自 {ip} 的口令认证失败") for f in fails],
                ev_item(ok, f"失败后同一来源以 publickey 登录成功"),
            ],
            "missing_context": [
                "该源 IP 是否属于该账号的历史常用登录点（登录基线/资产台账）",
                "该账号当时是否有工单或变更窗口对应本次登录",
                "失败的是口令认证而成功的是 publickey，需堡垒机侧确认是否同人操作",
            ],
            "reason": (
                f"{ev_ref(fails[0])} 至 {ev_ref(last_fail)}：{user}@{ip} 连续 "
                f"{len(fails)} 次口令失败；{ev_ref(ok)}：同一来源登录成功。"
                f"仅凭日志无法区分“本人多次输错密码后改用密钥”与“爆破尝试后成功”，"
                f"需上述上下文定性。"
            ),
        })

    # 敏感路径探测被 403 拒绝：可能是攻击踩点，也可能是授权扫描
    probes_by_ip: dict[str, list[dict]] = {}
    for e in events:
        if e["kind"] != "http" or not e["status"].startswith("4"):
            continue
        p = e["path"].split("?")[0].lower()
        if any(p.startswith(s) for s in SENSITIVE_PATHS):
            probes_by_ip.setdefault(e["ip"], []).append(e)
    for ip, probes in probes_by_ip.items():
        review.append({
            "rule": "needs_review",
            "topic": "rejected_sensitive_probes",
            "first_seen": probes[0]["ts_raw"],
            "last_seen": probes[-1]["ts_raw"],
            "entities": {"src_ip": ip, "host": probes[0]["host"],
                         "paths": sorted({p["path"] for p in probes})},
            "evidence": [
                ev_item(p, f"{ip} 请求敏感路径 {p['path']} 被拒绝（HTTP {p['status']}）")
                for p in probes
            ],
            "missing_context": [
                "授权扫描器/漏扫平台的 IP 清单（判断是否为计划内扫描）",
                "该 IP 的威胁情报与历史告警记录",
                "WAF/负载均衡侧是否还有未进入本日志的后续请求",
            ],
            "reason": (
                f"{ev_ref(probes[0])} 至 {ev_ref(probes[-1])}：{ip} 探测 "
                f"{', '.join(p['path'] for p in probes)} 均被 4xx 拒绝。"
                f"请求未成功、日志中也无后续利用动作，无法区分攻击踩点与授权扫描，"
                f"需上述上下文定性。"
            ),
        })
    return review


def scan(path: str) -> dict:
    events = parse_events(path)
    findings = detect_privilege_escalation(events) + detect_webshell(events)
    findings.sort(key=lambda f: f["first_seen"])
    return {"findings": findings, "needs_review": detect_needs_review(events)}


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: detector.py <log> <out.json>")
        return 2
    result = scan(sys.argv[1])
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    print(f"{len(result['findings'])} findings, "
          f"{len(result['needs_review'])} needs_review -> {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
