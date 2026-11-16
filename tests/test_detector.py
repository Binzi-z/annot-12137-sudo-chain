import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "logs", "auth.log")

# 良性相似流量：少量失败后成功（10.20.1.77）、被拒绝的探测（10.20.1.88）
BENIGN_IPS = {"10.20.1.77", "10.20.1.88"}


def run(tmp_path, log=LOG):
    out = tmp_path / "out.json"
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "detector", "detector.py"), log, str(out)],
        capture_output=True, text=True,
    )
    return r, out


def load(tmp_path):
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text(encoding="utf-8"))


def test_corpus_and_labels():
    assert os.path.exists(LOG)
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        data = json.load(fh)
    assert len(data["events"]) == 2


def test_detector_runs(tmp_path):
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "findings" in json.loads(out.read_text(encoding="utf-8"))


def test_findings_have_required_fields(tmp_path):
    for f in load(tmp_path)["findings"]:
        assert f.get("rule")
        assert f.get("first_seen") and f.get("last_seen")
        assert f.get("entities")
        assert f.get("evidence"), "每条告警必须给出触发序列"
        for ev in f["evidence"]:
            assert ev.get("line") and ev.get("raw"), "证据必须引用具体日志事件"
        assert f.get("reason"), "每条告警必须给出判定理由"


def test_labels_all_hit(tmp_path):
    findings = load(tmp_path)["findings"]
    pe = [f for f in findings if f["rule"] == "privilege_escalation"]
    ws = [f for f in findings if f["rule"] == "webshell"]
    assert any(f["entities"].get("user") == "ops" for f in pe), "未命中标注的提权事件"
    assert any(f["entities"].get("src_ip") == "10.20.1.51" for f in ws), "未命中标注的 webshell 事件"


def test_zero_false_positives_on_benign_lookalikes(tmp_path):
    findings = load(tmp_path)["findings"]
    assert len(findings) == 2, f"良性相似流量产生了误报: {findings}"
    for f in findings:
        entity_text = json.dumps(f["entities"], ensure_ascii=False)
        assert not any(ip in entity_text for ip in BENIGN_IPS)


def test_needs_review_states_missing_context(tmp_path):
    review = load(tmp_path)["needs_review"]
    assert review, "无法判定的序列应列入 needs_review"
    for item in review:
        assert item.get("missing_context"), "needs_review 必须说明缺少哪类上下文"
        assert item.get("evidence") and item.get("reason")


def test_empty_log_yields_no_findings(tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    r, out = run(tmp_path, str(empty))
    assert r.returncode == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["findings"] == []
    assert data["needs_review"] == []
