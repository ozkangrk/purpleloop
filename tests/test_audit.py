import json
import pytest

from purpleloop.audit import AuditLog, AuditTamperError


def test_append_and_verify(tmp_path):
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    for i in range(5):
        log.append("TEST_EVENT", n=i, detail=f"rec {i}")
    assert log.verify_chain() is True


def test_chain_links_prev_sha(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    log = AuditLog(p)
    log.append("A")
    log.append("B")
    lines = [json.loads(l) for l in open(p)]
    assert lines[0]["prev_sha256"] == "0" * 64
    assert lines[1]["prev_sha256"] == lines[0]["sha256"]


def test_tamper_field_detected(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    log = AuditLog(p)
    log.append("SCOPE_ALLOW", host="10.10.0.1")
    log.append("SCOPE_DENY", host="8.8.8.8")
    # attacker flips the DENY to ALLOW without rehashing
    lines = open(p).readlines()
    rec = json.loads(lines[1])
    rec["event"] = "SCOPE_ALLOW"
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
    open(p, "w").writelines(lines)
    with pytest.raises(AuditTamperError):
        AuditLog(p).verify_chain()


def test_deleted_line_detected(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    log = AuditLog(p)
    for i in range(4):
        log.append("E", i=i)
    lines = open(p).readlines()
    del lines[2]
    open(p, "w").writelines(lines)
    with pytest.raises(AuditTamperError):
        AuditLog(p).verify_chain()


def test_inserted_line_detected(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    log = AuditLog(p)
    log.append("E1")
    log.append("E2")
    forged = json.dumps({"event": "FAKE", "prev_sha256": "0" * 64, "sha256": "f" * 64}) + "\n"
    lines = open(p).readlines()
    lines.insert(1, forged)
    open(p, "w").writelines(lines)
    with pytest.raises(AuditTamperError):
        AuditLog(p).verify_chain()


def test_corrupt_json_detected(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    log = AuditLog(p)
    log.append("E1")
    with open(p, "a") as f:
        f.write("garbage{{{\n")
    with pytest.raises(AuditTamperError):
        AuditLog(p).verify_chain()


def test_scope_deny_is_audited(tmp_path):
    """End-to-end: scope denial must produce an immutable audit record."""
    from purpleloop.scope import ScopeContract
    p = str(tmp_path / "audit.jsonl")
    log = AuditLog(p)
    scope = ScopeContract({
        "targets": ["10.10.0.0/16"],
        "ports": [80],
        "methods": ["GET"],
    })
    allowed, reason = scope.check_request(host="8.8.8.8", port=80, method="GET")
    log.append("SCOPE_CHECK", allowed=allowed, reason=reason, host="8.8.8.8", port=80)
    recs = [json.loads(l) for l in open(p)]
    assert recs[0]["allowed"] is False
    assert log.verify_chain() is True
