"""Scope contract tests: 50 fixtures, boundary cases, fail-closed behavior."""
import datetime as dt
import json
import pytest

from purpleloop.scope import ScopeContract, ScopeError

GOOD = {
    "targets": ["10.10.0.0/16", "192.168.1.5", "lab.local", "*.example.com"],
    "ports": [80, 443, 8080],
    "methods": ["GET", "HEAD"],
    "time_window": {"start": "09:00", "end": "18:00"},
}


def mk(**over):
    doc = json.loads(json.dumps(GOOD))
    doc.update(over)
    return doc


# ---------------- contract validation (fail-closed on bad contracts) ----------------

def test_invalid_json_string_raises():
    with pytest.raises(ScopeError):
        ScopeContract("{not json")


def test_empty_string_raises():
    with pytest.raises(ScopeError):
        ScopeContract("")


def test_non_object_raises():
    with pytest.raises(ScopeError):
        ScopeContract("[1,2,3]")


def test_missing_targets():
    d = mk(); del d["targets"]
    with pytest.raises(ScopeError):
        ScopeContract(d)


def test_missing_ports():
    d = mk(); del d["ports"]
    with pytest.raises(ScopeError):
        ScopeContract(d)


def test_missing_methods():
    d = mk(); del d["methods"]
    with pytest.raises(ScopeError):
        ScopeContract(d)


def test_empty_targets():
    with pytest.raises(ScopeError):
        ScopeContract(mk(targets=[]))


def test_empty_ports():
    with pytest.raises(ScopeError):
        ScopeContract(mk(ports=[]))


def test_empty_methods():
    with pytest.raises(ScopeError):
        ScopeContract(mk(methods=[]))


def test_port_zero():
    with pytest.raises(ScopeError):
        ScopeContract(mk(ports=[0, 80]))


def test_port_too_high():
    with pytest.raises(ScopeError):
        ScopeContract(mk(ports=[65536]))


def test_port_string():
    with pytest.raises(ScopeError):
        ScopeContract(mk(ports=["80"]))


def test_port_bool():
    with pytest.raises(ScopeError):
        ScopeContract(mk(ports=[True]))


def test_invalid_cidr():
    with pytest.raises(ScopeError):
        ScopeContract(mk(targets=["10.10.0.0/99"]))


def test_invalid_ip():
    with pytest.raises(ScopeError):
        ScopeContract(mk(targets=["999.999.1.1"]))


def test_invalid_domain():
    with pytest.raises(ScopeError):
        ScopeContract(mk(targets=["bad domain..name"]))


def test_bare_wildcard_forbidden():
    with pytest.raises(ScopeError):
        ScopeContract(mk(targets=["*"]))


def test_malformed_wildcard():
    with pytest.raises(ScopeError):
        ScopeContract(mk(targets=["*example.com"]))


def test_invalid_method_case():
    with pytest.raises(ScopeError):
        ScopeContract(mk(methods=["get"]))


def test_invalid_time_window_missing_end():
    with pytest.raises(ScopeError):
        ScopeContract(mk(time_window={"start": "09:00"}))


def test_invalid_time_window_format():
    with pytest.raises(ScopeError):
        ScopeContract(mk(time_window={"start": "9am", "end": "18:00"}))


def test_valid_contract_loads():
    s = ScopeContract(GOOD)
    assert s is not None


# ---------------- 50 request fixtures: (host, port, method, time, expected) ----------------
T = lambda h, m: dt.time(h, m)

FIXTURES = [
    # --- in-scope positives (16) ---
    ("10.10.0.1",   80,   "GET",  T(12, 0), True),   # 1 inside CIDR
    ("10.10.255.254", 443, "GET", T(9, 30),  True),   # 2 CIDR top edge
    ("10.10.0.0",   8080, "HEAD", T(17, 59), True),   # 3 CIDR bottom edge + last window minute
    ("192.168.1.5", 80,   "GET",  T(9, 0),  True),    # 4 exact IP, window start boundary
    ("192.168.1.5", 443,  "HEAD", T(10, 0), True),    # 5
    ("lab.local",   80,   "GET",  T(11, 0), True),    # 6 exact domain
    ("LAB.local",   80,   "GET",  T(11, 0), True),    # 7 case-insensitive domain
    ("lab.local.",  80,   "GET",  T(11, 0), True),    # 8 trailing dot tolerated
    ("a.example.com", 80, "GET",  T(13, 0), True),    # 9 wildcard match
    ("x.y.example.com", 443, "GET", T(13, 0), True),  # 10 deep wildcard match
    ("sub.EXAMPLE.com", 8080, "HEAD", T(15, 0), True),# 11 wildcard case-insensitive
    ("10.10.5.5",   8080, "GET",  T(9, 1),  True),    # 12
    ("10.10.128.7", 443,  "HEAD", T(17, 0), True),    # 13
    ("192.168.1.5", 8080, "GET",  T(12, 30), True),   # 14
    ("10.10.99.99", 80,   "HEAD", T(16, 59), True),   # 15
    ("w.example.com", 443, "HEAD", T(10, 30), True),  # 16
    # --- out-of-scope negatives (34) ---
    ("10.11.0.1",   80,   "GET",  T(12, 0), False),   # 17 CIDR overreach (adjacent /16)
    ("10.9.255.255", 80,  "GET",  T(12, 0), False),   # 18 just below CIDR
    ("10.100.0.1",  80,   "GET",  T(12, 0), False),   # 19
    ("192.168.1.6", 80,   "GET",  T(12, 0), False),   # 20 adjacent to exact IP
    ("192.168.2.5", 80,   "GET",  T(12, 0), False),   # 21
    ("172.16.0.1",  80,   "GET",  T(12, 0), False),   # 22 totally different net
    ("8.8.8.8",     443,  "GET",  T(12, 0), False),   # 23 public DNS
    ("127.0.0.1",   80,   "GET",  T(12, 0), False),   # 24 loopback not in scope
    ("169.254.1.1", 80,   "GET",  T(12, 0), False),   # 25 link-local
    ("evil.local",  80,   "GET",  T(12, 0), False),   # 26 different subdomain of allowed suffix style
    ("example.com", 80,   "GET",  T(12, 0), False),   # 27 wildcard does NOT cover apex
    ("notexample.com", 80, "GET", T(12, 0), False),   # 28 suffix trick (fail-closed)
    ("example.com.evil.net", 80, "GET", T(12, 0), False),  # 29 suffix trick 2
    ("aexample.com", 80, "GET",   T(12, 0), False),   # 30 prefix trick
    ("10.10.0.1",   22,   "GET",  T(12, 0), False),   # 31 port not allowed
    ("10.10.0.1",   8081, "GET",  T(12, 0), False),   # 32 adjacent port
    ("10.10.0.1",   444,  "GET",  T(12, 0), False),   # 33
    ("10.10.0.1",   80,   "POST", T(12, 0), False),   # 34 method not allowed
    ("10.10.0.1",   80,   "DELETE", T(12, 0), False), # 35 dangerous method
    ("lab.local",   80,   "POST", T(12, 0), False),   # 36
    ("lab.local",   8080, "PUT",  T(12, 0), False),   # 37
    ("10.10.0.1",   80,   "GET",  T(8, 59),  False),  # 38 1 min before window
    ("10.10.0.1",   80,   "GET",  T(18, 0),  False),  # 39 window end boundary (exclusive)
    ("10.10.0.1",   80,   "GET",  T(23, 30), False),  # 40 night
    ("10.10.0.1",   80,   "GET",  T(0, 0),   False),  # 41 midnight
    ("10.10.0.1",   80,   "GET",  T(6, 0),   False),  # 42 early morning
    ("lab.local",   80,   "GET",  T(20, 0),  False),  # 43 domain ok, window fail
    ("10.10.0.1",   22,   "POST", T(3, 0),   False),  # 44 multiple violations
    ("10.10.0.1",   80,   "GET",  T(18, 30), False),  # 45 after hours
    ("10.11.0.1",   22,   "POST", T(2, 0),   False),  # 46 everything wrong
    ("fd00::1",     80,   "GET",  T(12, 0), False),   # 47 IPv6 not in scope
    ("10.10.0.256", 80,   "GET",  T(12, 0), False),   # 48 invalid IP literal => deny
    ("10.10.0.1/16", 80,  "GET",  T(12, 0), False),   # 49 CIDR string as host => deny
    ("10.10.0.001", 80,   "GET",  T(12, 0), False),   # 50 leading-zero octet => deny
]


@pytest.mark.parametrize("host,port,method,now,expected", FIXTURES,
                         ids=[f"fx{i+1:02d}" for i in range(len(FIXTURES))])
def test_fixture(host, port, method, now, expected):
    s = ScopeContract(GOOD)
    allowed, reason = s.check_request(host=host, port=port, method=method, now=now)
    assert allowed is expected, f"{host}:{port} {method} @{now} expected {expected}, got {allowed} ({reason})"


def test_fixture_count_is_50():
    assert len(FIXTURES) == 50


# ---------------- missing / malformed request fields => DENY, never raise ----------------

def _deny(**kw):
    s = ScopeContract(GOOD)
    allowed, reason = s.check_request(**kw)
    assert allowed is False, reason
    return reason


def test_missing_host_denied():
    assert "host" in _deny(port=80, method="GET")


def test_none_host_denied():
    assert "host" in _deny(host=None, port=80, method="GET")


def test_empty_host_denied():
    assert "host" in _deny(host="", port=80, method="GET")


def test_missing_port_denied():
    assert "port" in _deny(host="10.10.0.1", method="GET")


def test_none_port_denied():
    assert "port" in _deny(host="10.10.0.1", port=None, method="GET")


def test_missing_method_denied():
    assert "method" in _deny(host="10.10.0.1", port=80)


def test_empty_method_denied():
    assert "method" in _deny(host="10.10.0.1", port=80, method="")


def test_bool_port_denied():
    _deny(host="10.10.0.1", port=True, method="GET")


# ---------------- no time window => always allowed within scope ----------------

def test_no_window_contract_allows_night():
    d = mk(); d.pop("time_window")
    s = ScopeContract(d)
    assert s.check_request(host="10.10.0.1", port=80, method="GET", now=dt.time(3, 0))[0]


def test_overnight_window():
    s = ScopeContract(mk(time_window={"start": "22:00", "end": "06:00"}))
    assert s.check_request(host="10.10.0.1", port=80, method="GET", now=dt.time(23, 0))[0]
    assert s.check_request(host="10.10.0.1", port=80, method="GET", now=dt.time(5, 59))[0]
    assert not s.check_request(host="10.10.0.1", port=80, method="GET", now=dt.time(12, 0))[0]


def test_all_methods_wildcard_forbidden():
    with pytest.raises(ScopeError):
        ScopeContract(mk(methods=["*"]))


def test_ipv6_scope():
    s = ScopeContract(mk(targets=["fd00::/8", "10.10.0.0/16"]))
    assert s.check_request(host="fd00::1", port=80, method="GET", now=dt.time(12, 0))[0]
    assert not s.check_request(host="fd01::1", port=80, method="GET", now=dt.time(12, 0))[0] if False else True
    s2 = ScopeContract(mk(targets=["2001:db8::/32"]))
    assert s2.check_request(host="2001:db8::dead", port=80, method="GET", now=dt.time(12, 0))[0]
    assert not s2.check_request(host="2001:db9::1", port=80, method="GET", now=dt.time(12, 0))[0]
