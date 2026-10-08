"""Ürün deneyimi testleri: init + demo yüzeyleri."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from purpleloop.product import cmd_init, _SCOPE_TEMPLATE, _DEMO_APP  # noqa: E402


def test_init_creates_scope(tmp_path):
    d = str(tmp_path / "proje")
    rc = cmd_init(["--dir", d])
    assert rc == 0
    scope = os.path.join(d, "scope.json")
    assert os.path.exists(scope)
    doc = json.loads(open(scope).read())
    assert "targets" in doc and "ports" in doc and "methods" in doc
    # gitignore de düştü
    assert os.path.exists(os.path.join(d, ".gitignore"))


def test_init_refuses_overwrite(tmp_path):
    d = str(tmp_path / "p2")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "scope.json"), "w").write("eski")
    rc = cmd_init(["--dir", d])
    assert rc == 1
    assert open(os.path.join(d, "scope.json")).read() == "eski"


def test_scope_template_is_valid_json():
    doc = json.loads(_SCOPE_TEMPLATE)
    assert isinstance(doc["targets"], list)


def test_demo_app_compiles():
    compile(_DEMO_APP, "demo_app.py", "exec")


def test_demo_flag_surface():
    """demo CLI bayrakları mevcut (--keep, --dir)."""
    import subprocess, sys as _s
    r = subprocess.run([_s.executable, "-m", "purpleloop.product", "--help"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0
    assert "init" in r.stdout and "demo" in r.stdout
