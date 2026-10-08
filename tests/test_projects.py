"""v1.7 proje defteri (multi-project) testleri.

Platform açısından: birden fazla müşetti/hedef projesini tek yerden yönetmek —
her projenin kendi scope sözleşmesi, çalışma dizini, delta geçmişi ve
policy ayarı olur; defter fail-closed (bozuk kayıt = RED).
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from purpleloop.projects import ProjectRegistry, ProjectRecord  # noqa: E402


def _write(p, d):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(d), encoding="utf-8")


def test_registry_add_and_list(tmp_path):
    reg = ProjectRegistry(tmp_path / "projects.json")
    reg.add(ProjectRecord(
        id="acme-web", ad="ACME Web", hedef=["10.0.0.5"],
        portlar=[80, 443], scope_dosyasi=str(tmp_path / "acme.json"),
        out_dir=str(tmp_path / "acme-run")))
    names = [p.id for p in reg.list_all()]
    assert names == ["acme-web"]


def test_registry_duplicate_id_rejected(tmp_path):
    reg = ProjectRegistry(tmp_path / "projects.json")
    rec = ProjectRecord(id="acme-web", ad="ACME", hedef=["10.0.0.5"],
                        portlar=[80], scope_dosyasi="s.json", out_dir="o")
    reg.add(rec)
    with pytest.raises(ValueError):
        reg.add(rec)


def test_registry_persistence(tmp_path):
    """Kapanıp açılınca kayıtlar korunmalı."""
    reg = ProjectRegistry(tmp_path / "projects.json")
    reg.add(ProjectRecord(id="p1", ad="P1", hedef=["h"], portlar=[1],
                          scope_dosyasi="s", out_dir="o"))
    reg2 = ProjectRegistry(tmp_path / "projects.json")
    assert [p.id for p in reg2.list_all()] == ["p1"]


def test_registry_corrupt_fails_closed(tmp_path):
    """Bozuk defter dosyası = KIRMIZI (sessiz boş liste değil)."""
    bad = tmp_path / "projects.json"
    bad.write_text("{bozuk json", encoding="utf-8")
    with pytest.raises(Exception):
        ProjectRegistry(bad)


def test_scan_all_runs_each_project(tmp_path):
    """scan_all: her proje için scope yüklenip tarama ÇAĞRILIR (fake ile say)."""
    _write(tmp_path / "a.json", {"targets": ["127.0.0.1"], "ports": [8081], "methods": ["GET"]})
    _write(tmp_path / "b.json", {"targets": ["127.0.0.1"], "ports": [9010], "methods": ["GET"]})
    reg = ProjectRegistry(tmp_path / "projects.json")
    reg.add(ProjectRecord(id="a", ad="A", hedef=["127.0.0.1"], portlar=[8081],
                          scope_dosyasi=str(tmp_path / "a.json"),
                          out_dir=str(tmp_path / "run-a")))
    reg.add(ProjectRecord(id="b", ad="B", hedef=["127.0.0.1"], portlar=[9010],
                          scope_dosyasi=str(tmp_path / "b.json"),
                          out_dir=str(tmp_path / "run-b")))
    calls = []
    # sahte tarama fonksiyonu enjekte et
    results = reg.scan_all(scanner=lambda rec: calls.append(rec.id) or {"bulgu": 3})
    assert sorted(calls) == ["a", "b"]
    assert results["a"]["bulgu"] == 3 and results["b"]["bulgu"] == 3


def test_scan_all_missing_scope_fails_closed(tmp_path):
    """Scope dosyası eksik proje = o proje RED, diğerleri koşar, hata kayda geçer."""
    _write(tmp_path / "a.json", {"targets": ["127.0.0.1"], "ports": [8081], "methods": ["GET"]})
    reg = ProjectRegistry(tmp_path / "projects.json")
    reg.add(ProjectRecord(id="a", ad="A", hedef=["127.0.0.1"], portlar=[8081],
                          scope_dosyasi=str(tmp_path / "a.json"),
                          out_dir=str(tmp_path / "run-a")))
    reg.add(ProjectRecord(id="eksik", ad="E", hedef=["x"], portlar=[1],
                          scope_dosyasi=str(tmp_path / "yok.json"),
                          out_dir=str(tmp_path / "run-e")))
    results = reg.scan_all(scanner=lambda rec: {"bulgu": 1})
    assert results["a"]["bulgu"] == 1
    assert "hata" in results["eksik"]
