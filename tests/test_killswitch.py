import pytest

from purpleloop.killswitch import KillSwitch


def test_inactive_when_file_absent(tmp_path):
    ks = KillSwitch(str(tmp_path / "STOP"))
    assert ks.is_active() is False


def test_active_when_file_exists(tmp_path):
    p = tmp_path / "STOP"
    p.write_text("halt")
    assert KillSwitch(str(p)).is_active() is True


def test_empty_file_still_active(tmp_path):
    p = tmp_path / "STOP"
    p.touch()
    assert KillSwitch(str(p)).is_active() is True


def test_unreadable_dir_fail_closed(tmp_path):
    d = tmp_path / "noperm"
    d.mkdir()
    d.chmod(0o000)
    try:
        assert KillSwitch(str(d / "x" / "STOP")).is_active() is True
    finally:
        d.chmod(0o755)


def test_any_active(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    b.write_text("stop")
    assert KillSwitch.any_active([str(a), str(b)]) is True
    assert KillSwitch.any_active([str(a)]) is False
    assert KillSwitch.any_active(None) is False
    assert KillSwitch.any_active([]) is False
