from tech_debtor.scanner import scan_python_files


def test_finds_python_files(tmp_path):
    (tmp_path / "a.py").write_text("x = 1")
    (tmp_path / "b.py").write_text("y = 2")
    (tmp_path / "c.txt").write_text("not python")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "d.py").write_text("z = 3")

    files = list(scan_python_files(tmp_path, exclude=[]))
    assert len(files) == 3
    names = {f.name for f in files}
    assert names == {"a.py", "b.py", "d.py"}


def test_excludes_patterns(tmp_path):
    (tmp_path / "a.py").write_text("x = 1")
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "b.py").write_text("y = 2")

    files = list(scan_python_files(tmp_path, exclude=["migrations/"]))
    assert len(files) == 1
    assert files[0].name == "a.py"


def test_excludes_hidden_and_venv(tmp_path):
    (tmp_path / "a.py").write_text("x = 1")
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "b.py").write_text("y = 2")
    dot = tmp_path / ".hidden"
    dot.mkdir()
    (dot / "c.py").write_text("z = 3")

    files = list(scan_python_files(tmp_path, exclude=[]))
    assert len(files) == 1
