from __future__ import annotations

import yaml

from bughunter.cli import main


def test_init_validate_and_scope(tmp_path, passive_policy_path, capsys):
    policy_path = tmp_path / "policies" / "demo.yaml"
    assert main(["init", "Demo Program", "--path", str(policy_path)]) == 0
    assert policy_path.exists()
    text = policy_path.read_text(encoding="utf-8")
    assert "confirmed: false" in text
    assert main(["validate", str(policy_path)]) == 0
    assert "NOT confirmed" in capsys.readouterr().out
    assert main(["scope", str(passive_policy_path), "https://api.example.com", "https://evil.test"]) == 1


def test_dry_run_makes_no_network(tmp_path, active_policy_path, capsys):
    result = main(
        [
            "hunt",
            str(active_policy_path),
            "--dry-run",
            "--data-dir",
            str(tmp_path / "state"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ]
    )
    assert result == 0
    output = capsys.readouterr().out
    assert "dry run" in output.lower()
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "reports").exists()


def test_unconfirmed_policy_refuses_to_run(tmp_path, passive_policy_path):
    data = yaml.safe_load(passive_policy_path.read_text(encoding="utf-8"))
    data["program"]["authorization"]["confirmed"] = False
    data["program"]["authorization"]["authorized_by"] = ""
    path = tmp_path / "unconfirmed.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    assert main(["hunt", str(path), "--data-dir", str(tmp_path / "state")]) == 2
    assert main(["hunt", str(path), "--dry-run", "--data-dir", str(tmp_path / "state")]) == 0
    assert not (tmp_path / "state").exists()


def test_runs_command_on_empty_state(tmp_path, capsys):
    assert main(["runs", "--data-dir", str(tmp_path / "state")]) == 0
    assert "No runs yet" in capsys.readouterr().out


def test_scope_command_reports_exclusion(tmp_path, passive_policy_path, capsys):
    assert main(["scope", str(passive_policy_path), "https://old.example.com"]) == 1
    output = capsys.readouterr().out
    assert "excluded" in output.lower()
