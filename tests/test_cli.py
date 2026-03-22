"""Tests for CLI commands."""
from click.testing import CliRunner

from cert_watch.cli import cli


class TestCLI:
    def test_demo_terminal(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["demo"])
        assert result.exit_code == 0
        assert "Certificate" in result.output or "CERT-" in result.output

    def test_demo_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["demo", "--format", "json"])
        assert result.exit_code == 0
        assert "health_score" in result.output
        assert "findings" in result.output

    def test_demo_html(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["demo", "--format", "html"])
        assert result.exit_code == 0
        assert "<html>" in result.output

    def test_rules_command(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["rules"])
        assert result.exit_code == 0
        assert "Certificate Expired" in result.output

    def test_scan_file(self, tmp_path, sample_inventory_yaml):
        inv = tmp_path / "certs.yaml"
        inv.write_text(sample_inventory_yaml)
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(inv)])
        assert result.exit_code == 0

    def test_scan_json(self, tmp_path, sample_inventory_yaml):
        inv = tmp_path / "certs.yaml"
        inv.write_text(sample_inventory_yaml)
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(inv), "--format", "json"])
        assert result.exit_code == 0
        assert "health_score" in result.output

    def test_scan_fail_on(self, tmp_path, sample_inventory_yaml):
        inv = tmp_path / "certs.yaml"
        inv.write_text(sample_inventory_yaml)
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(inv), "--fail-on", "critical"])
        assert result.exit_code == 1

    def test_scan_output_file(self, tmp_path, sample_inventory_yaml):
        inv = tmp_path / "certs.yaml"
        inv.write_text(sample_inventory_yaml)
        out = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(inv), "--format", "json", "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "cert-watch" in result.output
