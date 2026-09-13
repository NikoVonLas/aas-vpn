from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_maintenance_marker_uses_networkless_service():
    deploy = (ROOT / 'scripts' / 'deploy.sh').read_text()
    marker_command = next(line for line in deploy.splitlines() if "Path('/data/maintenance').touch()" in line)

    assert '--entrypoint python storage-init' in marker_command
    assert '--entrypoint python portal' not in marker_command
    compose = (ROOT / 'compose.yml').read_text()
    storage = compose.split('  storage-init:', 1)[1].split('\n  awg2:', 1)[0]
    assert 'network_mode: none' in storage
