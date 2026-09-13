"""Exercise the online backup against an isolated disposable Compose stack."""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import tempfile
import textwrap
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
WRITERS = ("portal", "awg-controller", "sing-box", "adguard-home", "caddy")
SERVICES = ("portal", "awg2", "awg-controller", "sing-box", "adguard-home", "caddy")
VOLUMES = (
    "portal_data", "auth_data", "ru_configs", "awg_data", "awg_control",
    "awg_network", "router_state", "routing_status", "adguard_work",
    "caddy_data", "caddy_config",
)


def run(*args: str, cwd: pathlib.Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed:\n{result.stdout}{result.stderr}")
    return result


def main() -> None:
    subprocess.run(["docker", "info"], check=True, stdout=subprocess.DEVNULL)
    with tempfile.TemporaryDirectory(prefix="aas-backup-test-") as raw_path:
        path = pathlib.Path(raw_path)
        (path / "compose.yml").write_text(textwrap.dedent("""
            services:
              portal:
                image: alpine:3.22
                command: [sh, -c, "touch /data/portal.db /auth/auth.db /ru-configs/index; exec sleep 300"]
                volumes: [portal_data:/data, auth_data:/auth, ru_configs:/ru-configs]
              awg2:
                image: alpine:3.22
                command: [sleep, "300"]
                volumes: [awg_control:/awg-control]
              awg-controller:
                image: alpine:3.22
                command: [sh, -c, "touch /awg-data/native.db /awg-control/status.json /awg-network/network.json; exec sleep 300"]
                volumes: [awg_data:/awg-data, awg_control:/awg-control, awg_network:/awg-network]
              sing-box:
                image: alpine:3.22
                command: [sh, -c, "touch /router-state/state.json /routing-status/status.json; exec sleep 300"]
                volumes: [router_state:/router-state, routing_status:/routing-status]
              adguard-home:
                image: alpine:3.22
                command: [sleep, "300"]
                volumes: [adguard_work:/work]
              caddy:
                image: alpine:3.22
                command: [sh, -c, "touch /data/cert /config/config.json; exec sleep 300"]
                volumes: [caddy_data:/data, caddy_config:/config]
            volumes:
              portal_data: {}
              auth_data: {}
              ru_configs: {}
              awg_data: {}
              awg_control: {}
              awg_network: {}
              router_state: {}
              routing_status: {}
              adguard_work: {}
              caddy_data: {}
              caddy_config: {}
        """).lstrip())
        try:
            run("docker", "compose", "up", "-d", "--quiet-pull", cwd=path)
            # Keep the largest production-like writer snapshot representative.
            run(
                "docker", "compose", "exec", "-T", "adguard-home", "sh", "-c",
                "dd if=/dev/urandom of=/work/querylog.bin bs=1M count=6 status=none",
                cwd=path,
            )
            result_file = path / "backup-result"
            env = {
                **os.environ,
                "AAS_MAINTENANCE_LOCKED": "1",
                "AAS_BACKUP_ROOT": str(path),
                "AAS_BACKUP_MODE": "online",
                "AAS_BACKUP_RESULT_FILE": str(result_file),
            }
            result = run(str(ROOT / "scripts" / "backup.sh"), cwd=path, env=env)
            backup = pathlib.Path(result_file.read_text().strip())
            assert (backup / "COMPLETE").is_file()
            assert (backup / "mode").read_text().strip() == "online"
            for volume in VOLUMES:
                assert (backup / f"volume-{volume}.tar.gz").is_file(), volume
            for service in SERVICES:
                state = run(
                    "docker", "compose", "ps", "-q", service, cwd=path,
                ).stdout.strip()
                inspect = run(
                    "docker", "inspect", "--format", "{{.State.Running}} {{.State.Paused}}", state,
                    cwd=path,
                ).stdout.strip()
                assert inspect == "true false", (service, inspect)
            portal = run("docker", "compose", "ps", "-q", "portal", cwd=path).stdout.strip()
            maintenance = subprocess.run(
                ["docker", "exec", portal, "test", "-e", "/data/maintenance"],
                cwd=path,
            )
            assert maintenance.returncode != 0
            pauses = {
                service: int(milliseconds)
                for service, milliseconds in re.findall(r"Snapshot pause: (\S+) (\d+)ms", result.stdout)
            }
            assert pauses.keys() == set(WRITERS), pauses
            assert max(pauses.values()) <= 1000, pauses
            print(f"Online backup pauses: {pauses}", flush=True)
            # The first deployment of the split backs up the previous release,
            # where awg2 itself still owns the database and control volumes.
            run("docker", "compose", "stop", "awg-controller", cwd=path)
            time.sleep(1.1)  # Backups use human-readable second-resolution directories.
            legacy_result = run(str(ROOT / "scripts" / "backup.sh"), cwd=path, env=env)
            legacy_pauses = {
                service: int(milliseconds)
                for service, milliseconds in re.findall(r"Snapshot pause: (\S+) (\d+)ms", legacy_result.stdout)
            }
            assert "awg2" in legacy_pauses and "awg-controller" not in legacy_pauses, legacy_pauses
            assert max(legacy_pauses.values()) <= 1000, legacy_pauses
            print(f"Legacy AWG backup fallback pauses: {legacy_pauses}", flush=True)
        finally:
            subprocess.run(
                ["docker", "compose", "down", "-v", "--remove-orphans"],
                cwd=path,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


if __name__ == "__main__":
    main()
