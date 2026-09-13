"""Verify that replacing the controller retains kernel state in the data plane."""

from __future__ import annotations

import os
import subprocess
import time


IMAGE = os.getenv("AWG_TEST_IMAGE", "aas-vpn-awg:native-test")
DATAPLANE = "aas-dataplane-check"
CONTROLLER = "aas-dataplane-controller-check"
VOLUME = "aas-dataplane-control-check"
INTERFACE = "aas-persist"
CAPS = (
    "/usr/sbin/capsh", "--inh=cap_net_admin,cap_net_raw",
    "--addamb=cap_net_admin,cap_net_raw", "--shell=/bin/sh", "--", "-c",
)


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(["docker", *args], text=True, capture_output=True, timeout=90)
    if check and result.returncode:
        raise RuntimeError(f"Docker test operation failed: {' '.join(args[:4])}\n{result.stderr}")
    return result


def main() -> None:
    for name in (DATAPLANE, CONTROLLER):
        if docker("inspect", name, check=False).returncode == 0:
            raise SystemExit(f"Test container already exists: {name}")
    if docker("volume", "inspect", VOLUME, check=False).returncode == 0:
        raise SystemExit(f"Test volume already exists: {VOLUME}")
    try:
        docker("volume", "create", VOLUME)
        docker(
            "run", "--rm", "--network", "none", "--user", "0:0",
            "-v", f"{VOLUME}:/awg-control", "--entrypoint", "chown", IMAGE,
            "1000:65532", "/awg-control",
        )
        docker(
            "run", "-d", "--name", DATAPLANE, "--network", "none",
            "-v", f"{VOLUME}:/awg-control", "--entrypoint", "/usr/local/bin/awg-dataplane", IMAGE,
        )
        for _ in range(20):
            marker = docker(
                "exec", DATAPLANE, "test", "-s", "/awg-control/dataplane-netns", check=False,
            )
            if marker.returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Data-plane namespace marker was not created")
        docker(
            "run", "-d", "--name", CONTROLLER, "--network", f"container:{DATAPLANE}",
            "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
            "--entrypoint", CAPS[0], IMAGE, *CAPS[1:],
            f"ip link add {INTERFACE} type dummy && ip link set {INTERFACE} up && exec sleep 300",
        )
        docker("exec", CONTROLLER, "ip", "link", "show", INTERFACE)
        docker("rm", "-f", CONTROLLER)
        docker("exec", DATAPLANE, "ip", "link", "show", INTERFACE)
        namespace = docker("exec", DATAPLANE, "readlink", "/proc/self/ns/net").stdout.strip()
        marker = docker("exec", DATAPLANE, "cat", "/awg-control/dataplane-netns").stdout.strip()
        assert namespace == marker
        docker(
            "run", "--rm", "--network", f"container:{DATAPLANE}",
            "--entrypoint", "ip", IMAGE, "link", "show", INTERFACE,
        )
        print("Controller replacement retained data-plane kernel state: passed", flush=True)
    finally:
        docker("rm", "-f", CONTROLLER, check=False)
        docker("rm", "-f", DATAPLANE, check=False)
        docker("volume", "rm", VOLUME, check=False)


if __name__ == "__main__":
    main()
