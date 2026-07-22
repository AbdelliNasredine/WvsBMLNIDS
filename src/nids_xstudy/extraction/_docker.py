"""Helper for running a Dockerized extractor over a PCAP.

Each Docker-based runner mounts the PCAP's directory read-only and an output
directory read-write, then invokes the tool inside the container. We mount
directories (not files) because Docker Desktop on Windows handles bind-mounting
a directory more reliably than a single large file.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class DockerUnavailable(RuntimeError):
    pass


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=20)
        return r.returncode == 0
    except Exception:
        return False


def image_exists(image: str) -> bool:
    r = subprocess.run(["docker", "image", "inspect", image],
                       capture_output=True, text=True)
    return r.returncode == 0


def _win_mount(p: Path) -> str:
    """Docker Desktop accepts native Windows paths for bind mounts."""
    return str(Path(p).resolve())


def run(
    image: str,
    container_cmd: list[str],
    *,
    pcap: Path,
    out_dir: Path,
    workdir: str = "/work",
    extra_mounts: list[tuple[Path, str, str]] | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess:
    """Run ``container_cmd`` in ``image`` with the pcap dir + out dir mounted.

    Inside the container:
      * the pcap directory is mounted read-only at ``/pcaps``
      * ``out_dir`` is mounted read-write at ``/out``
      * the pcap is therefore at ``/pcaps/<pcap.name>``
    """
    if not docker_available():
        raise DockerUnavailable(
            "Docker daemon not reachable. Start Docker Desktop and retry."
        )
    pcap = Path(pcap)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    mounts = [
        "-v", f"{_win_mount(pcap.parent)}:/pcaps:ro",
        "-v", f"{_win_mount(out_dir)}:/out",
    ]
    for host, cont, mode in (extra_mounts or []):
        mounts += ["-v", f"{_win_mount(host)}:{cont}:{mode}"]

    env_flags = []
    for k, v in (env or {}).items():
        env_flags += ["-e", f"{k}={v}"]

    cmd = ["docker", "run", "--rm", "-w", workdir, *mounts, *env_flags, image, *container_cmd]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
