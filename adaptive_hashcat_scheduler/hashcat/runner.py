from __future__ import annotations
import os, subprocess
from typing import Optional

EXIT_MEANINGS = {0: 'success', 1: 'exhausted', 4: 'runtime_reached'}

def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return p.returncode, p.stdout, p.stderr

def build_hashcat_command(hashcat_bin: str, hash_mode: int, attack_mode: int, runtime: int, potfile: str, hashes: str,
                          candidate: Optional[str] = None, skip: int = 0, limit: Optional[int] = None,
                          extra_args: Optional[list[str]] = None, optimized_kernels: bool = True,
                          potfile_path_override: Optional[str] = None) -> list[str]:
    cmd = [hashcat_bin, '-m', str(hash_mode)]
    if optimized_kernels:
        cmd.append('-O')
    cmd.extend(['-a', str(attack_mode), '--runtime', str(runtime),
                '--status', '--status-json', '--status-timer', '5', '--potfile-path', os.fspath(potfile_path_override or potfile), hashes])
    if skip > 0:
        cmd.extend(['--skip', str(skip)])
    if limit is not None:
        cmd.extend(['--limit', str(limit)])
    if extra_args:
        cmd.extend(extra_args)
    if candidate:
        cmd.append(candidate)
    return cmd
