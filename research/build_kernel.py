"""Generic kernel builder: embed a submission/attack_*.py into a 4-cell notebook.

Usage:
  python research/build_kernel.py <src_file> <slug> <replay_safe> "<title>" "<assert_marker>"

e.g. python research/build_kernel.py submission/attack_v17.py aas-v17-mid 0.90 \
        "aas-v17-mid" "PAD_UNVALIDATED"

Self-checks: substitutes REPLAY_SAFE, py_compiles, verifies base64 round-trip and
that the assert_marker + substituted REPLAY_SAFE survive into the embedded source.
"""
from __future__ import annotations

import base64
import json
import re
import sys
import tempfile
import py_compile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def build(src_file: str, slug: str, replay_safe: float, title: str, marker: str) -> Path:
    src = (ROOT / src_file).read_text(encoding="utf-8")

    src2, n = re.subn(r"(?m)^REPLAY_SAFE = [0-9.]+", f"REPLAY_SAFE = {replay_safe}", src)
    if n != 1:
        raise SystemExit(f"expected exactly 1 REPLAY_SAFE assignment, found {n}")

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tf:
        tf.write(src2)
        tmp = tf.name
    py_compile.compile(tmp, doraise=True)

    b64 = base64.b64encode(src2.encode("utf-8")).decode("ascii")
    assert base64.b64decode(b64).decode("utf-8") == src2, "b64 roundtrip mismatch"

    cell_title = f"# {slug} | REPLAY_SAFE={replay_safe} | marker={marker}"
    cell_path = (
        "import sys, os, glob\n"
        "from pathlib import Path\n"
        "sys.argv=[sys.argv[0]]\n"
        "for c in glob.glob('/kaggle/input/**/kaggle_evaluation', recursive=True):\n"
        "    r=str(Path(c).parent)\n"
        "    if r not in sys.path: sys.path.insert(0,r)\n"
        "    print('root',r); break\n"
        "print('IS_RERUN:', bool(os.getenv('KAGGLE_IS_COMPETITION_RERUN')))\n"
    )
    cell_write = (
        "import base64, py_compile\n"
        "from pathlib import Path\n"
        "Path('/kaggle/working').mkdir(parents=True, exist_ok=True)\n"
        f'ATTACK_B64 = "{b64}"\n'
        "src=base64.b64decode(ATTACK_B64).decode('utf-8')\n"
        "open('/kaggle/working/attack.py','w',encoding='utf-8').write(src)\n"
        "py_compile.compile('/kaggle/working/attack.py', doraise=True)\n"
        f"assert {marker!r} in src and 'REPLAY_SAFE = {replay_safe}' in src\n"
        f"print('attack.py {slug} written', len(src))\n"
    )
    cell_serve = (
        "import os, csv\n"
        "if bool(os.getenv('KAGGLE_IS_COMPETITION_RERUN')):\n"
        "    import kaggle_evaluation.jed_attack_134815.jed_attack_inference_server as server\n"
        "    server.JEDAttackInferenceServer().serve()\n"
        "else:\n"
        "    with open('/kaggle/working/submission.csv','w',newline='') as f:\n"
        "        w=csv.writer(f); w.writerow(['Id','Score'])\n"
        "        for r in ['gpt_oss_public','gpt_oss_private','gemma_public','gemma_private']: w.writerow([r,0.0])\n"
        "    print('placeholder')\n"
    )

    def code_cell(source: str) -> dict:
        return {"cell_type": "code", "execution_count": None, "metadata": {},
                "outputs": [], "source": source.splitlines(keepends=True)}

    nb = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": [cell_title]},
            code_cell(cell_path), code_cell(cell_write), code_cell(cell_serve),
        ],
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "version": "3.11"},
        },
        "nbformat": 4, "nbformat_minor": 5,
    }

    kdir = ROOT / f"kernel_{slug}"
    kdir.mkdir(exist_ok=True)
    nb_path = kdir / f"{slug}.ipynb"
    nb_path.write_text(json.dumps(nb, ensure_ascii=False, indent=1), encoding="utf-8")

    meta = {
        "id": f"yuyizhu/{slug}", "title": title, "code_file": f"{slug}.ipynb",
        "language": "python", "kernel_type": "notebook", "is_private": True,
        "enable_gpu": True, "enable_tpu": False, "enable_internet": False,
        "dataset_sources": [], "competition_sources": ["ai-agent-security-multi-step-tool-attacks"],
        "kernel_sources": [], "model_sources": [], "machine_shape": "NvidiaTeslaT4",
    }
    (kdir / "kernel-metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    written = json.loads(nb_path.read_text(encoding="utf-8"))
    c2 = "".join(written["cells"][2]["source"])
    decoded = base64.b64decode(re.search(r'ATTACK_B64 = "([^"]+)"', c2).group(1)).decode("utf-8")
    assert f"REPLAY_SAFE = {replay_safe}" in decoded and marker in decoded, "embedded marker mismatch"
    print(f"[build] {nb_path} ({nb_path.stat().st_size}B) attack {len(src2)} chars, "
          f"REPLAY_SAFE={replay_safe}, marker={marker} OK")
    return kdir


if __name__ == "__main__":
    if len(sys.argv) != 6:
        raise SystemExit("usage: build_kernel.py <src_file> <slug> <replay_safe> <title> <marker>")
    build(sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4], sys.argv[5])
