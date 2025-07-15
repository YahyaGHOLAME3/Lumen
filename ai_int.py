#!/usr/bin/env python3
"""
PentestGPT – autonomous internal-network reconnaissance driver
--------------------------------------------------------------

*   Loads a local GGUF model with `llama-cpp-python`
*   Talks to the model in a strict JSON-only format
*   Executes only safe discovery commands (nmap, masscan, dig …)
*   Rotates its own logs, supports dry-run, graceful SIGTERM/SIGINT
"""

# pip install llama-cpp-python python-json-logger tenacity

from __future__ import annotations

import argparse
import json
import logging
import re
import signal
import subprocess
import sys
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from llama_cpp import Llama
from tenacity import retry, stop_after_attempt, wait_exponential

# ──────────────────────────────────────────────────────────────
# 0. Globals & constants
# ──────────────────────────────────────────────────────────────
DEFAULT_MODEL_REPO = "mav23/Pentest_AI-GGUF"
DEFAULT_MODEL_FILE = "pentest_ai.Q4_1.gguf"

SYSTEM_PROMPT = r"""
You are **PentestGPT**, an elite internal-network penetration-testing assistant.

╭──────────────────────────────────────────────────────────────╮
│  --- OUTPUT FORMAT – MANDATORY & EXCLUSIVE ---               │
│  • Respond **once only** per turn, as **valid JSON** with    │
│    exactly these two keys and no extra whitespace keys:      │
│      1. "command"        — string  | null                    │
│      2. "justification"  — string                            │
│  • If there is nothing useful left to do, set                │
│        "command": null                                       │
│  • Do **not** wrap JSON in markdown fences.                  │
╰──────────────────────────────────────────────────────────────╯

╭──────────────────────────────────────────────────────────────╮
│  🔹 COMMAND RULES                                            │
│  • Use **one** shell command per turn.                       │
│  • Allowed binaries (case-insensitive):                      │
│      nmap, masscan, host, dig, smbclient                     │
│  • Insert the literal token <TARGET_IP_RANGE> wherever the   │
│    target network should appear.                             │
│  • No exploits, brute-force, password-spray, DoS, or traffic │
│    flooding parameters. Discovery & enumeration only.        │
│  • Avoid repeating commands that have already run *unless*   │
│    new data from prior output justifies it.                  │
╰──────────────────────────────────────────────────────────────╯

╭──────────────────────────────────────────────────────────────╮
│  🔹 STRATEGY GUIDANCE                                        │
│  1. **Host discovery** → 2. **Port scan** → 3. **Service     │
│     enumeration** → 4. **Light version-detection / vuln      │
│     check** (safe NSE or banner grabs).                      │
│  5. If nothing new is revealed, finish with "command": null. │
│  • Prefer fast but thorough syntax:                          │
│      – masscan for large ranges, then selective nmap follow- │
│        ups.                                                  │
│      – Use -sV, -O, --script=*safe* only when warranted.     │
│  • Justification should be ≤ 30 words, reference prior       │
│    findings briefly, and state the goal of the next command. │
╰──────────────────────────────────────────────────────────────╯

╭──────────────────────────────────────────────────────────────╮
│  🔹 REASONING INSTRUCTIONS                                   │
│  • Think step-by-step *internally* but expose **only** the   │
│    JSON.                                                     │
│  • Validate that the proposed command matches the allow-list │
│    and contains <TARGET_IP_RANGE> before you output.         │
╰──────────────────────────────────────────────────────────────╯
"""

ALLOW_CMD = re.compile(r"^(?:nmap|masscan|host|dig|smbclient)\b", re.IGNORECASE)
PLACEHOLDER = "<TARGET_IP_RANGE>"

llm: Optional[Llama] = None  # global model handle

# ──────────────────────────────────────────────────────────────
# 1. Logging
# ──────────────────────────────────────────────────────────────
def init_logging(log_dir: Path) -> None:
    """Initialise console + rotating-file loggers."""
    log_dir.mkdir(parents=True, exist_ok=True)
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%H:%M:%S"

    logging.basicConfig(level=logging.INFO, format=fmt, datefmt=datefmt)

    fh = RotatingFileHandler(log_dir / "pentestgpt.log",
                             maxBytes=2_000_000, backupCount=5)
    fh.setFormatter(logging.Formatter(fmt, datefmt))
    fh.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(fh)

# ──────────────────────────────────────────────────────────────
# 2. Graceful shutdown
# ──────────────────────────────────────────────────────────────
_stop = False
def _sigexit(sig_num: int, _frame) -> None:
    global _stop
    logging.warning("Received %s – shutting down …", signal.Signals(sig_num).name)
    _stop = True

signal.signal(signal.SIGINT, _sigexit)
signal.signal(signal.SIGTERM, _sigexit)

# ──────────────────────────────────────────────────────────────
# 3. Model helpers
# ──────────────────────────────────────────────────────────────
def load_model(repo: str, filename: str,
               gpu_layers: int, n_batch: int) -> None:
    """Load the GGUF model into the global `llm`."""
    global llm
    logging.info("Loading model %s/%s …", repo, filename)
    llm = Llama.from_pretrained(repo_id=repo,
                                filename=filename,
                                n_gpu_layers=gpu_layers,
                                n_batch=n_batch,
                                n_ctx = 2048)  # context size
    logging.info("Model loaded successfully.")

@retry(reraise=True,
       stop=stop_after_attempt(3),
       wait=wait_exponential(multiplier=1, min=2, max=10))
def call_model(prompt: str,
               *,
               max_tokens: int = 4096,
               temperature: float = 0.1,
               top_p: float = 0.9,
               repeat_penalty: float = 1.2,
               stop_sequences: Optional[List[str]] = None) -> str:
    """Query the Llama model and return the raw text reply."""
    if llm is None:
        raise RuntimeError("Model not loaded")
    stop_sequences = stop_sequences or ["User:", "Assistant:"]
    resp = llm.create_completion(prompt=prompt,
                                 max_tokens=max_tokens,
                                 temperature=temperature,
                                 top_p=top_p,
                                 repeat_penalty=repeat_penalty,
                                 stop=stop_sequences)
    return resp.choices[0].text.strip()

# ──────────────────────────────────────────────────────────────
# 4. Chat-history helpers
# ──────────────────────────────────────────────────────────────
def build_prompt(history: List[Dict[str, str]]) -> str:
    """Flatten chat history into the prompt expected by the model."""
    lines: List[str] = []
    role_tag = {"system": "System", "user": "User", "assistant": "Assistant"}
    for msg in history:
        lines.append(f"{role_tag[msg['role']]}: {msg['content']}")
    lines.append("User: Based on the above, provide your next step in JSON.")
    return "\n".join(lines)

def persist_msg(session_file: Path, msg: Dict[str, Any]) -> None:
    """Append a single message to the on-disk JSONL session history."""
    session_file.parent.mkdir(parents=True, exist_ok=True)
    with session_file.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(msg, ensure_ascii=False) + "\n")

def parse_json(text: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Attempt to parse the model’s reply as strictly-formatted JSON.
    Returns (command, justification) or (None, None).
    """
    try:
        data = json.loads(text)
        cmd = data.get("command")          # may be null
        reason = data.get("justification", "")
        if cmd and ALLOW_CMD.match(cmd):
            return cmd.strip(), reason.strip()
    except json.JSONDecodeError as exc:
        logging.debug("JSON decode error: %s", exc)
    return None, None

def fallback_extract(text: str) -> Optional[str]:
    """If JSON parse failed, fall back to first line that *looks* like a command."""
    for line in text.splitlines():
        line = line.strip()
        if ALLOW_CMD.match(line):
            return line
    return None

# ──────────────────────────────────────────────────────────────
# 5. Safe command runner
# ──────────────────────────────────────────────────────────────
@retry(reraise=False,
       stop=stop_after_attempt(2),
       wait=wait_exponential(multiplier=1, min=2, max=8))
def run_cmd(cmd: str, timeout: int, dry_run: bool = False) -> str:
    """Run a shell command with timeout; honour dry-run flag."""
    if dry_run:
        return "(dry-run) " + cmd
    res = subprocess.run(cmd,
                         shell=True,
                         capture_output=True,
                         text=True,
                         timeout=timeout)
    return (res.stdout or "") + (res.stderr or "")

# ──────────────────────────────────────────────────────────────
# 6. Main loop
# ──────────────────────────────────────────────────────────────
def pentest_loop(args: argparse.Namespace) -> None:
    session_ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    session_dir = Path(args.output_dir) / session_ts
    init_logging(session_dir)
    session_file = session_dir / "session.jsonl"

    history: List[Dict[str, str]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": f"Initiate internal pentest on `{args.target}`."}
    ]
    for msg in history:
        persist_msg(session_file, msg)

    load_model(args.model_repo, args.model_file,
               gpu_layers=args.gpu_layers,
               n_batch=args.n_batch)

    start_time = time.time()
    consecutive_errors = 0

    for iteration in range(1, args.max_iters + 1):
        if _stop:
            break

        prompt = build_prompt(history)
        try:
            reply = call_model(prompt,
                               max_tokens=args.max_tokens,
                               temperature=args.temperature,
                               top_p=args.top_p)
        except Exception as e:
            logging.error("Model call failed: %s", e)
            consecutive_errors += 1
            if consecutive_errors >= args.error_threshold:
                logging.error("Too many consecutive model errors – aborting.")
                break
            continue

        history.append({"role": "assistant", "content": reply})
        persist_msg(session_file, history[-1])

        cmd, reason = parse_json(reply)
        source = "json"
        if cmd is None:
            cmd = fallback_extract(reply)
            reason = "Fallback: regex-extracted command"
            source = "regex"

        if not cmd:
            logging.info("No valid command suggested – stopping.")
            break

        cmd = cmd.replace(PLACEHOLDER, args.target)
        logging.info("▶ (%s) %s — %s", source, cmd, reason or "no justification")

        try:
            output = run_cmd(cmd, timeout=args.cmd_timeout, dry_run=args.dry_run)
            consecutive_errors = 0
        except Exception as e:
            output = f"Error running `{cmd}`: {e}"
            consecutive_errors += 1
            if consecutive_errors >= args.error_threshold:
                logging.error("Too many consecutive cmd errors – aborting.")
                break

        logging.debug("--- Cmd output start ---\n%s\n--- Cmd output end ---", output)
        history.append({"role": "system",
                        "content": f"Command `{cmd}` finished.\nOutput:\n{output}"})
        persist_msg(session_file, history[-1])

    elapsed = time.time() - start_time
    logging.info("🏁 Finished after %.1fs, %d iterations", elapsed, iteration)

# ──────────────────────────────────────────────────────────────
# 7. CLI interface & entry-point
# ──────────────────────────────────────────────────────────────
def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="PentestGPT unstoppable driver")
    p.add_argument("target",
                   help="CIDR or IP range, e.g. 10.0.0.0/24")
    p.add_argument("--max-iters", type=int, default=9999,
                   help="maximum model iterations (default 9999)")
    p.add_argument("--error-threshold", type=int, default=5,
                   help="abort after N consecutive errors")
    p.add_argument("--cmd-timeout", type=int, default=300,
                   help="seconds allowed per shell command")
    p.add_argument("--dry-run", action="store_true",
                   help="log commands but do NOT execute them")
    p.add_argument("--output-dir", default="pentestgpt_runs",
                   help="where to store logs and session history")

    # model options
    p.add_argument("--model-repo", default=DEFAULT_MODEL_REPO)
    p.add_argument("--model-file", default=DEFAULT_MODEL_FILE)
    p.add_argument("--gpu-layers", type=int, default=10)
    p.add_argument("--n-batch", type=int, default=8)
    p.add_argument("--max-tokens", type=int, default=256)
    p.add_argument("--temperature", type=float, default=0.1)
    p.add_argument("--top-p", type=float, default=0.9)
    return p

def main() -> None:
    args = build_argparser().parse_args()
    try:
        pentest_loop(args)
    except Exception:
        logging.exception("Fatal error")
        sys.exit(2)

if __name__ == "__main__":
    main()
