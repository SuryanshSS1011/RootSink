#!/usr/bin/env python3
"""Exploratory AI raters for the PR-9 audit (PREREGISTRATION, PR-9 entry of 2026-11-05).

Each model gets what a human rater got: the packet's codebook, the six practice items with
their answer key, and then one of the 150 items per request. It gets no labels, tools or web
access. Its answer is one sheet row, validated against the codebook's vocabulary. An invalid
answer is retried once with the validation error; if it is still invalid, every cell is recorded
as `unclear`, which scores as disagreement, exactly as for a human. Every request is logged with
the model the provider reports, the time, a hash of the prompt and the raw response.

AI sheets are written under data/irr/ai/, never data/irr/returned/, so they are never scored as
human raters. score_ai_raters.py scores them.

Usage (keys from the environment, never from the command line):
  ANTHROPIC_API_KEY=... uv run python infra/verify/ai_raters.py --provider anthropic \
      --model claude-opus-5-5
  OPENAI_API_KEY=... uv run python infra/verify/ai_raters.py --provider openai --model gpt-6.1-terra
  GEMINI_API_KEY=... uv run python infra/verify/ai_raters.py --provider gemini \
      --model gemini-3.8-flash --sleep 7
  VLLM_API_KEY=... uv run python infra/verify/ai_raters.py --provider openai \
      --model Qwen/Qwen3.8-27B --base-url https://<workspace>--rootsink-vllm-serve.modal.run/v1 \
      --api-key-env VLLM_API_KEY
  ... --items 1-5         a smoke test on five items
  ... --dry-run           build every prompt and report sizes, without calling any API

Reruns resume: items with a final answer in raw.jsonl are skipped.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import irr  # noqa: E402

FIELDS = ["source_cwe", "sink_cwe", "source_site", "sink_site", "causal", "site_roles", "note"]
SOURCE_VOCAB = {"20", "129", "190", "252", "362", "416", "456", "476", "843"}
SINK_VOCAB = {"119", "125", "787", "190", "415", "416", "457", "476"}
ROLES = {"defect", "repair", "crash", "unrelated", "unclear"}

# Human-only logistics in the codebook (time estimate, sheet file, the request not to use an AI
# tool) are dropped from the model's copy; nothing about the task or its conventions is changed.
LOGISTICS = re.compile(r"Read it, then fill one row of the sheet.*?several sittings\.", re.S)

INSTRUCTIONS = """You are rating one item of a blind label audit. Follow the codebook above exactly.
Answer with a single JSON object and nothing else, with these keys:
  "source_cwe", "sink_cwe", "source_site", "sink_site", "causal", "site_roles", "note".
Use the codebook's answer formats: a CWE id from the vocabulary, "other:<id>" or "unclear" for the
CWEs; a site number, "other:<file>:<function>", "none" or "unclear" for source_site; a site number
or "none" for sink_site; "y", "n" or "unclear" for causal; and site_roles as "1:<role>;2:<role>"
giving every listed site exactly one role. Keep the note to one or two sentences."""


def split_items(text: str) -> tuple[str, dict[int, str]]:
    parts = re.split(r"^## Item (\d+)\n", text, flags=re.M)
    head, items = parts[0], {}
    for i in range(1, len(parts), 2):
        items[int(parts[i])] = parts[i + 1].rstrip().rstrip("-").rstrip()
    return head, items


def system_prompt() -> str:
    head, _ = split_items((ROOT / "data/irr/packet.md").read_text())
    codebook = (
        LOGISTICS.sub(
            "Read it, then give the answers below. You do not see the dataset's labels.", head
        )
        .rstrip()
        .rstrip("-")
    )
    _, practice = split_items((ROOT / "data/irr/practice/packet.md").read_text())
    with open(ROOT / "data/irr/practice/answer_key.csv") as fh:
        key = {r["id"]: r for r in csv.DictReader(fh)}
    shown = []
    for n, body in sorted(practice.items()):
        k = key.get(f"item-{n}", {})
        answer = ", ".join(
            f"{f}={k[f]}" for f in ("source_cwe", "sink_cwe", "source_site", "sink_site", "causal")
        )
        shown.append(f"## Practice item {n}\n\n{body}\n\nAnswer key: {answer}")
    return (
        codebook.strip()
        + "\n\n# Practice items with their answer key\n\n"
        + "The key gives five of the answers; site roles are not keyed.\n\n"
        + "\n\n".join(shown)
        + "\n\n# Task\n\n"
        + INSTRUCTIONS
    )


def user_prompt(n: int, body: str, n_sites: int) -> str:
    return f"## Item {n}\n\n{body}\n\nThis item lists {n_sites} site(s). Answer as JSON only."


def _cwe(v: str, vocab: set[str]) -> str | None:
    v = re.sub(r"(?i)^cwe-", "", v.strip().lower())
    if v == "unclear":
        return v
    if v.startswith("other:"):
        rest = re.sub(r"(?i)^cwe-", "", v[6:].strip())
        return f"other:{rest}" if rest.isdigit() else None
    if v.isdigit():
        return v if v in vocab else f"other:{v}"
    return None


def validate(ans: dict, n_sites: int) -> tuple[dict | None, str]:
    """Normalize a model's answer to sheet cells, or explain why it is invalid."""
    if not isinstance(ans, dict):
        return None, "not a JSON object"
    get = lambda k: str(ans.get(k, "")).strip()  # noqa: E731
    row = {}
    for k, vocab in (("source_cwe", SOURCE_VOCAB), ("sink_cwe", SINK_VOCAB)):
        v = _cwe(get(k), vocab)
        if v is None:
            return None, f"{k} must be a CWE id, other:<id> or unclear"
        row[k] = v
    s = get("source_site")
    sl = s.lower()
    if sl in ("none", "unclear") or (s.isdigit() and 1 <= int(s) <= n_sites):
        row["source_site"] = sl
    elif sl.startswith("other:") and s.count(":") >= 2:
        row["source_site"] = "other:" + s.split(":", 1)[1].strip()
    else:
        return None, f"source_site must be 1..{n_sites}, other:<file>:<function>, none or unclear"
    s = get("sink_site").lower()
    if not (s in ("none", "unclear") or (s.isdigit() and 1 <= int(s) <= n_sites)):
        return None, f"sink_site must be 1..{n_sites} or none"
    row["sink_site"] = s
    c = get("causal").lower()
    if c not in ("y", "n", "unclear"):
        return None, "causal must be y, n or unclear"
    row["causal"] = c
    roles = {}
    for part in get("site_roles").replace(",", ";").split(";"):
        num, _, role = part.partition(":")
        if part.strip():
            if not num.strip().isdigit() or role.strip().lower() not in ROLES:
                return None, f"site_roles entry {part.strip()!r} is not <n>:<role>"
            roles[int(num)] = role.strip().lower()
    if set(roles) != set(range(1, n_sites + 1)):
        return None, f"site_roles must give exactly one role to each of sites 1..{n_sites}"
    row["site_roles"] = ";".join(f"{k}:{roles[k]}" for k in sorted(roles))
    row["note"] = " ".join(get("note").split())
    return row, ""


def parse_json(text: str) -> dict | None:
    # Only the final answer is scored: drop a reasoning block an open-weights model may emit.
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    for cand in ([fenced.group(1)] if fenced else []) + [
        text,
        text[text.find("{") : text.rfind("}") + 1],
    ]:
        try:
            out = json.loads(cand)
            return out if isinstance(out, dict) else None
        except (json.JSONDecodeError, ValueError):
            continue
    return None


class Client:
    def __init__(self, a: argparse.Namespace):
        self.a = a
        env = (
            a.api_key_env
            or {
                "anthropic": "ANTHROPIC_API_KEY",
                "openai": "OPENAI_API_KEY",
                "gemini": "GEMINI_API_KEY",
            }[a.provider]
        )
        self.key = os.environ.get(env, "")
        if not self.key and not a.dry_run:
            sys.exit(f"set {env}")
        self.http = httpx.Client(timeout=900)

    def _post(self, url: str, headers: dict, body: dict) -> dict:
        for attempt in range(8):
            r = self.http.post(url, headers=headers, json=body)
            if r.status_code in (429, 500, 502, 503, 504, 529) and attempt < 7:
                time.sleep(min(300, 10 * 2**attempt))
                continue
            if r.status_code >= 400:  # keep the provider's message, e.g. an unsupported setting
                raise httpx.HTTPStatusError(
                    f"{r.status_code}: {r.text[:500]}", request=r.request, response=r
                )
            return r.json()
        raise AssertionError("unreachable")

    def ask(self, system: str, messages: list[dict]) -> tuple[str, str, dict]:
        """Returns (text, model the provider reports, usage)."""
        a, t = self.a, self.a.temperature
        if a.provider == "anthropic":
            body = {
                "model": a.model,
                "max_tokens": a.max_tokens,
                "system": [
                    {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}
                ],
                "messages": messages,
            }
            if t is not None:
                body["temperature"] = t
            hdr = {"x-api-key": self.key, "anthropic-version": "2023-06-01"}
            j = self._post("https://api.anthropic.com/v1/messages", hdr, body)
            text = "".join(
                c.get("text", "") for c in j.get("content", []) if c.get("type") == "text"
            )
            return text, j.get("model", ""), j.get("usage", {})
        if a.provider == "openai":
            base = (a.base_url or "https://api.openai.com/v1").rstrip("/")
            body = {
                "model": a.model,
                "messages": [{"role": "system", "content": system}, *messages],
            }
            if t is not None:
                body["temperature"] = t
            j = self._post(
                f"{base}/chat/completions", {"Authorization": f"Bearer {self.key}"}, body
            )
            return (
                j["choices"][0]["message"].get("content") or "",
                j.get("model", ""),
                j.get("usage", {}),
            )
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [
                {
                    "role": "model" if m["role"] == "assistant" else "user",
                    "parts": [{"text": m["content"]}],
                }
                for m in messages
            ],
            "generationConfig": {"responseMimeType": "application/json"}
            | ({"temperature": t} if t is not None else {}),
        }
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{a.model}:generateContent"
        j = self._post(url, {"x-goog-api-key": self.key}, body)
        parts = (j.get("candidates") or [{}])[0].get("content", {}).get("parts", [])
        return (
            "".join(p.get("text", "") for p in parts),
            j.get("modelVersion", ""),
            j.get("usageMetadata", {}),
        )


def item_range(spec: str | None, total: int) -> list[int]:
    if not spec:
        return list(range(1, total + 1))
    out = []
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        out += list(range(int(lo), int(hi or lo) + 1))
    return out


def write_sheet(raw: Path, sheet: Path, total: int) -> int:
    final = {}
    for line in raw.read_text().splitlines():
        rec = json.loads(line)
        if rec.get("final"):
            final[rec["item"]] = rec["row"]
    with open(sheet, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["id", *FIELDS])
        w.writeheader()
        for n in range(1, total + 1):
            if n in final:
                w.writerow({"id": f"item-{n}", **final[n]})
    return len(final)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--provider", required=True, choices=["anthropic", "openai", "gemini"])
    ap.add_argument("--model", required=True)
    ap.add_argument("--base-url", help="OpenAI-compatible endpoint, e.g. a vLLM server on Modal")
    ap.add_argument("--api-key-env", help="environment variable holding the key")
    ap.add_argument("--temperature", default="0", help="a number, or 'none' to omit it")
    ap.add_argument("--max-tokens", type=int, default=4096, help="Anthropic only")
    ap.add_argument("--items", help="e.g. 1-5 or 3,7,9-12; default all 150")
    ap.add_argument("--sleep", type=float, default=0.0, help="seconds between requests")
    ap.add_argument("--out", default="data/irr/ai")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    a.temperature = None if a.temperature.lower() == "none" else float(a.temperature)

    picked = json.loads((ROOT / "data/irr/sample.json").read_text())
    _, items = split_items((ROOT / "data/irr/packet.md").read_text())
    if len(items) != len(picked):
        sys.exit(f"packet has {len(items)} items but the sample has {len(picked)}")
    system = system_prompt()
    todo = item_range(a.items, len(items))

    if a.dry_run:
        sizes = [len(user_prompt(n, items[n], len(irr.item_sites(picked[n - 1])))) for n in todo]
        med = sorted(sizes)[len(sizes) // 2]
        print(
            f"system prompt {len(system):,} chars; {len(todo)} items, user prompts "
            f"median {med:,} max {max(sizes):,} total {sum(sizes):,} chars"
        )
        return 0

    out = ROOT / a.out / re.sub(r"[^A-Za-z0-9._-]+", "_", a.model)
    out.mkdir(parents=True, exist_ok=True)
    raw, sheet = out / "raw.jsonl", out / "sheet.csv"
    done = set()
    if raw.exists():
        done = {
            json.loads(x)["item"]
            for x in raw.read_text().splitlines()
            if json.loads(x).get("final")
        }
    client = Client(a)
    sys_hash = hashlib.sha256(system.encode()).hexdigest()
    for n in todo:
        if n in done:
            continue
        n_sites = len(irr.item_sites(picked[n - 1]))
        messages = [{"role": "user", "content": user_prompt(n, items[n], n_sites)}]
        row, why = None, ""
        for attempt in (1, 2):
            started = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
            try:
                text, reported, usage = client.ask(system, messages)
                err = ""
            except httpx.HTTPError as e:  # an infrastructure failure is never an answer
                text, reported, usage, err = "", "", {}, f"{type(e).__name__}: {e}"
            if err:
                with open(raw, "a") as fh:
                    fh.write(
                        json.dumps({"item": n, "attempt": attempt, "error": err, "time": started})
                        + "\n"
                    )
                print(f"item {n}: {err}; stopping so a rerun can resume", file=sys.stderr)
                write_sheet(raw, sheet, len(items))
                return 1
            ans = parse_json(text)
            row, why = validate(ans, n_sites) if ans is not None else (None, "no JSON object found")
            final = row is not None or attempt == 2
            if row is None and attempt == 2:
                row = {f: "unclear" for f in FIELDS[:-1]} | {"note": f"invalid answer: {why}"}
                row["site_roles"] = ";".join(f"{k}:unclear" for k in range(1, n_sites + 1))
            rec = {
                "item": n,
                "attempt": attempt,
                "final": final,
                "valid": why == "" and row is not None,
                "provider": a.provider,
                "model_requested": a.model,
                "model_reported": reported,
                "temperature": a.temperature,
                "time": started,
                "system_sha256": sys_hash,
                "user_sha256": hashlib.sha256(messages[-1]["content"].encode()).hexdigest(),
                "usage": usage,
                "response": text,
                "row": row if final else None,
                "error": why,
            }
            with open(raw, "a") as fh:
                fh.write(json.dumps(rec) + "\n")
            if final:
                break
            messages += [
                {"role": "assistant", "content": text or "(empty)"},
                {
                    "role": "user",
                    "content": f"That answer is invalid: {why}. Reply with JSON only.",
                },
            ]
        print(f"item {n}: {'ok' if why == '' else 'unclear (' + why + ')'}")
        if a.sleep:
            time.sleep(a.sleep)
    got = write_sheet(raw, sheet, len(items))
    print(f"{got} of {len(items)} items answered -> {sheet}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
