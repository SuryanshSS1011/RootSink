# Qwen/Qwen3.8-27B: AI rater run (PR-9 exploratory AI raters)

Date: 2026-11-05 (all times UTC). First answer 17:10:41, last answer 23:03:32.
Result: **150 of 150 items answered**, 150 valid on the first attempt (no validation retries,
no `unclear` fallbacks). Every response reports model `Qwen/Qwen3.8-27B`, temperature 0.0 and
system-prompt SHA-256 `a423c2794d1f…`, the same codebook hash as the Opus and Gemini runs.

## Model

- Hugging Face `Qwen/Qwen3.8-27B`, revision `8c0b3d30f3ae96f5c7f774de704bf0ada83e422a` (the only
  snapshot in the `rootsink-hf-cache` volume; `main` pointed to it throughout, last modified
  2026-11-05T15:15:29Z, before the first deploy). Licence Apache-2.0, not gated. BF16.
- Model card: thinking mode is on by default; the vLLM recipe gives vLLM >= 0.17.0 and
  `--reasoning-parser qwen3`. The recipe's `--enable-auto-tool-choice --tool-call-parser
  qwen3_coder` were not used, because the rater gives the model no tools.
- The card recommends temperature 1.0 for thinking mode; PR-9 fixes temperature 0, which was used.
  The client sends no `max_tokens`, `reasoning_effort` or `chat_template_kwargs`, so the server
  and chat-template defaults apply (thinking on).

## Serving

- vLLM 0.33.0 (unpinned `pip install vllm` in the Modal image; the same build at every start).
  Modal client 1.6.2.
- GPU: one Modal `H100`, tensor parallelism 1, one container.
- Final serve command (the key redacted):

  ```
  vllm serve Qwen/Qwen3.8-27B --host 0.0.0.0 --port 8000 --max-model-len 262144 \
    --tensor-parallel-size 1 --api-key *** --gdn-prefill-backend triton --max-num-seqs 16 \
    --reasoning-parser qwen3
  ```

  Environment: `VLLM_USE_FLASHINFER_SAMPLER=0`. KV cache 315,956 tokens at 262144.
- Started with `MODEL=Qwen/Qwen3.8-27B REASONING_PARSER=qwen3 MAX_LEN=262144 modal run --detach
  infra/verify/modal_vllm.py::serve`, reached through a Modal tunnel URL.
- Client: `ai_raters.py --provider openai --model Qwen/Qwen3.8-27B --api-key-env VLLM_API_KEY
  --base-url <tunnel>/v1`, unmodified, run from a clean checkout and
  reading the committed `data/irr/packet.md`.

## Changes to `infra/verify/modal_vllm.py` (serving only)

1. `max_containers=1`. Readiness polls queued during the first cold start made Modal start three
   H100 containers. The rater sends one request at a time.
2. `--gdn-prefill-backend triton`. The first start failed: vLLM's default FlashInfer GDN prefill
   kernel is JIT-compiled and the image has no `nvcc` (`RuntimeError: Could not find nvcc`).
   This is the fix vLLM's own warning names. It is not a model-card flag; the authors approved it
   before it was used.
3. `VLLM_USE_FLASHINFER_SAMPLER=0`. The second start failed the same way in FlashInfer's
   top-k/top-p sampler during memory profiling. vLLM falls back to its PyTorch sampler; greedy
   decoding at temperature 0 uses neither.
4. `--max-num-seqs 16`. The third start failed: `max_num_seqs (1024) exceeds available Mamba
   cache blocks (361)`. A cap on concurrent sequences; it does not change any single request.
5. Modal tunnel (`modal.forward`) instead of `@modal.web_server`. A Modal web endpoint answers
   any request longer than 150 s with a 303 redirect, which `ai_raters.py` does not follow; a
   long reasoning answer takes longer than that. Verified with a dummy request (not an audit
   item): 303 after 151 s through the web endpoint, 200 after 187 s through the tunnel.
6. `MAX_LEN` 262144 instead of 131072, set in the environment for the run and now the script's
   default, so a rerun reproduces it. Item 31's prompt
   is 140,522 tokens under the Qwen tokenizer, which is over 131072. The "about 62K tokens"
   estimate for the largest prompt assumed 4 characters per token: system prompt 41,371 chars
   plus largest item 202,701 chars. The other 149 prompts are at most 21,219 tokens (counted with
   vLLM's `/tokenize`, no generation). 262144 is the model's native context; no RoPE scaling
   was used. The authors approved the change before item 31 was answered.

Items 1–7 were answered through the web endpoint, items 8–30 through the tunnel at
`--max-model-len 131072`, and items 31–150 through the tunnel at 262144. Every other flag was
the same for all 150 items. The context limit does not change the computation for prompts that
fit, and no RoPE scaling was used.

## Errors and reruns

`raw.jsonl` holds 153 records: 150 final answers and three infrastructure errors, none of which
is an answer (PR-9 item 5).

| Time | Item | Error | Cause and cure |
|---|---|---|---|
| 17:16:00 | 8 | `RemoteProtocolError: Server disconnected` | A consumer VPN on the author's laptop cut HTTP connections idle for about 75–90 s; the same request succeeded from inside Modal. VPN disconnected. |
| 17:18:04 | 8 | same | Same rerun, before the cause was found. |
| 19:32:05 | 31 | `400: maximum context length is 131072 tokens` | Prompt 140,522 tokens; MAX_LEN raised to 262144 (change 6). |

The rater was started 5 times: smoke test `--items 1-3` at 17:10, then full runs at 17:13
(stopped at item 8), 17:18 (item 8), 19:07 (item 31) and 21:04 (completed at 23:05:26 with
"150 of 150 items answered"). Each run resumed at the first item without a final answer. The
automatic rerun loop may also have started one more attempt at item 8 at about 17:19:48. It was
stopped mid-request while the disconnects were investigated and wrote no record. Item 8
was answered at 19:07 with 5,722 completion tokens, and item 31 at 21:04 with 3,604.

Token use per item: prompt median 18,088 (max 140,522), completion median 2,517 (max 11,604),
almost all of it reasoning, which vLLM's `qwen3` parser keeps out of the scored answer.

The server was stopped after the run (`modal app stop`; no containers left).
