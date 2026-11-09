"""Serve an open-weights model with vLLM on Modal as an OpenAI-compatible endpoint for
ai_raters.py (PREREGISTRATION, PR-9 entry of 2026-11-05). A starting point: if Modal's API has
moved, follow Modal's own vLLM example and keep the same model, flags and key.

  modal secret create rootsink-vllm VLLM_API_KEY=<a long random string>
  MODEL=Qwen/Qwen3.8-27B modal run --detach infra/verify/modal_vllm.py::serve
  VLLM_API_KEY=<same string> uv run python infra/verify/ai_raters.py --provider openai \
      --model Qwen/Qwen3.8-27B --api-key-env VLLM_API_KEY \
      --base-url <the "base URL" the container log prints>

The server is reached through a Modal tunnel rather than a web endpoint: a web endpoint answers
any request longer than 150 s with a redirect, which ai_raters.py does not follow, and a long
reasoning answer takes longer than that.

Record the vLLM version the container installed (it is printed in the container log) with the
run, and `modal app stop rootsink-vllm` when the 150 items are done.
"""

import os
import subprocess

import modal

MODEL = os.environ.get("MODEL", "Qwen/Qwen3.8-27B")
GPU = os.environ.get("GPU", "H100")  # e.g. "H100:2" with TP=2 if one GPU runs out of memory
MAX_LEN = os.environ.get("MAX_LEN", "262144")  # item 31 plus prompt is 140,522 Qwen tokens
TP = os.environ.get("TP", "1")
REASONING_PARSER = os.environ.get("REASONING_PARSER", "")  # as the model card recommends

image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("vllm", "huggingface_hub[hf_transfer]")
    .env(
        {
            "HF_HUB_ENABLE_HF_TRANSFER": "1",
            "MODEL": MODEL,
            "MAX_LEN": MAX_LEN,
            "TP": TP,
            "REASONING_PARSER": REASONING_PARSER,
            "VLLM_USE_FLASHINFER_SAMPLER": "0",  # it needs nvcc to JIT, which the image lacks
        }
    )
)
cache = modal.Volume.from_name("rootsink-hf-cache", create_if_missing=True)
app = modal.App("rootsink-vllm")


@app.function(
    image=image,
    gpu=GPU,
    volumes={"/root/.cache/huggingface": cache},
    secrets=[modal.Secret.from_name("rootsink-vllm")],
    timeout=4 * 60 * 60,
    max_containers=1,
)
def serve():
    subprocess.run(["vllm", "--version"], check=False)
    cmd = [
        "vllm",
        "serve",
        os.environ["MODEL"],
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
        "--max-model-len",
        os.environ["MAX_LEN"],
        "--tensor-parallel-size",
        os.environ["TP"],
        "--api-key",
        os.environ["VLLM_API_KEY"],
        "--gdn-prefill-backend",  # the FlashInfer default needs nvcc to JIT, which the image lacks
        "triton",
        "--max-num-seqs",  # the default 1024 exceeds the Mamba cache blocks; the rater sends one
        "16",
    ]
    if os.environ.get("REASONING_PARSER"):
        cmd += ["--reasoning-parser", os.environ["REASONING_PARSER"]]
    print(" ".join(c for c in cmd if c != os.environ["VLLM_API_KEY"]), flush=True)
    with modal.forward(8000) as tunnel:
        print(f"base URL: {tunnel.url}/v1", flush=True)
        subprocess.run(cmd, check=True)
