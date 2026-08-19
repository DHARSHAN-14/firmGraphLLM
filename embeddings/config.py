"""
FirmGraph-LLM — Embedding Model Configuration
==============================================
Central config for the function embedding pipeline.

Model Decision (rationale in docs/embedding_model_decision.md):
    Selected: microsoft/unixcoder-base
    Reason:   Best fit for decompiled C pseudocode on CPU-only hardware
              (7.6GB RAM, Intel i5-10210U, no discrete GPU).
"""

from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class EmbeddingConfig:
    # ── Model ──────────────────────────────────────────────────────────────
    model_name: str = "microsoft/unixcoder-base"
    """
    UniXcoder: unified cross-modal pre-training for code.
    - Trained on code understanding, generation, and search tasks
    - Handles decompiled C pseudocode well (token overlap with real C)
    - 125M parameters — fits comfortably in ~500MB RAM at fp32
    - Encodes up to 512 tokens; Ghidra decompiled functions typically < 300 tokens
    - Better than CodeBERT for cross-language code similarity (needed for
      cross-firmware function matching)
    """

    # ── Embedding dimensions ────────────────────────────────────────────────
    embedding_dim: int = 768
    """UniXcoder hidden size — standard BERT-base dimension."""

    # ── Tokenization ────────────────────────────────────────────────────────
    max_length: int = 512
    """Max token length. Decompiled functions are typically 50–300 tokens."""

    truncation: bool = True
    padding: str = "max_length"

    # ── Pooling strategy ───────────────────────────────────────────────────
    pooling: str = "mean"
    """
    Mean pooling over all token embeddings (excluding padding).
    Better than [CLS]-only for code similarity tasks.
    """

    # ── Inference hardware ─────────────────────────────────────────────────
    device: str = "cpu"
    """
    CPU-only inference. Hardware: Intel i5-10210U, 7.6GB RAM, Intel iGPU.
    No discrete NVIDIA GPU available.
    Expected throughput: ~50-100 functions/sec on this hardware.
    """

    batch_size: int = 16
    """
    Batch size for embedding generation.
    16 is safe for CPU inference with 7.6GB RAM.
    Reduce to 8 if OOM errors occur.
    """

    # ── Vector index ────────────────────────────────────────────────────────
    index_type: str = "flat"
    """
    FAISS IndexFlatIP (inner product / cosine similarity after normalization).
    For small-medium corpus (<100k functions), flat index is fast enough on CPU.
    Upgrade to IVF or HNSW when corpus exceeds 100k functions.
    """

    normalize_embeddings: bool = True
    """Normalize to unit length so inner product = cosine similarity."""

    # ── Paths ───────────────────────────────────────────────────────────────
    index_path: Path = ROOT / "embeddings" / "juliet_functions.faiss"
    metadata_path: Path = ROOT / "embeddings" / "juliet_functions_meta.json"
    model_cache_dir: Path = ROOT / "embeddings" / ".model_cache"


# ── LLM Configuration (Open-Source) ────────────────────────────────────────────
@dataclass
class LLMConfig:
    """
    Open-source LLM configuration for FirmGraph-LLM.

    Model Decision:
        Primary:  Ollama with qwen3-coder (Qwen3 Coder Next)
        Fallback: Ollama with qwen2.5-coder:7b-instruct
        Rationale:
          - No GPU → must use quantized (GGUF) models via Ollama
          - Qwen3 Coder: state-of-the-art code reasoning, stronger than CodeLlama-13B
            on vulnerability analysis tasks, native 128K context window
          - qwen2.5-coder:7b is the fallback if RAM is too tight (~4.5GB Q4_K_M)
          - Both run fully locally — no API cost, no data leakage
          - Install: curl -fsSL https://ollama.com/install.sh | sh
          - Pull:    ollama pull qwen3-coder
    """

    provider: str = "ollama"
    model: str = "qwen3-coder"
    fallback_model: str = "qwen2.5-coder:7b-instruct"
    base_url: str = "http://localhost:11434"

    # Generation parameters
    temperature: float = 0.4
    """
    0.4 matches LATTE's recommended range (0.4-0.6) for stability/quality balance.
    Lower = more deterministic but less creative; higher = more varied.
    """
    max_tokens: int = 2048
    top_p: float = 0.9
    repeat_penalty: float = 1.1

    # Timeout for long code analysis
    timeout_seconds: int = 120


# Singletons for import
EMBEDDING_CONFIG = EmbeddingConfig()
LLM_CONFIG = LLMConfig()
