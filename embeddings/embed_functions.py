#!/usr/bin/env python3
"""
FirmGraph-LLM — Function Embedding Pipeline
============================================
Generates code embeddings for decompiled function pseudocode
using UniXcoder (microsoft/unixcoder-base).

Workflow:
    1. Load decompiled function pseudocode (from Ghidra output JSON)
    2. Tokenize using UniXcoder tokenizer
    3. Run forward pass (CPU inference), mean-pool hidden states
    4. Normalize to unit vectors
    5. Store in FAISS flat index + metadata JSON

Usage:
    # Embed functions from a single Ghidra output file
    python3 embeddings/embed_functions.py --input data/juliet/functions/CWE-78/
    
    # Embed all processed functions
    python3 embeddings/embed_functions.py --input data/processed/functions/
    
    # Query: find top-5 similar functions to a query function
    python3 embeddings/embed_functions.py --query "void bad() { char data[100]; recv(...)... }" --top-k 5
"""

import json
import logging
import argparse
import time
from pathlib import Path
from typing import Optional

import numpy as np

log = logging.getLogger("embedder")


def _load_model_and_tokenizer(config):
    """Lazy import and load UniXcoder model."""
    try:
        from transformers import AutoTokenizer, AutoModel
        import torch
    except ImportError:
        raise ImportError(
            "transformers and torch are required. Install with:\n"
            "  pip install transformers torch sentence-transformers"
        )

    log.info(f"Loading model: {config.model_name}")
    log.info(f"  Cache dir: {config.model_cache_dir}")
    config.model_cache_dir.mkdir(parents=True, exist_ok=True)

    tokenizer = AutoTokenizer.from_pretrained(
        config.model_name,
        cache_dir=str(config.model_cache_dir),
    )
    model = AutoModel.from_pretrained(
        config.model_name,
        cache_dir=str(config.model_cache_dir),
    )
    model.eval()
    model.to(config.device)
    log.info(f"  Model loaded on {config.device}")
    return tokenizer, model


def mean_pool(token_embeddings, attention_mask):
    """Mean pool over non-padding token embeddings."""
    import torch
    mask_expanded = attention_mask.unsqueeze(-1).float()
    sum_embeddings = (token_embeddings * mask_expanded).sum(dim=1)
    sum_mask = mask_expanded.sum(dim=1).clamp(min=1e-9)
    return sum_embeddings / sum_mask


def embed_batch(texts: list[str], tokenizer, model, config) -> np.ndarray:
    """
    Embed a batch of code strings → numpy array [batch_size, 768].
    Uses mean pooling + L2 normalization.
    """
    import torch

    encoded = tokenizer(
        texts,
        max_length=config.max_length,
        truncation=config.truncation,
        padding=config.padding,
        return_tensors="pt",
    )
    encoded = {k: v.to(config.device) for k, v in encoded.items()}

    with torch.no_grad():
        outputs = model(**encoded)

    # Mean pool over sequence dimension
    embeddings = mean_pool(outputs.last_hidden_state, encoded["attention_mask"])
    embeddings = embeddings.cpu().numpy().astype(np.float32)

    # L2 normalize
    if config.normalize_embeddings:
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        norms = np.maximum(norms, 1e-9)
        embeddings /= norms

    return embeddings


def load_function_texts(input_path: Path) -> list[dict]:
    """
    Load decompiled function pseudocode from Ghidra output files.
    Expected format (JSON per function or per file):
        {
            "function_id": "CWE78/bad/...__sub_400A10",
            "name": "bad",
            "binary": "...",
            "cwe": 78,
            "pseudocode": "void bad() { ... }"
        }
    """
    functions = []

    if input_path.is_file():
        data = json.loads(input_path.read_text())
        if isinstance(data, list):
            functions.extend(data)
        else:
            functions.append(data)
    elif input_path.is_dir():
        for json_file in sorted(input_path.rglob("*.json")):
            try:
                data = json.loads(json_file.read_text())
                if isinstance(data, list):
                    functions.extend(data)
                elif isinstance(data, dict):
                    functions.append(data)
            except Exception as e:
                log.warning(f"Skipping {json_file.name}: {e}")

    log.info(f"Loaded {len(functions)} functions from {input_path}")
    return functions


def build_index(embeddings: np.ndarray, config):
    """Build a FAISS flat inner-product index from embeddings."""
    try:
        import faiss
    except ImportError:
        raise ImportError("faiss-cpu is required: pip install faiss-cpu")

    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim)  # inner product = cosine (after L2 norm)
    index.add(embeddings)
    log.info(f"  FAISS index built: {index.ntotal} vectors, dim={dim}")
    return index


def save_index(index, metadata: list[dict], config):
    """Save FAISS index and metadata JSON to disk."""
    import faiss

    config.index_path.parent.mkdir(parents=True, exist_ok=True)
    faiss.write_index(index, str(config.index_path))
    config.metadata_path.write_text(json.dumps(metadata, indent=2))
    log.info(f"  Index saved  → {config.index_path}")
    log.info(f"  Metadata saved → {config.metadata_path}")


def load_index(config):
    """Load existing FAISS index and metadata from disk."""
    import faiss

    if not config.index_path.exists():
        raise FileNotFoundError(f"No index found at {config.index_path}. Run embedding first.")

    index = faiss.read_index(str(config.index_path))
    metadata = json.loads(config.metadata_path.read_text())
    log.info(f"Loaded index: {index.ntotal} vectors")
    return index, metadata


def query_similar(
    query_text: str,
    tokenizer,
    model,
    index,
    metadata: list[dict],
    config,
    top_k: int = 5,
) -> list[dict]:
    """
    Find the top-K most similar functions to a query code string.
    Returns list of {score, metadata} dicts.
    """
    q_emb = embed_batch([query_text], tokenizer, model, config)
    scores, indices = index.search(q_emb, top_k)

    results = []
    for score, idx in zip(scores[0], indices[0]):
        if idx < 0:
            continue
        entry = metadata[idx].copy()
        entry["similarity_score"] = float(score)
        results.append(entry)
    return results


def run_embedding_pipeline(args, config):
    """Full embedding pipeline: load → embed → index → save."""
    tokenizer, model = _load_model_and_tokenizer(config)

    input_path = Path(args.input)
    functions = load_function_texts(input_path)

    if not functions:
        log.error("No functions found. Check input path.")
        return

    # Extract pseudocode texts
    texts    = [f.get("pseudocode", f.get("code", "")) for f in functions]
    metadata = functions

    log.info(f"\nEmbedding {len(texts)} functions (batch_size={config.batch_size})...")
    start = time.time()

    all_embeddings = []
    for i in range(0, len(texts), config.batch_size):
        batch = texts[i : i + config.batch_size]
        embs = embed_batch(batch, tokenizer, model, config)
        all_embeddings.append(embs)
        if (i // config.batch_size + 1) % 10 == 0:
            elapsed = time.time() - start
            done = i + len(batch)
            log.info(f"  {done}/{len(texts)} functions embedded ({elapsed:.1f}s)")

    embeddings = np.vstack(all_embeddings)
    elapsed = time.time() - start
    throughput = len(texts) / elapsed
    log.info(f"  Done: {len(texts)} functions in {elapsed:.1f}s ({throughput:.1f} fn/s)")

    # Build and save index
    log.info("\nBuilding FAISS index...")
    index = build_index(embeddings, config)
    save_index(index, metadata, config)


def run_query(args, config):
    """Query existing index for similar functions."""
    tokenizer, model = _load_model_and_tokenizer(config)
    index, metadata = load_index(config)

    query_text = args.query
    log.info(f"\nQuerying for top-{args.top_k} similar functions...")
    log.info(f"  Query: {query_text[:100]}...")

    results = query_similar(query_text, tokenizer, model, index, metadata, config, args.top_k)

    print(f"\n{'='*60}")
    print(f"Top-{args.top_k} Similar Functions")
    print(f"{'='*60}")
    for i, r in enumerate(results, 1):
        print(f"\n[{i}] Score: {r['similarity_score']:.4f}")
        print(f"    Function: {r.get('name', 'unknown')}")
        print(f"    Binary:   {r.get('binary', 'unknown')}")
        print(f"    CWE:      {r.get('cwe', 'unknown')}")
        print(f"    Code:     {str(r.get('pseudocode', ''))[:150]}...")


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    from embeddings.config import EMBEDDING_CONFIG

    parser = argparse.ArgumentParser(description="FirmGraph-LLM function embedding pipeline")
    sub = parser.add_subparsers(dest="cmd")

    # Embed subcommand
    ep = sub.add_parser("embed", help="Embed functions from input directory")
    ep.add_argument("--input", required=True, help="Path to function JSON files")

    # Query subcommand
    qp = sub.add_parser("query", help="Query similar functions")
    qp.add_argument("--query", required=True, help="Code string to query")
    qp.add_argument("--top-k", type=int, default=5)

    args = parser.parse_args()

    if args.cmd == "embed":
        run_embedding_pipeline(args, EMBEDDING_CONFIG)
    elif args.cmd == "query":
        run_query(args, EMBEDDING_CONFIG)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
