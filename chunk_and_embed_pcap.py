"""
Chunk and embed the PCAP knowledge base into a FAISS index for Syd V3.
Follows the same pattern as chunk_and_embed_nxc.py
"""

import os, sys, json, pickle, re
from pathlib import Path

BASE_PATH = Path(__file__).parent
KB_DIR    = BASE_PATH / "knowledge_bases" / "pcap"
EMB_DIR   = BASE_PATH / "rag_engine" / "embeddings" / "customers"
INDEX_NAME = "customer_syd_pcap_knowledge"

CHUNK_SIZE    = 400   # words per chunk
CHUNK_OVERLAP = 80

def load_md_files():
    docs = []
    for f in sorted(KB_DIR.glob("*.md")):
        text = f.read_text(encoding="utf-8")
        docs.append({"source": f.name, "text": text})
        print(f"  Loaded: {f.name} ({len(text):,} chars)")
    return docs

def chunk_text(text, source, chunk_size=CHUNK_SIZE, overlap=CHUNK_OVERLAP):
    # Split on double newlines first (paragraph-aware)
    paragraphs = re.split(r'\n\n+', text)
    chunks = []
    current_words = []
    current_len   = 0

    for para in paragraphs:
        words = para.split()
        if current_len + len(words) > chunk_size and current_words:
            chunk_text_str = " ".join(current_words)
            chunks.append({"text": chunk_text_str, "source": source})
            # Overlap
            current_words = current_words[-overlap:]
            current_len   = len(current_words)
        current_words.extend(words)
        current_len += len(words)

    if current_words:
        chunks.append({"text": " ".join(current_words), "source": source})
    return chunks

def main():
    print("=" * 60)
    print("Syd V3 - PCAP Knowledge Base -> FAISS Index")
    print("=" * 60)

    # Load model
    print("\nLoading sentence transformer...")
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    # Use same model as other tools
    hf_home = BASE_PATH / "hf_home"
    if hf_home.exists():
        os.environ["SENTENCE_TRANSFORMERS_HOME"] = str(hf_home / "sentence_transformers")
        os.environ["HF_HOME"] = str(hf_home)

    from sentence_transformers import SentenceTransformer
    import numpy as np
    import faiss

    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    print("  Model loaded")

    # Load and chunk
    print("\nLoading knowledge base files...")
    docs = load_md_files()

    print("\nChunking...")
    all_chunks = []
    for doc in docs:
        chunks = chunk_text(doc["text"], doc["source"])
        all_chunks.extend(chunks)
        print(f"  {doc['source']}: {len(chunks)} chunks")

    print(f"\nTotal chunks: {len(all_chunks)}")

    # Embed
    print("\nEmbedding chunks...")
    texts = [c["text"] for c in all_chunks]
    embeddings = model.encode(texts, show_progress_bar=True, batch_size=32)
    embeddings = embeddings.astype("float32")

    # Normalise for cosine similarity
    norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
    norms = np.where(norms == 0, 1, norms)
    embeddings = embeddings / norms

    # Build FAISS index
    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)
    print(f"  FAISS index: {index.ntotal} vectors, dim={dim}")

    # Save
    EMB_DIR.mkdir(parents=True, exist_ok=True)
    faiss_path = EMB_DIR / f"{INDEX_NAME}.faiss"
    pkl_path   = EMB_DIR / f"{INDEX_NAME}.pkl"

    faiss.write_index(index, str(faiss_path))
    with open(pkl_path, "wb") as f:
        pickle.dump(all_chunks, f)

    print(f"\n[SAVED] {faiss_path}")
    print(f"[SAVED] {pkl_path}")
    print(f"\nDone. {len(all_chunks)} chunks ready for RAG.")

if __name__ == "__main__":
    main()
