#!/usr/bin/env python3
"""
Chunk and Embed Nmap Knowledge Base
Converts Nmap markdown documentation into FAISS index
"""

import numpy as np
import faiss
from pathlib import Path
from sentence_transformers import SentenceTransformer
import pickle
import json

# Configuration
KNOWLEDGE_DIR = Path("knowledge_bases/nmap")
OUTPUT_FAISS = Path("rag_engine/embeddings/customers/customer_syd_nmap_knowledge.faiss")
OUTPUT_PKL = Path("rag_engine/embeddings/customers/customer_syd_nmap_knowledge.pkl")
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

def load_markdown_files():
    """Load all markdown files from knowledge base"""
    print(f"[1/4] Loading Nmap knowledge from: {KNOWLEDGE_DIR}")

    if not KNOWLEDGE_DIR.exists():
        print(f"ERROR: Knowledge directory not found: {KNOWLEDGE_DIR}")
        return []

    md_files = list(KNOWLEDGE_DIR.glob("*.md"))
    print(f"OK Found {len(md_files)} markdown files")

    documents = []
    for md_file in md_files:
        with open(md_file, 'r', encoding='utf-8') as f:
            content = f.read()
            documents.append({
                'filename': md_file.name,
                'content': content
            })

    return documents

def chunk_documents(documents):
    """Chunk markdown into semantic sections"""
    print("[2/4] Chunking documents...")

    chunks = []

    for doc in documents:
        content = doc['content']
        filename = doc['filename']

        # Split by headers (# or ##)
        sections = []
        current_section = []
        current_header = ""

        for line in content.split('\n'):
            if line.startswith('# ') or line.startswith('## '):
                # Save previous section
                if current_section:
                    sections.append({
                        'header': current_header,
                        'content': '\n'.join(current_section)
                    })
                current_header = line.strip('#').strip()
                current_section = [line]
            else:
                current_section.append(line)

        # Add last section
        if current_section:
            sections.append({
                'header': current_header,
                'content': '\n'.join(current_section)
            })

        # Create chunks from sections
        for i, section in enumerate(sections):
            if len(section['content'].strip()) > 50:  # Skip tiny sections
                chunk = {
                    'id': f"{filename}_{i}",
                    'content': section['content'].strip(),
                    'metadata': {
                        'filename': filename,
                        'header': section['header'],
                        'chunk_index': i
                    }
                }
                chunks.append(chunk)

    print(f"OK Created {len(chunks)} chunks")
    return chunks

def embed_chunks(chunks):
    """Generate embeddings for chunks"""
    print(f"[3/4] Embedding {len(chunks)} chunks using {EMBEDDING_MODEL}...")

    model = SentenceTransformer(EMBEDDING_MODEL)

    texts = [chunk['content'] for chunk in chunks]
    embeddings = model.encode(texts, show_progress_bar=True, convert_to_numpy=True)

    print(f"OK Generated embeddings: shape {embeddings.shape}")
    return embeddings, model

def create_faiss_index(embeddings, chunks):
    """Create and save FAISS index"""
    print("[4/4] Creating FAISS index...")

    # Normalize embeddings for cosine similarity
    faiss.normalize_L2(embeddings)

    # Create index
    dimension = embeddings.shape[1]
    index = faiss.IndexFlatIP(dimension)  # Inner product (cosine after normalization)
    index.add(embeddings)

    # Ensure output directory exists
    OUTPUT_FAISS.parent.mkdir(parents=True, exist_ok=True)

    # Save FAISS index
    faiss.write_index(index, str(OUTPUT_FAISS))
    print(f"OK Saved FAISS index: {OUTPUT_FAISS}")

    # Save chunks with metadata
    with open(OUTPUT_PKL, 'wb') as f:
        pickle.dump(chunks, f)
    print(f"OK Saved chunks metadata: {OUTPUT_PKL}")

    return index

def main():
    print("=" * 60)
    print("Nmap Knowledge Base Embedder")
    print("=" * 60)
    print()

    # Load documents
    documents = load_markdown_files()
    if not documents:
        return

    # Chunk documents
    chunks = chunk_documents(documents)
    if not chunks:
        print("ERROR: No chunks created!")
        return

    # Generate embeddings
    embeddings, model = embed_chunks(chunks)

    # Create FAISS index
    index = create_faiss_index(embeddings, chunks)

    print()
    print("=" * 60)
    print("SUCCESS! Nmap knowledge base embedded")
    print("=" * 60)
    print(f"Total chunks: {len(chunks)}")
    print(f"Index size: {index.ntotal} vectors")
    print(f"Dimension: {index.d}")
    print()
    print("Files created:")
    print(f"  - {OUTPUT_FAISS}")
    print(f"  - {OUTPUT_PKL}")
    print()

if __name__ == "__main__":
    main()
