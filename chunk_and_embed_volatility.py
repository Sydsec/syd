#!/usr/bin/env python3
"""
Chunk and Embed Volatility Knowledge Base
Converts markdown knowledge base into FAISS index for RAG

FIXED: PyTorch 2.6.0 meta tensor issue
Mirrors nmap chunking architecture
"""

import os
# Environment variables must be set BEFORE torch imports
os.environ["CUDA_VISIBLE_DEVICES"] = ""
os.environ["ACCELERATE_USE_CPU"] = "1"
os.environ["TRANSFORMERS_NO_ADVISORY_WARNINGS"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"

import json
import numpy as np
import faiss
from pathlib import Path
from sentence_transformers import SentenceTransformer
from datetime import datetime
import pickle
import re

# Configuration
KNOWLEDGE_DIR = Path("knowledge_bases/volatility")
OUTPUT_FAISS = Path("rag_engine/embeddings/customers/customer_syd_volatility_knowledge_Volatility3.faiss")
OUTPUT_PKL = Path("rag_engine/embeddings/customers/customer_syd_volatility_knowledge_Volatility3.pkl")
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

def load_markdown_files():
    """Load all markdown files from knowledge base directory"""
    print(f"[1/5] Loading Volatility knowledge from: {KNOWLEDGE_DIR}")

    markdown_files = sorted(KNOWLEDGE_DIR.glob("*.md"))

    if not markdown_files:
        print(f"ERROR: No markdown files found in {KNOWLEDGE_DIR}")
        print("Please create knowledge base files first!")
        return []

    documents = []
    for md_file in markdown_files:
        with open(md_file, 'r', encoding='utf-8') as f:
            content = f.read()
            documents.append({
                'filename': md_file.name,
                'content': content
            })

    print(f"[OK] Loaded {len(documents)} knowledge base files")
    return documents

def extract_sections(markdown_content):
    """Extract major sections from markdown (## headers)"""
    sections = []
    current_section = {'title': 'Introduction', 'content': ''}

    lines = markdown_content.split('\n')
    for line in lines:
        # Match ## headers (level 2)
        if line.startswith('## '):
            # Save previous section if it has content
            if current_section['content'].strip():
                sections.append(current_section)
            # Start new section
            current_section = {
                'title': line[3:].strip(),
                'content': ''
            }
        else:
            current_section['content'] += line + '\n'

    # Add last section
    if current_section['content'].strip():
        sections.append(current_section)

    return sections

def chunk_by_paragraphs(text, max_chunk_size=1000):
    """Split text into paragraph-sized chunks"""
    # Split by double newlines (paragraphs)
    paragraphs = text.split('\n\n')

    chunks = []
    current_chunk = ''

    for para in paragraphs:
        para = para.strip()
        if not para:
            continue

        # If adding this paragraph exceeds max size, start new chunk
        if len(current_chunk) + len(para) > max_chunk_size and current_chunk:
            chunks.append(current_chunk.strip())
            current_chunk = para
        else:
            if current_chunk:
                current_chunk += '\n\n' + para
            else:
                current_chunk = para

    # Add last chunk
    if current_chunk.strip():
        chunks.append(current_chunk.strip())

    return chunks

def chunk_knowledge(documents):
    """Convert knowledge documents into chunks with metadata"""
    print("[2/5] Chunking knowledge into embeddable pieces...")

    all_chunks = []

    for doc in documents:
        filename = doc['filename']
        content = doc['content']

        # Extract main title (first # header)
        title_match = re.search(r'^# (.+)$', content, re.MULTILINE)
        doc_title = title_match.group(1) if title_match else filename.replace('.md', '')

        # Extract sections (## headers)
        sections = extract_sections(content)

        for section in sections:
            section_title = section['title']
            section_content = section['content']

            # Chunk large sections into paragraphs
            para_chunks = chunk_by_paragraphs(section_content, max_chunk_size=800)

            for idx, chunk_text in enumerate(para_chunks):
                if len(chunk_text.strip()) < 50:  # Skip very small chunks
                    continue

                chunk = {
                    'id': f"{filename}_{len(all_chunks)}",
                    'content': chunk_text,
                    'metadata': {
                        'filename': filename,
                        'document_title': doc_title,
                        'section': section_title,
                        'chunk_index': idx,
                        'source': 'volatility_knowledge_base'
                    }
                }
                all_chunks.append(chunk)

    print(f"[OK] Created {len(all_chunks)} chunks")
    return all_chunks

def embed_chunks(chunks):
    """Generate embeddings for all chunks"""
    print(f"[3/5] Generating embeddings using {EMBEDDING_MODEL}...")
    print("Loading embedding model (this may take a minute)...")

    # Load embedding model (CPU-only mode enforced by environment variables)
    model = SentenceTransformer(EMBEDDING_MODEL)

    # Extract content for embedding
    texts = [chunk['content'] for chunk in chunks]

    print(f"Embedding {len(texts)} chunks...")
    embeddings = model.encode(texts, show_progress_bar=True, convert_to_numpy=True)

    print(f"[OK] Generated embeddings: {embeddings.shape}")
    return embeddings

def build_faiss_index(embeddings):
    """Build FAISS index for similarity search"""
    print("[4/5] Building FAISS index...")

    # Normalize embeddings for cosine similarity (must match query-time normalization in syd.py)
    faiss.normalize_L2(embeddings)

    # Use IndexFlatIP (inner product) after normalization = cosine similarity
    # This is consistent with Nmap and YARA embedding modules
    dimension = embeddings.shape[1]
    index = faiss.IndexFlatIP(dimension)
    index.add(embeddings)

    print(f"[OK] Built FAISS index with {index.ntotal} vectors")
    return index

def save_artifacts(index, chunks):
    """Save FAISS index and chunk metadata"""
    print("[5/5] Saving artifacts...")

    # Ensure output directory exists
    OUTPUT_FAISS.parent.mkdir(parents=True, exist_ok=True)

    # Save FAISS index
    faiss.write_index(index, str(OUTPUT_FAISS))
    print(f"[OK] Saved FAISS index: {OUTPUT_FAISS}")

    # Save chunks with metadata (pickle for fast loading)
    with open(OUTPUT_PKL, 'wb') as f:
        pickle.dump(chunks, f)
    print(f"[OK] Saved chunk metadata: {OUTPUT_PKL}")

    # Also save as JSON for human readability
    json_path = OUTPUT_PKL.with_suffix('.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(chunks, f, indent=2, ensure_ascii=False)
    print(f"[OK] Saved readable metadata: {json_path}")

def main():
    print("=" * 60)
    print("Volatility Knowledge Base Embedder")
    print("=" * 60)
    print()

    # Step 1: Load markdown files
    documents = load_markdown_files()
    if not documents:
        return 1

    # Step 2: Chunk into smaller pieces
    chunks = chunk_knowledge(documents)
    if not chunks:
        print("ERROR: No chunks created!")
        return 1

    # Step 3: Generate embeddings
    embeddings = embed_chunks(chunks)

    # Step 4: Build FAISS index
    index = build_faiss_index(embeddings)

    # Step 5: Save everything
    save_artifacts(index, chunks)

    print()
    print("=" * 60)
    print("[SUCCESS] SUCCESS - Volatility knowledge base is ready!")
    print("=" * 60)
    print()
    print("Files created:")
    print(f"  - FAISS index: {OUTPUT_FAISS}")
    print(f"  - Chunk metadata: {OUTPUT_PKL}")
    print()
    print("Next steps:")
    print("  1. Restart Syd to load new knowledge base")
    print("  2. Test with: 'What is Volatility?' in Ask Syd")
    print("  3. Load a Volatility dump and ask analysis questions")
    print()

    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
