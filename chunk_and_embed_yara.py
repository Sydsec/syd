#!/usr/bin/env python3
"""
YARA Knowledge Base Chunking and Embedding
Processes all YARA markdown files and creates FAISS embeddings

Author: Ask Syd Team
Version: 1.0
Date: 2024-01-15
"""

import numpy as np
import faiss
from pathlib import Path
from sentence_transformers import SentenceTransformer
import pickle
import re

# Configuration
KNOWLEDGE_DIR = Path("knowledge_bases/yara")
OUTPUT_FAISS = Path("rag_engine/embeddings/customers/customer_syd_yara_knowledge.faiss")
OUTPUT_PKL = Path("rag_engine/embeddings/customers/customer_syd_yara_knowledge.pkl")
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# Chunking parameters
MAX_CHUNK_SIZE = 512  # tokens (approximate)
CHUNK_OVERLAP = 50    # tokens


def load_markdown_files():
    """Load all markdown files from knowledge base"""
    print(f"[1/4] Loading YARA knowledge from: {KNOWLEDGE_DIR}")

    if not KNOWLEDGE_DIR.exists():
        print(f"ERROR: Knowledge directory not found: {KNOWLEDGE_DIR}")
        return []

    md_files = sorted(KNOWLEDGE_DIR.glob("*.md"))
    print(f"OK Found {len(md_files)} markdown files")

    documents = []
    for md_file in md_files:
        try:
            with open(md_file, 'r', encoding='utf-8') as f:
                content = f.read()
                documents.append({
                    'filename': md_file.name,
                    'content': content
                })
                print(f"   - {md_file.name}: {len(content)} chars")
        except Exception as e:
            print(f"   ! Error reading {md_file.name}: {e}")

    return documents


def chunk_documents(documents):
    """
    Chunk markdown into semantic sections
    Preserves code blocks and examples intact
    """
    print("[2/4] Chunking documents...")

    chunks = []

    for doc in documents:
        content = doc['content']
        filename = doc['filename']

        # Split by headers while preserving structure
        sections = split_by_headers(content)

        for i, section in enumerate(sections):
            # Skip very small sections
            if len(section['content'].strip()) < 50:
                continue

            # If section is too large, split further
            if len(section['content']) > 2000:
                sub_chunks = split_large_section(section['content'], section['header'])
                for j, sub_chunk in enumerate(sub_chunks):
                    chunk = {
                        'id': f"{filename}_{i}_{j}",
                        'content': sub_chunk['content'].strip(),
                        'metadata': {
                            'filename': filename,
                            'header': sub_chunk['header'],
                            'chunk_index': i,
                            'sub_index': j,
                            'type': 'yara_knowledge'
                        }
                    }
                    chunks.append(chunk)
            else:
                chunk = {
                    'id': f"{filename}_{i}",
                    'content': section['content'].strip(),
                    'metadata': {
                        'filename': filename,
                        'header': section['header'],
                        'chunk_index': i,
                        'type': 'yara_knowledge'
                    }
                }
                chunks.append(chunk)

    print(f"OK Created {len(chunks)} chunks")
    return chunks


def split_by_headers(content):
    """Split content by markdown headers"""
    sections = []
    current_section = []
    current_header = ""

    for line in content.split('\n'):
        # Check for headers (# or ##)
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

    return sections


def split_large_section(content, header):
    """Split large sections while preserving code blocks"""
    sub_chunks = []

    # Find code blocks and preserve them
    code_block_pattern = r'```[\s\S]*?```'
    code_blocks = list(re.finditer(code_block_pattern, content))

    if not code_blocks:
        # No code blocks, split by paragraphs
        paragraphs = content.split('\n\n')
        current_chunk = []
        current_length = 0

        for para in paragraphs:
            para_length = len(para)

            if current_length + para_length > 1500 and current_chunk:
                sub_chunks.append({
                    'header': header,
                    'content': '\n\n'.join(current_chunk)
                })
                current_chunk = [para]
                current_length = para_length
            else:
                current_chunk.append(para)
                current_length += para_length

        if current_chunk:
            sub_chunks.append({
                'header': header,
                'content': '\n\n'.join(current_chunk)
            })
    else:
        # Has code blocks - try to keep code with its explanation
        last_end = 0
        for match in code_blocks:
            # Text before code block
            pre_text = content[last_end:match.start()].strip()
            code_text = match.group()

            # Include some context before code
            context_start = max(0, match.start() - 500)
            context = content[context_start:match.start()].strip()

            chunk_content = f"{context}\n\n{code_text}" if context else code_text

            if len(chunk_content) > 100:
                sub_chunks.append({
                    'header': header,
                    'content': chunk_content
                })

            last_end = match.end()

        # Remaining text after last code block
        remaining = content[last_end:].strip()
        if len(remaining) > 100:
            sub_chunks.append({
                'header': header,
                'content': remaining
            })

    # Ensure we have at least one chunk
    if not sub_chunks:
        sub_chunks.append({
            'header': header,
            'content': content[:1500]
        })

    return sub_chunks


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


def verify_index():
    """Verify the created index"""
    print("\n[VERIFY] Testing index...")

    try:
        # Load index
        index = faiss.read_index(str(OUTPUT_FAISS))
        with open(OUTPUT_PKL, 'rb') as f:
            chunks = pickle.load(f)

        print(f"OK Index loaded: {index.ntotal} vectors")
        print(f"OK Chunks loaded: {len(chunks)} entries")

        # Test query
        model = SentenceTransformer(EMBEDDING_MODEL)
        test_query = "How do I write a YARA rule to detect malware?"
        query_embedding = model.encode([test_query], convert_to_numpy=True)
        faiss.normalize_L2(query_embedding)

        D, I = index.search(query_embedding, 3)

        print(f"\nTest query: '{test_query}'")
        print("Top 3 results:")
        for i, (idx, score) in enumerate(zip(I[0], D[0])):
            chunk = chunks[idx]
            preview = chunk['content'][:100].replace('\n', ' ')
            print(f"  {i+1}. [{score:.3f}] {chunk['metadata']['filename']}: {preview}...")

        return True

    except Exception as e:
        print(f"ERROR: Verification failed: {e}")
        return False


def main():
    print("=" * 60)
    print("YARA Knowledge Base Embedder")
    print("=" * 60)
    print()

    # Load documents
    documents = load_markdown_files()
    if not documents:
        print("ERROR: No documents found!")
        return False

    # Chunk documents
    chunks = chunk_documents(documents)
    if not chunks:
        print("ERROR: No chunks created!")
        return False

    # Generate embeddings
    embeddings, model = embed_chunks(chunks)

    # Create FAISS index
    index = create_faiss_index(embeddings, chunks)

    # Summary
    print()
    print("=" * 60)
    print("SUCCESS! YARA knowledge base embedded")
    print("=" * 60)
    print(f"Total documents: {len(documents)}")
    print(f"Total chunks: {len(chunks)}")
    print(f"Index size: {index.ntotal} vectors")
    print(f"Dimension: {index.d}")
    print()
    print("Files created:")
    print(f"  - {OUTPUT_FAISS}")
    print(f"  - {OUTPUT_PKL}")
    print()

    # Verify
    success = verify_index()

    return success


if __name__ == "__main__":
    import sys
    success = main()
    sys.exit(0 if success else 1)
