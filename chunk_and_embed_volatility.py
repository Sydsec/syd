#!/usr/bin/env python3
"""
Chunk and Embed Volatility Knowledge Base
Converts Opus-generated JSON into FAISS index with metadata
"""

import json
import numpy as np
import faiss
from pathlib import Path
from sentence_transformers import SentenceTransformer
from datetime import datetime
import pickle

# Configuration
KNOWLEDGE_FILE = Path("knowledge_bases/volatility/generated/volatility_complete_knowledge.json")
OUTPUT_FAISS = Path("rag_engine/embeddings/customers/customer_syd_volatility_knowledge_Volatility3.faiss")
OUTPUT_METADATA = Path("rag_engine/embeddings/customers/customer_syd_volatility_knowledge_Volatility3_metadata.json")
OUTPUT_PKL_CHUNKS = Path("rag_engine/embeddings/customers/customer_syd_volatility_knowledge_Volatility3.pkl")
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

def load_knowledge():
    """Load Opus-generated knowledge"""
    print(f"[1/5] Loading knowledge from: {KNOWLEDGE_FILE}")

    if not KNOWLEDGE_FILE.exists():
        print(f"ERROR: Knowledge file not found: {KNOWLEDGE_FILE}")
        print("Please generate knowledge with Opus first!")
        return None

    with open(KNOWLEDGE_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)

    print(f"✓ Loaded knowledge base")
    return data

def chunk_knowledge(knowledge):
    """Convert knowledge into chunks with metadata"""
    print("[2/5] Chunking knowledge into embeddable pieces...")

    chunks = []

    categories = knowledge.get('knowledge_base', {}).get('categories', [])

    for category in categories:
        category_id = category.get('id')
        category_name = category.get('name')

        for topic in category.get('topics', []):
            topic_title = topic.get('title')
            keywords = topic.get('keywords', [])
            difficulty = topic.get('difficulty', 'intermediate')

            # Main content chunk
            main_chunk = {
                'id': f"{category_id}_{len(chunks)}",
                'content': topic.get('content', ''),
                'metadata': {
                    'category': category_id,
                    'category_name': category_name,
                    'topic': topic_title,
                    'keywords': keywords,
                    'difficulty': difficulty,
                    'chunk_type': 'explanation'
                }
            }
            chunks.append(main_chunk)

            # Example chunks
            for idx, example in enumerate(topic.get('examples', [])):
                example_text = f"""Command: {example.get('command', '')}

Explanation: {example.get('explanation', '')}

Use Case: {example.get('use_case', '')}

Output Sample:
{example.get('output_sample', '')}
"""

                example_chunk = {
                    'id': f"{category_id}_{len(chunks)}_ex{idx}",
                    'content': example_text,
                    'metadata': {
                        'category': category_id,
                        'category_name': category_name,
                        'topic': topic_title,
                        'keywords': keywords + ['example', 'command'],
                        'difficulty': difficulty,
                        'chunk_type': 'example',
                        'command': example.get('command', '')
                    }
                }
                chunks.append(example_chunk)

            # Best practices chunk
            if topic.get('best_practices'):
                bp_text = "Best Practices:\n" + "\n".join([f"• {bp}" for bp in topic.get('best_practices', [])])

                bp_chunk = {
                    'id': f"{category_id}_{len(chunks)}_bp",
                    'content': bp_text,
                    'metadata': {
                        'category': category_id,
                        'category_name': category_name,
                        'topic': topic_title,
                        'keywords': keywords + ['best practices'],
                        'difficulty': difficulty,
                        'chunk_type': 'best_practice'
                    }
                }
                chunks.append(bp_chunk)

            # Warnings chunk
            if topic.get('warnings'):
                warn_text = "Warnings:\n" + "\n".join([f"⚠ {w}" for w in topic.get('warnings', [])])

                warn_chunk = {
                    'id': f"{category_id}_{len(chunks)}_warn",
                    'content': warn_text,
                    'metadata': {
                        'category': category_id,
                        'category_name': category_name,
                        'topic': topic_title,
                        'keywords': keywords + ['warning', 'safety'],
                        'difficulty': difficulty,
                        'chunk_type': 'warning'
                    }
                }
                chunks.append(warn_chunk)

    print(f"✓ Created {len(chunks)} chunks from {len(categories)} categories")
    return chunks

def create_embeddings(chunks):
    """Generate embeddings for all chunks"""
    print("[3/5] Generating embeddings (this may take a few minutes)...")

    # Load embedding model
    model = SentenceTransformer(EMBEDDING_MODEL)

    # Extract text content
    texts = [chunk['content'] for chunk in chunks]

    # Generate embeddings
    embeddings = model.encode(
        texts,
        show_progress_bar=True,
        batch_size=32
    )

    print(f"✓ Generated embeddings: {embeddings.shape}")
    return embeddings

def build_faiss_index(embeddings):
    """Create FAISS index from embeddings"""
    print("[4/5] Building FAISS index...")

    # Create FAISS index
    dimension = embeddings.shape[1]
    index = faiss.IndexFlatL2(dimension)

    # Add embeddings
    index.add(np.array(embeddings).astype('float32'))

    print(f"✓ FAISS index created: {index.ntotal} vectors, {dimension} dimensions")
    return index

def save_index_and_metadata(index, chunks):
    """Save FAISS index and metadata"""
    print("[5/5] Saving index and metadata...")

    # Ensure directories exist
    OUTPUT_FAISS.parent.mkdir(parents=True, exist_ok=True)

    # Save FAISS index
    faiss.write_index(index, str(OUTPUT_FAISS))
    print(f"✓ FAISS index saved: {OUTPUT_FAISS}")

    # Save chunks as a pickle file for ToolRAG
    with open(OUTPUT_PKL_CHUNKS, 'wb') as f:
        pickle.dump(chunks, f)
    print(f"✓ Chunks saved: {OUTPUT_PKL_CHUNKS}")

    # Save metadata
    metadata = {
        'created_date': datetime.now().isoformat(),
        'total_chunks': len(chunks),
        'embedding_model': EMBEDDING_MODEL,
        'chunks': chunks
    }

    with open(OUTPUT_METADATA, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print(f"✓ Metadata saved: {OUTPUT_METADATA}")

def test_retrieval(index):
    """Test the index with a sample query"""
    print("\n" + "=" * 60)
    print("TESTING RETRIEVAL")
    print("=" * 60)

    # Load chunks from the PKL file
    try:
        with open(OUTPUT_PKL_CHUNKS, 'rb') as f:
            chunks = pickle.load(f)
        print(f"✓ Loaded {len(chunks)} chunks from {OUTPUT_PKL_CHUNKS}")
    except FileNotFoundError:
        print(f"Error: Chunks PKL file not found at {OUTPUT_PKL_CHUNKS}. Cannot run retrieval test.")
        return

    # Load embedding model
    model = SentenceTransformer(EMBEDDING_MODEL)

    # Test query
    test_query = "How do I find processes with code injection?"
    print(f"\nTest Query: \"{test_query}\"\n")

    # Encode query
    query_embedding = model.encode([test_query])

    # Search
    k = 5  # Top 5 results
    distances, indices = index.search(
        np.array(query_embedding).astype('float32'),
        k
    )

    print(f"Top {k} Results:")
    print("-" * 60)

    for i, idx in enumerate(indices[0]):
        chunk = chunks[idx]
        print(f"\n{i+1}. [{chunk['metadata']['category_name']}] {chunk['metadata']['topic']}")
        print(f"   Type: {chunk['metadata']['chunk_type']}")
        print(f"   Preview: {chunk['content'][:150]}...")
        print(f"   Distance: {distances[0][i]:.4f}")

    print("\n" + "=" * 60)

def main():
    print("=" * 60)
    print("VOLATILITY KNOWLEDGE BASE → FAISS INDEX")
    print("=" * 60)
    print()

    # Load knowledge
    knowledge = load_knowledge()
    if not knowledge:
        return

    # Chunk
    chunks = chunk_knowledge(knowledge)

    # Embed
    embeddings = create_embeddings(chunks)

    # Build index
    index = build_faiss_index(embeddings)

    # Save
    save_index_and_metadata(index, chunks)

    # Test
    test_retrieval(index)

    print("\n" + "=" * 60)
    print("✓ DONE! FAISS index ready to use!")
    print("=" * 60)
    print()
    print("Next steps:")
    print("1. Run: python syd.py")
    print("2. Go to Blue Team → Volatility3")
    print("3. Ask questions in the Ask Syd panel!")
    print()

if __name__ == "__main__":
    main()
