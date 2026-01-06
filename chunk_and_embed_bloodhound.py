#!/usr/bin/env python3
"""
Chunk and Embed BloodHound Knowledge Base
Converts BloodHound knowledge JSON into FAISS index with metadata
"""

import json
import numpy as np
import faiss
from pathlib import Path
from sentence_transformers import SentenceTransformer
from datetime import datetime
import pickle

# Configuration
KNOWLEDGE_FILE = Path("bloodhound_knowledge.json")
OUTPUT_FAISS = Path("rag_engine/embeddings/customers/customer_syd_bloodhound_knowledge_BloodHound.faiss")
OUTPUT_METADATA = Path("rag_engine/embeddings/customers/customer_syd_bloodhound_knowledge_BloodHound_metadata.json")
OUTPUT_PKL_CHUNKS = Path("rag_engine/embeddings/customers/customer_syd_bloodhound_knowledge_BloodHound.pkl")
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

def load_knowledge():
    """Load BloodHound knowledge base"""
    print(f"[1/5] Loading knowledge from: {KNOWLEDGE_FILE}")

    if not KNOWLEDGE_FILE.exists():
        print(f"ERROR: Knowledge file not found: {KNOWLEDGE_FILE}")
        print("Please ensure bloodhound_knowledge.json exists!")
        return None

    with open(KNOWLEDGE_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)

    print(f"OK Loaded {data['metadata']['total_entries']} knowledge entries")
    print(f"  Generated: {data['metadata']['generated_date']}")
    print(f"  Scope: {data['metadata']['scope']}")
    return data

def chunk_knowledge(knowledge):
    """Convert knowledge entries into embeddable chunks"""
    print("[2/5] Chunking knowledge into embeddable pieces...")

    chunks = []
    entries = knowledge.get('knowledge_entries', [])

    for entry in entries:
        entry_id = entry.get('id')
        category = entry.get('category')
        subcategory = entry.get('subcategory')
        topic = entry.get('topic')
        question = entry.get('question')
        answer = entry.get('answer')
        technical_details = entry.get('technical_details', '')
        difficulty = entry.get('difficulty', 'intermediate')
        team = entry.get('team', 'both')
        tags = entry.get('tags', [])

        # Main Q&A chunk
        main_content = f"""Question: {question}

Answer: {answer}

Technical Details: {technical_details}"""

        main_chunk = {
            'id': f"{entry_id}_main",
            'content': main_content,
            'metadata': {
                'entry_id': entry_id,
                'category': category,
                'subcategory': subcategory,
                'topic': topic,
                'question': question,
                'difficulty': difficulty,
                'team': team,
                'tags': tags,
                'chunk_type': 'explanation'
            }
        }
        chunks.append(main_chunk)

        # Command chunks - each command becomes its own chunk
        commands = entry.get('commands', [])
        for idx, cmd in enumerate(commands):
            cmd_text = f"""Tool: {cmd.get('tool', 'N/A')}
Command: {cmd.get('command', '')}

Description: {cmd.get('description', '')}

Syntax Explanation: {cmd.get('syntax_explanation', '')}

Context: {topic}"""

            cmd_chunk = {
                'id': f"{entry_id}_cmd{idx}",
                'content': cmd_text,
                'metadata': {
                    'entry_id': entry_id,
                    'category': category,
                    'subcategory': subcategory,
                    'topic': topic,
                    'tool': cmd.get('tool', ''),
                    'command': cmd.get('command', ''),
                    'difficulty': difficulty,
                    'team': team,
                    'tags': tags + ['command', cmd.get('tool', '').lower()],
                    'chunk_type': 'command'
                }
            }
            chunks.append(cmd_chunk)

        # Example chunks - each example becomes its own chunk
        examples = entry.get('examples', [])
        for idx, example in enumerate(examples):
            steps = example.get('steps', [])
            steps_text = "\n".join([f"{i+1}. {step}" for i, step in enumerate(steps)])

            example_text = f"""Scenario: {example.get('scenario', '')}

Steps:
{steps_text}

Expected Output: {example.get('expected_output', '')}

Notes: {example.get('notes', '')}

Context: {topic}"""

            example_chunk = {
                'id': f"{entry_id}_ex{idx}",
                'content': example_text,
                'metadata': {
                    'entry_id': entry_id,
                    'category': category,
                    'subcategory': subcategory,
                    'topic': topic,
                    'scenario': example.get('scenario', ''),
                    'difficulty': difficulty,
                    'team': team,
                    'tags': tags + ['example', 'scenario'],
                    'chunk_type': 'example'
                }
            }
            chunks.append(example_chunk)

        # Defense chunk (if applicable)
        defense = entry.get('defense', {})
        if defense and any([defense.get('detection'), defense.get('prevention'), defense.get('remediation')]):
            defense_text = f"""Defense for: {topic}

Detection: {defense.get('detection', 'N/A')}

Prevention: {defense.get('prevention', 'N/A')}

Remediation: {defense.get('remediation', 'N/A')}

Event IDs: {', '.join(defense.get('event_ids', []))}

Monitoring Queries: {defense.get('monitoring_queries', 'N/A')}"""

            defense_chunk = {
                'id': f"{entry_id}_defense",
                'content': defense_text,
                'metadata': {
                    'entry_id': entry_id,
                    'category': category,
                    'subcategory': subcategory,
                    'topic': topic,
                    'event_ids': defense.get('event_ids', []),
                    'difficulty': difficulty,
                    'team': 'blue',  # Defense is always blue team
                    'tags': tags + ['defense', 'detection', 'prevention'],
                    'chunk_type': 'defense'
                }
            }
            chunks.append(defense_chunk)

    print(f"OK Created {len(chunks)} chunks from {len(entries)} knowledge entries")

    # Print breakdown
    chunk_types = {}
    for chunk in chunks:
        ct = chunk['metadata']['chunk_type']
        chunk_types[ct] = chunk_types.get(ct, 0) + 1

    print(f"  Breakdown:")
    for ct, count in sorted(chunk_types.items(), key=lambda x: -x[1]):
        print(f"    {ct}: {count}")

    return chunks

def create_embeddings(chunks):
    """Generate embeddings for all chunks"""
    print("[3/5] Generating embeddings (this may take a few minutes)...")

    # Load embedding model
    print(f"  Loading model: {EMBEDDING_MODEL}")
    model = SentenceTransformer(EMBEDDING_MODEL)

    # Extract text content
    texts = [chunk['content'] for chunk in chunks]

    # Generate embeddings
    embeddings = model.encode(
        texts,
        show_progress_bar=True,
        batch_size=32
    )

    print(f"OK Generated embeddings: {embeddings.shape}")
    return embeddings

def build_faiss_index(embeddings):
    """Create FAISS index from embeddings"""
    print("[4/5] Building FAISS index...")

    # Create FAISS index
    dimension = embeddings.shape[1]
    index = faiss.IndexFlatL2(dimension)

    # Add embeddings
    index.add(np.array(embeddings).astype('float32'))

    print(f"OK FAISS index created: {index.ntotal} vectors, {dimension} dimensions")
    return index

def save_index_and_metadata(index, chunks):
    """Save FAISS index and metadata"""
    print("[5/5] Saving index and metadata...")

    # Ensure directories exist
    OUTPUT_FAISS.parent.mkdir(parents=True, exist_ok=True)

    # Save FAISS index
    faiss.write_index(index, str(OUTPUT_FAISS))
    print(f"OK FAISS index saved: {OUTPUT_FAISS}")

    # Save chunks as a pickle file for ToolRAG
    with open(OUTPUT_PKL_CHUNKS, 'wb') as f:
        pickle.dump(chunks, f)
    print(f"OK Chunks saved: {OUTPUT_PKL_CHUNKS}")

    # Save metadata
    metadata = {
        'created_date': datetime.now().isoformat(),
        'total_chunks': len(chunks),
        'embedding_model': EMBEDDING_MODEL,
        'source': 'bloodhound_knowledge.json',
        'chunks': chunks
    }

    with open(OUTPUT_METADATA, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print(f"OK Metadata saved: {OUTPUT_METADATA}")

def test_retrieval(index):
    """Test the index with sample queries"""
    print("\n" + "=" * 60)
    print("TESTING RETRIEVAL")
    print("=" * 60)

    # Load chunks from the PKL file
    try:
        with open(OUTPUT_PKL_CHUNKS, 'rb') as f:
            chunks = pickle.load(f)
        print(f"OK Loaded {len(chunks)} chunks from {OUTPUT_PKL_CHUNKS}")
    except FileNotFoundError:
        print(f"Error: Chunks PKL file not found at {OUTPUT_PKL_CHUNKS}. Cannot run retrieval test.")
        return

    # Load embedding model
    model = SentenceTransformer(EMBEDDING_MODEL)

    # Test queries
    test_queries = [
        "How do I use BloodHound to find Domain Admin attack paths?",
        "What is Kerberoasting and how do I detect it?",
        "How do I exploit ADCS ESC1 vulnerabilities?",
        "What are the best defense strategies for Active Directory?"
    ]

    for test_query in test_queries:
        print(f"\n{'-' * 60}")
        print(f"Query: \"{test_query}\"")
        print(f"{'-' * 60}")

        # Encode query
        query_embedding = model.encode([test_query])

        # Search
        k = 3  # Top 3 results
        distances, indices = index.search(
            np.array(query_embedding).astype('float32'),
            k
        )

        for i, idx in enumerate(indices[0]):
            chunk = chunks[idx]
            print(f"\n{i+1}. [{chunk['metadata']['category']}] {chunk['metadata']['topic']}")
            print(f"   Type: {chunk['metadata']['chunk_type']} | Team: {chunk['metadata']['team']} | Difficulty: {chunk['metadata']['difficulty']}")
            print(f"   Preview: {chunk['content'][:200].replace(chr(10), ' ')}...")
            print(f"   Distance: {distances[0][i]:.4f}")

    print("\n" + "=" * 60)

def main():
    print("=" * 60)
    print("BLOODHOUND KNOWLEDGE BASE -> FAISS INDEX")
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
    print("OK DONE! FAISS index ready to use!")
    print("=" * 60)
    print()
    print("Files created:")
    print(f"  • {OUTPUT_FAISS}")
    print(f"  • {OUTPUT_METADATA}")
    print(f"  • {OUTPUT_PKL_CHUNKS}")
    print()
    print("Next steps:")
    print("1. Run: python syd.py")
    print("2. Go to Red Team -> BloodHound")
    print("3. Ask questions in the Ask Syd panel!")
    print()

if __name__ == "__main__":
    main()
