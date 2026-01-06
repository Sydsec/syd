"""
Fix ALL FAISS indexes (Nmap, BloodHound, Volatility) by regenerating with proper CPU embeddings
This fixes the "Cannot copy out of meta tensor" error
"""
import os
# Critical: Set environment variables BEFORE any torch imports
os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"
os.environ["TRANSFORMERS_NO_ADVISORY_WARNINGS"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["TORCH_DEVICE_BACKEND_INIT_PRIORITY"] = "cpu"
os.environ["ACCELERATE_USE_CPU"] = "1"

import torch
torch.set_default_device('cpu')

# Monkey-patch torch.empty to never create meta tensors
_original_empty = torch.empty
def patched_empty(*args, **kwargs):
    if 'device' in kwargs and kwargs['device'] == 'meta':
        kwargs['device'] = 'cpu'
    return _original_empty(*args, **kwargs)
torch.empty = patched_empty

import pickle
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
from pathlib import Path

def fix_faiss_index(name, pkl_path, faiss_path):
    """Fix a single FAISS index"""
    print(f"\n{'='*60}")
    print(f"Fixing {name} FAISS index")
    print(f"{'='*60}")

    try:
        print(f"[1/4] Loading chunks from {pkl_path.name}...")
        with open(pkl_path, 'rb') as f:
            chunks = pickle.load(f)
        print(f"[OK] Loaded {len(chunks)} chunks")

        print("[2/4] Loading embedding model on CPU...")
        model = SentenceTransformer("all-MiniLM-L6-v2", device='cpu')
        model.eval()

        # Verify model is on CPU
        for param in model.parameters():
            if param.device.type == 'meta':
                raise RuntimeError(f"Model has parameters on meta device!")

        print(f"[OK] Model on device: {next(model.parameters()).device}")

        print("[3/4] Generating fresh embeddings...")
        batch_size = 32
        all_embeddings = []

        for i in range(0, len(chunks), batch_size):
            batch = chunks[i:i+batch_size]
            embeddings = model.encode(batch, show_progress_bar=False, convert_to_numpy=True)
            all_embeddings.append(embeddings)

            if (i // batch_size) % 10 == 0:
                print(f"   Progress: {i}/{len(chunks)} chunks...")

        embeddings_matrix = np.vstack(all_embeddings).astype('float32')
        print(f"[OK] Embeddings shape: {embeddings_matrix.shape}")

        print("[4/4] Building new FAISS index...")
        dimension = embeddings_matrix.shape[1]
        index = faiss.IndexFlatL2(dimension)
        faiss.normalize_L2(embeddings_matrix)
        index.add(embeddings_matrix)

        # Backup old index first
        if faiss_path.exists():
            backup_path = faiss_path.with_suffix('.faiss.backup')
            faiss_path.rename(backup_path)
            print(f"[BACKUP] Old index saved to {backup_path.name}")

        faiss.write_index(index, str(faiss_path))
        print(f"[SUCCESS] Fixed index: {index.ntotal} vectors, dim {dimension}")
        return True

    except Exception as e:
        print(f"[ERROR] Failed to fix {name}: {e}")
        import traceback
        traceback.print_exc()
        return False

# Fix all three indexes
base_dir = Path("rag_engine/embeddings/customers")

indexes_to_fix = [
    ("Nmap",
     base_dir / "customer_syd_Nmap.pkl",
     base_dir / "customer_syd_Nmap.faiss"),

    ("BloodHound",
     base_dir / "customer_syd_bloodhound_knowledge_BloodHound.pkl",
     base_dir / "customer_syd_bloodhound_knowledge_BloodHound.faiss"),

    ("Volatility",
     base_dir / "customer_syd_volatility_knowledge_Volatility3.pkl",
     base_dir / "customer_syd_volatility_knowledge_Volatility3.faiss"),
]

print("\n" + "="*60)
print("FAISS Index Repair Tool")
print("="*60)
print("This will regenerate all FAISS indexes with proper CPU embeddings")
print("to fix the 'Cannot copy out of meta tensor' error\n")

results = {}
for name, pkl_path, faiss_path in indexes_to_fix:
    if not pkl_path.exists():
        print(f"\n[SKIP] {name}: {pkl_path.name} not found")
        results[name] = "SKIPPED"
        continue

    success = fix_faiss_index(name, pkl_path, faiss_path)
    results[name] = "SUCCESS" if success else "FAILED"

print("\n" + "="*60)
print("SUMMARY")
print("="*60)
for name, status in results.items():
    icon = "✓" if status == "SUCCESS" else "✗" if status == "FAILED" else "⊘"
    print(f"{icon} {name}: {status}")
print("="*60)
