# Utility Scripts

Documentation for maintenance and utility scripts.

## Knowledge Base Management

### chunk_and_embed_bloodhound.py

Generates FAISS index for BloodHound knowledge base.

**Usage:**
```bash
python chunk_and_embed_bloodhound.py
```

**What it does:**
- Reads markdown files from `knowledge_bases/bloodhound/`
- Chunks documents into 512-token segments
- Generates embeddings using sentence-transformers
- Creates FAISS index for fast retrieval
- Saves to `rag_engine/embeddings/customers/`

**When to run:**
- First-time setup
- After updating BloodHound knowledge base
- If index becomes corrupted

**Output files:**
- `customer_syd_bloodhound_knowledge_BloodHound.faiss` (vector index)
- `customer_syd_bloodhound_knowledge_BloodHound.pkl` (chunk metadata)

**Time required:** 2-3 minutes

### chunk_and_embed_volatility.py

Generates FAISS index for Volatility knowledge base.

**Usage:**
```bash
python chunk_and_embed_volatility.py
```

**What it does:**
- Reads markdown files from `knowledge_bases/volatility/`
- Chunks documents into 512-token segments
- Generates embeddings
- Creates FAISS index
- Saves to `rag_engine/embeddings/customers/`

**Output files:**
- `customer_syd_volatility_knowledge_Volatility3.faiss`
- `customer_syd_volatility_knowledge_Volatility3.pkl`

**Time required:** 2-3 minutes

## Index Maintenance

### fix_all_faiss_indexes.py

Regenerates all FAISS indexes with proper CPU embeddings. Use this if you encounter "Cannot copy out of meta tensor" errors.

**Usage:**
```bash
python fix_all_faiss_indexes.py
```

**What it does:**
- Loads existing knowledge chunks
- Regenerates embeddings on CPU
- Rebuilds FAISS indexes
- Backs up old indexes (.faiss.backup)
- Fixes Nmap, BloodHound, and Volatility indexes

**When to run:**
- After PyTorch/transformers updates
- If you see meta tensor errors
- If indexes become corrupted

**Time required:** 5-8 minutes for all three indexes

## Fact Extractors

These are not standalone scripts - they're imported by syd.py.

### nmap_fact_extractor.py

Parses Nmap XML into structured facts.

**Key functions:**
- `extract_facts(xml_string)` - Returns dict of services, hosts, vulnerabilities
- `validate_answer(answer, facts)` - Checks for hallucinations

### bloodhound_fact_extractor.py

Parses BloodHound JSON into structured facts.

**Key functions:**
- `extract_facts(json_data)` - Returns dict of users, groups, attack paths
- `facts_to_text(facts)` - Converts to Q&A format for LLM

### volatility_fact_extractor.py

Parses Volatility plugin output into structured facts.

**Key functions:**
- `extract_facts(output_string)` - Returns dict of processes, connections, etc.
- `validate_answer(answer, facts)` - Anti-hallucination checks

## Analyzer Modules

### bloodhound_analyzer.py

BloodHound-specific analysis logic.

**Key functions:**
- `analyze_bloodhound_output(json_string)` - Generates report and vulnerabilities
- `analyze_bloodhound_zip(zip_path)` - Handles ZIP exports

### volatility_analyzer.py

Volatility-specific analysis logic (pattern matching for ransomware, malware, etc.).

**Key functions:**
- Pattern detection for common threats
- Threat categorization and scoring

## Adding New Knowledge

To add new technical documentation:

1. Place markdown files in appropriate directory:
   - `knowledge_bases/bloodhound/` for AD/BloodHound docs
   - `knowledge_bases/volatility/` for memory forensics docs

2. Regenerate the index:
```bash
python chunk_and_embed_bloodhound.py   # for BloodHound
python chunk_and_embed_volatility.py    # for Volatility
```

3. Restart Syd to load new index

**Markdown format guidelines:**
- Use headers for main topics
- Keep sections focused (300-800 words)
- Include code examples where relevant
- Avoid excessive formatting

## Troubleshooting Scripts

If embedding scripts fail:

```bash
# Check dependencies
pip list | grep -E "sentence-transformers|faiss|torch"

# Reinstall if needed
pip install --upgrade sentence-transformers faiss-cpu torch

# Try regenerating
python chunk_and_embed_bloodhound.py
```

If fix_all_faiss_indexes.py fails:

```bash
# Check pickle files exist
ls rag_engine/embeddings/customers/*.pkl

# If missing, regenerate from scratch
python chunk_and_embed_bloodhound.py
python chunk_and_embed_volatility.py
```

## Performance Notes

**Embedding generation:**
- CPU-bound operation
- Uses all available cores
- 100-200 chunks/second typical
- ~5-10 minutes for full knowledge base

**FAISS index size:**
- Bloodhound: ~15-20MB
- Volatility: ~8-12MB
- Nmap: ~18-25MB

**Memory usage during indexing:**
- Peak: 4-6GB
- Can run alongside other applications

## Advanced Usage

### Custom knowledge bases

To use custom knowledge:

1. Create new directory in `knowledge_bases/`
2. Add markdown files
3. Create custom embedding script (copy existing one as template)
4. Modify syd.py to load custom index

### Optimizing retrieval

Edit chunk size in embedding scripts:

```python
# Line 20-25 in chunk_and_embed_*.py
chunk_size = 512  # Increase for longer chunks
overlap = 128     # Increase for more context
```

Larger chunks = more context but slower retrieval
Smaller chunks = faster but may miss connections

## Backup and Recovery

**Backup indexes:**
```bash
cp -r rag_engine/embeddings/ embeddings_backup/
```

**Restore indexes:**
```bash
cp -r embeddings_backup/ rag_engine/embeddings/
```

**Regenerate from scratch:**
```bash
rm rag_engine/embeddings/customers/*
python chunk_and_embed_bloodhound.py
python chunk_and_embed_volatility.py
```
