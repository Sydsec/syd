# Syd - Offline Penetration Testing Assistant

---

## 🎉 **SYD V3 LAUNCHING NEXT WEEK** 🎉

**20% more accurate than V2** - Tested on 119 real-world pentest scenarios:
- ✅ **Nmap:** 9.1/10 accuracy (up from 7.6/10 in V2)
- ✅ **BloodHound:** 10.0/10 accuracy (up from 8.5/10 in V2)
- ✅ **Volatility:** 8.13/10 accuracy (up from 6.8/10 in V2)
- ✅ **YARA:** 9.84/10 accuracy (up from 8.2/10 in V2)
- ✅ **Overall:** 9.27/10 (Grade A) across all 4 tools

**V3 Pro features:**
- 💎 One-click installer (no Python setup required)
- 📧 Email support
- 🎯 Priority updates
- 📊 Professional-grade accuracy

**⭐ Star this repo to get notified when V3 launches + early bird pricing!**

*V2 (below) remains free forever. V3 Pro coming next week.*

---

Syd is an air-gapped penetration testing assistant that analyzes scan outputs using local LLMs and retrieval-augmented generation. It runs entirely on your laptop without requiring internet connectivity or API keys.

## Overview

Syd parses technical scan outputs (Nmap, BloodHound, Volatility) and answers questions in plain English. Instead of manually reviewing hundreds of pages of results, you can ask specific questions and get evidence-based answers grounded in your actual scan data.

**Supported Tools:**
- Nmap (XML exports)
- BloodHound (JSON/ZIP exports)
- Volatility 3 (plugin output)
- YARA (scan results)

**Key Features:**
- Fully offline operation
- No cloud dependencies or API keys
- Fact-extraction architecture prevents hallucinations
- Runs on standard laptop hardware
- Evidence-based answers backed by scan data

## Architecture

Syd uses a three-stage pipeline:

1. **Fact Extraction** - Deterministic parsing of scan files into structured data
2. **Knowledge Retrieval** - RAG-based lookup of relevant technical documentation
3. **Answer Generation** - LLM generates answers using extracted facts and retrieved knowledge

The fact extraction stage uses regex and structured parsing (no LLM). This ensures 100% accurate data extraction. The LLM only generates natural language explanations based on verified facts.

Validation checks every generated answer against extracted facts. If the LLM mentions data not present in your scan (PIDs, IP addresses, hostnames, etc.), the answer is rejected.

## Requirements

**Hardware:**
- 16GB RAM minimum (24GB recommended)
- 10GB free disk space
- Multi-core CPU

**Software:**
- Python 3.8 or higher
- pip

**Tested Configuration:**
- AMD Ryzen AI 9 365 (10 cores)
- 24GB RAM
- Windows 11
- Query response time: 2-5 seconds

## Installation

### From Installer (Customers)

Syd is delivered as a single installer that includes everything — the AI model, databases, and all dependencies. No Python or internet connection required after installation.

1. Download `Syd_Installer.exe`
2. Run the installer — it will set up everything automatically
3. Launch Syd from the desktop shortcut or Start Menu
4. First launch takes 10-20 seconds (loading AI model)

### From Source (Developers)

If you are running from the repository directly:

1. Ensure Python 3.8+ and pip are installed
2. Run `python setup.py` — this installs dependencies, downloads the embedding model (~90MB), and downloads the Qwen 2.5 14B model (~9.7GB)
3. Once setup completes, run `python syd.py`

See INSTALL.md for troubleshooting.

## Usage

### Nmap Analysis

1. Load Nmap XML file or paste XML output
2. Wait for fact extraction (typically 5-15 seconds)
3. Ask questions:
   - "What services are running on high ports?"
   - "Which hosts have SMB signing disabled?"
   - "Show me all web servers"
   - "What vulnerabilities were found?"

### BloodHound Analysis

1. Load BloodHound JSON export (from SharpHound)
2. Ask questions:
   - "What is the shortest path to Domain Admin?"
   - "Which accounts are Kerberoastable?"
   - "Show me unconstrained delegation issues"
   - "What ACL abuse paths exist?"

### Volatility Analysis

1. Paste Volatility 3 plugin output
2. Ask questions:
   - "What is the most suspicious process?"
   - "List all network connections"
   - "Is there evidence of process injection?"
   - "What processes have PAGE_EXECUTE_READWRITE regions?"

## Accuracy

Tested on real pentest data:

- **Nmap**: 96.7% (29/30 test questions)
- **Volatility**: 90% (9/10 test questions)
- **BloodHound**: 85-90% (refinement in progress)

The validation layer prevents hallucinations. Answers that reference non-existent data are blocked.

## Project Structure

```
Syd_V3/
├── syd.py                          # Main application
├── nmap_fact_extractor.py          # Nmap parser
├── bloodhound_fact_extractor.py    # BloodHound parser
├── volatility_fact_extractor.py    # Volatility parser
├── bloodhound_analyzer.py          # BloodHound analysis logic
├── volatility_analyzer.py          # Volatility analysis logic
├── knowledge_bases/                # Technical documentation
│   ├── bloodhound/
│   └── volatility/
├── rag_engine/
│   ├── models/                     # LLM models (GGUF format)
│   └── embeddings/                 # FAISS indexes
└── chunk_and_embed_*.py            # Knowledge base indexing scripts
```

## Technical Details

**LLM:** Qwen 2.5 14B (Q5_K_M quantization)
**Embeddings:** all-MiniLM-L6-v2 (sentence-transformers)
**Vector DB:** FAISS (CPU-optimized)
**GUI:** tkinter (cross-platform)

Temperature: 0.05-0.1 (low to reduce hallucinations)
Repeat penalty: 2.8-3.2 (prevent looping)
Context window: 4096-8192 tokens

## Known Limitations

- BloodHound JSON must be standard SharpHound format
- Nmap XML must be complete (not truncated)
- Large scans (1000+ hosts) may take 30-60 seconds to parse
- Volatility network direction analysis: 85% accuracy (being refined)

Designed for typical pentest scenarios (10-500 hosts). Enterprise-scale scans may require chunking.

## Troubleshooting

**Model not found:**
- Verify model file exists in `rag_engine/models/`
- Check filename matches exactly: `qwen2.5-14b-instruct-q5_k_m.gguf`

**FAISS index not found:**
- Run `python chunk_and_embed_*.py` scripts
- Check for .faiss and .pkl files in `rag_engine/embeddings/customers/`

**Out of memory:**
- Close other applications
- Minimum 16GB RAM required
- Only use Nmap module if memory constrained

**Slow performance:**
- First load takes 10-20 seconds (model initialization)
- Subsequent queries: 2-5 seconds
- Check CPU usage - model is CPU-bound
- Ensure laptop is plugged in (power management affects performance)

## Support

**Contact:** info@sydsec.co.uk

**Resources:**
- YouTube: https://www.youtube.com/@paularmstrong8306 (tutorials and demos)
- Website: https://sydsec.co.uk

**Updates:** Database and model updates sold separately. Contact for pricing.

## License

MIT License - See LICENSE file

## Acknowledgments

Built using:
- llama.cpp (efficient CPU inference)
- FAISS (fast vector search)
- sentence-transformers (embeddings)
- Qwen 2.5 (instruction-following LLM)

Developed and tested on real penetration testing data.

---

**Author:** Paul Armstrong
**Website:** https://sydsec.co.uk
**YouTube:** https://www.youtube.com/@paularmstrong8306
