# Syd

Offline AI assistant for penetration testing. Paste your tool output, ask questions in plain English, get answers grounded in your actual data. No internet connection, no API keys, nothing leaves the machine.

Runs entirely on CPU. Tested on standard laptop hardware.

---

## What it supports

- **Nmap** — XML exports. Ask what's running, what's exposed, what to look at first.
- **BloodHound** — SharpHound JSON. Find paths to DA, Kerberoastable accounts, ACL abuse, unconstrained delegation.
- **Volatility** — Paste plugin output. Ask about suspicious processes, injected code, network connections, persistence mechanisms.
- **YARA** — Scan results. Understand what triggered and why, map matches to attack techniques.
- **NetExec** — Paste output. Identify credential wins, relay opportunities, quick wins.
- **PCAP** — Packet capture analysis. Ask what happened, when, and what to focus on.

---

## Requirements

- Windows 10/11
- 16GB RAM minimum (24GB if you want it to be fast)
- 15GB free disk space (model is ~9.7GB)
- Python 3.10, 3.11 or 3.12 (not 3.13 — llama-cpp-python doesn't have pre-built wheels for it yet)

Tested on: AMD Ryzen AI 9 365, 24GB RAM. Query time 2-5 seconds on that hardware. On 16GB it'll work but close everything else first.

---

## Install

```
git clone https://github.com/Sydsec/syd
cd syd
python setup.py
python syd.py
```

Setup downloads the model (~9.7GB) and the embedding model (~90MB) automatically. No HuggingFace account needed. Takes 20-30 minutes depending on your connection. Once it's done everything runs fully offline.

**If you get errors on the llama-cpp-python install**, run this manually before setup.py:

```
pip install llama-cpp-python==0.3.16 --force-reinstall --no-cache-dir --config-settings="cmake.args=-DGGML_AVX2=OFF;-DGGML_AVX=OFF;-DGGML_F16C=OFF;-DGGML_FMA=OFF"
```

This is a known compatibility issue on some Windows setups. The cmake flags disable AVX2 which causes crashes on certain CPUs.

---

## How it works

Three stages. First, your scan file gets parsed deterministically — no AI, pure regex and structured parsing, so the data extraction is always accurate. Second, it pulls relevant technique documentation from local FAISS indexes. Third, Qwen 2.5 14B generates an answer using only those verified facts.

The answer then gets checked against what was actually in your scan. If the model references an IP, process, or hostname that wasn't in your data, the answer gets blocked and regenerated. That's what keeps it from hallucinating.

---

## Usage

Load a file or paste output into the relevant tab. Click Analyse. Once analysis completes, type questions in the Ask Syd box.

Examples that work well:

*Nmap:* "Which hosts have SMB signing disabled?" / "Show me all services on non-standard ports" / "What's the attack surface on 10.0.0.15?"

*BloodHound:* "What's the shortest path to Domain Admin?" / "Which users are Kerberoastable?" / "Show me all computers with unconstrained delegation"

*Volatility:* "What's the most suspicious process?" / "Are there any injected processes?" / "List all external network connections"

---

## Troubleshooting

**"Model not found"** — setup.py didn't complete. Check the model exists at `rag_engine/models/qwen2.5-14b-instruct-q5_k_m.gguf` and is around 9.7GB. If it's smaller the download was interrupted, delete it and rerun setup.py.

**Out of memory** — Close your browser and anything else eating RAM. 16GB is tight, 24GB is comfortable.

**First launch slow** — Expected. Loading the model takes 10-20 seconds. After that queries are 2-5 seconds.

**FAISS errors** — The indexes ship with the repo. If they're missing or corrupted run `python build_all_databases.py`.

---

## Enterprise

Enterprise adds Metasploit and Sliver C2 analysis on top of everything in this repo.

If you're running red team engagements you know the problem — you can't paste session output into ChatGPT because of NDAs and client data. Enterprise gives you the same AI analysis, fully offline, for your MSF sessions and Sliver beacons. Ask what happened, what to pivot to next, what the credentials mean in context.

Get in touch: **info@sydsec.co.uk** or **https://sydsec.co.uk**

---

## Videos and demos

Tutorials and walkthroughs on YouTube: https://www.youtube.com/@paularmstrong8306

Worth watching before you dive in — shows the actual workflow on real pentest data.

---

## Model

Qwen 2.5 14B Instruct, Q5_K_M quantization. Temperature 0.05-0.1 to keep answers tight. Repeat penalty 2.8-3.2. Context window 8192 tokens.

Embeddings: all-MiniLM-L6-v2. Vector store: FAISS (IndexFlatIP, cosine similarity).

---

Paul Armstrong — https://sydsec.co.uk — YouTube: https://www.youtube.com/@paularmstrong8306
