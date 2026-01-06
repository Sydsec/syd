# Installation Guide

Complete installation instructions for Syd. Budget 30-45 minutes including downloads.

## Prerequisites

Verify Python is installed:

```bash
python --version
```

Should show Python 3.8 or higher. If not, install from python.org first.

## Quick Install (Recommended)

### Step 1: Get Syd

**Option A: Git**
```bash
git clone https://github.com/yourusername/Syd.git
cd Syd
```

**Option B: Download ZIP**
- Download from GitHub
- Extract to a folder
- Open terminal/command prompt in that folder

### Step 2: Run Automated Setup

```bash
python setup.py
```

This single command:
- Installs all dependencies from requirements.txt
- Downloads Qwen 2.5 14B model (9.7GB)
- Verifies everything is working

Press Enter when prompted, then wait 15-30 minutes.

### Step 3: Done!

```bash
python syd.py
```

That's it! See QUICKSTART.md for first test.

---

## Manual Installation (If Automated Setup Fails)

Use this if `python setup.py` doesn't work.

### Step 1: Install Dependencies Manually

```bash
pip install -r requirements.txt
```

**Expected download:** 2-3GB
**Time required:** 5-10 minutes

### Windows-specific notes:

If llama-cpp-python fails to install:

```bash
pip install llama-cpp-python --no-cache-dir
```

If that also fails, you may need Visual Studio Build Tools. Download from Microsoft (search "Visual Studio Build Tools").

### Linux-specific notes:

On Ubuntu/Debian, install build dependencies first:

```bash
sudo apt-get install python3-dev build-essential
pip install -r requirements.txt
```

### macOS-specific notes:

Ensure Xcode command line tools are installed:

```bash
xcode-select --install
pip install -r requirements.txt
```

### Step 2: Download Model Manually

The model is split into 3 parts on HuggingFace.

1. Go to: https://huggingface.co/Qwen/Qwen2.5-14B-Instruct-GGUF
2. Download these 3 files (no account needed):
   - qwen2.5-14b-instruct-q5_k_m-00001-of-00003.gguf (~3.3GB)
   - qwen2.5-14b-instruct-q5_k_m-00002-of-00003.gguf (~3.3GB)
   - qwen2.5-14b-instruct-q5_k_m-00003-of-00003.gguf (~3.1GB)

3. Merge the parts:

**Windows:**
```cmd
copy /b qwen2.5-14b-instruct-q5_k_m-00001-of-00003.gguf + qwen2.5-14b-instruct-q5_k_m-00002-of-00003.gguf + qwen2.5-14b-instruct-q5_k_m-00003-of-00003.gguf rag_engine\models\qwen2.5-14b-instruct-q5_k_m.gguf
```

**Linux/Mac:**
```bash
cat qwen2.5-14b-instruct-q5_k_m-*.gguf > rag_engine/models/qwen2.5-14b-instruct-q5_k_m.gguf
```

4. Verify merged file is 9.7GB:
```bash
ls -lh rag_engine/models/
```

### Step 3: Verify Installation

Run Syd:

```bash
python syd.py
```

The GUI should open with three tabs (Nmap, BloodHound, Volatility).

**First launch takes 10-20 seconds** while models load. You should see:

```
[LOADING] Loading Nmap knowledge...
[OK] Embedding model loaded on cpu
[OK] Loaded XXX Nmap knowledge chunks
[OK] Qwen 2.5 14B loaded
[SUCCESS] Ask Syd ready!
```

If you see errors, check the Troubleshooting section below.

## Verification Test

### Test Nmap Module:

1. Click Nmap tab
2. Paste sample Nmap XML (or use File > Analyze)
3. Wait for fact extraction
4. Ask: "What services were found?"
5. Should get a concise list of services

### Test Volatility Module:

1. Click Volatility tab
2. Paste sample Volatility plugin output
3. Click "Analyze Pasted Results"
4. Ask: "What processes are running?"
5. Should get a list of PIDs and process names

If both work, installation is complete.

## Troubleshooting

### "Model not found" error

Check the model file:

```bash
ls rag_engine/models/qwen2.5-14b-instruct-q5_k_m.gguf
```

If missing:
- Re-download from HuggingFace
- Verify filename matches exactly
- Check file size is 9.7GB

### "FAISS index not found" error

Regenerate indexes:

```bash
python chunk_and_embed_bloodhound.py
python chunk_and_embed_volatility.py
```

Verify they were created:

```bash
ls rag_engine/embeddings/customers/*.faiss
```

Should show three .faiss files.

### "ImportError: No module named llama_cpp"

llama-cpp-python didn't install correctly:

```bash
pip uninstall llama-cpp-python
pip install llama-cpp-python --no-cache-dir --force-reinstall
```

On Windows, you may need Visual Studio Build Tools.

### "Out of memory" error

You need at least 16GB RAM:

- Close other applications
- Check Task Manager / Activity Monitor for memory usage
- If you have less than 16GB, Syd may not work reliably

### Models load but no answers

Check knowledge bases were generated:

```bash
ls rag_engine/embeddings/customers/
```

Should show:
- customer_syd_Nmap.faiss
- customer_syd_Nmap.pkl
- customer_syd_bloodhound_knowledge_BloodHound.faiss
- customer_syd_bloodhound_knowledge_BloodHound.pkl
- customer_syd_volatility_knowledge_Volatility3.faiss
- customer_syd_volatility_knowledge_Volatility3.pkl

If any are missing, rerun the corresponding embedding script.

### GUI is very slow

**First load is always slow** (10-20 seconds). This is normal.

If every query is slow (30+ seconds):
- Check CPU usage (should spike to 100% during queries)
- Close background applications
- Ensure laptop is plugged in (power management throttles CPU on battery)
- Check disk I/O (SSD strongly recommended)

### Permission errors

On Linux/macOS, you may need to make scripts executable:

```bash
chmod +x *.py
```

## Hardware Requirements

**Minimum:**
- 16GB RAM
- 4-core CPU
- 15GB free disk space
- Any OS that runs Python 3.8+

**Recommended:**
- 24GB RAM
- 8-core CPU
- 20GB free disk space
- SSD (not HDD)

**GPU:** Not required. CPU inference is sufficient.

## Post-Installation

Once installed, try analyzing a real scan:

**Nmap example:**
```bash
nmap -sV -sC -p- target.com -oX scan.xml
```

Load scan.xml into Syd and ask questions about the results.

**Volatility example:**
```bash
vol -f memory.dmp windows.pslist > pslist.txt
```

Paste pslist.txt output into Syd Volatility tab.

## Updating

To update Syd:

```bash
git pull
pip install -r requirements.txt --upgrade
```

To update knowledge bases:

```bash
python chunk_and_embed_bloodhound.py
python chunk_and_embed_volatility.py
```

To update the LLM model, download the new .gguf file and replace the old one.

## Uninstallation

To remove Syd:

1. Delete the Syd directory
2. Uninstall Python packages:

```bash
pip uninstall sentence-transformers faiss-cpu llama-cpp-python torch
```

Total disk space reclaimed: approximately 15-20GB.

## Support

If you encounter issues not covered here:

1. Check the main README.md
2. Search existing GitHub issues
3. Open a new issue with environment details and error messages

Typical response time: 1-3 days.
