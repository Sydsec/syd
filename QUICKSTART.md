# Quick Start - 3 Steps

Get Syd running in 30 minutes (most of it is downloading).

## Requirements

- Python 3.8 or higher
- 16GB RAM minimum
- 15GB free disk space
- Internet connection (for initial setup only)

Check Python version:
```bash
python --version
```

If you don't have Python, install from python.org first.

## Step 1: Download Syd

**Option A: Git (if you have it)**
```bash
git clone https://github.com/yourusername/Syd.git
cd Syd
```

**Option B: Download ZIP**
1. Click "Code" → "Download ZIP" on GitHub
2. Extract the ZIP file
3. Open terminal/command prompt in the extracted folder

## Step 2: Run Setup (Does Everything)

```bash
python setup.py
```

This script will:
- Install all dependencies automatically (5-10 minutes)
- Download the Qwen 2.5 14B model (10-20 minutes, 9.7GB)
- Verify everything is working

**Just press Enter when it asks, then wait.**

You'll see progress like:
```
Installing packages from requirements.txt...
[Progress bars...]
Downloading model parts...
[1/3] Downloading qwen2.5-14b-instruct-q5_k_m-00001-of-00003.gguf...
[2/3] Downloading qwen2.5-14b-instruct-q5_k_m-00002-of-00003.gguf...
[3/3] Downloading qwen2.5-14b-instruct-q5_k_m-00003-of-00003.gguf...
Merging model parts...
SETUP COMPLETE!
```

## Step 3: Run Syd

```bash
python syd.py
```

The GUI will open. First launch takes 10-20 seconds to load models.

## First Test

1. Click **Nmap** tab
2. Paste this sample (or use your own Nmap XML):

```xml
<?xml version="1.0"?>
<nmaprun>
<host>
<address addr="192.168.1.100"/>
<ports>
<port protocol="tcp" portid="22">
<state state="open"/>
<service name="ssh" product="OpenSSH" version="8.2"/>
</port>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http" product="Apache" version="2.4"/>
</port>
</ports>
</host>
</nmaprun>
```

3. Click **Analyze Results**
4. Ask: "What services are running?"

You should get a response listing SSH and HTTP.

## Troubleshooting

**"python command not found"**
- Try `python3` instead of `python`
- Or install Python from python.org

**Setup script fails**
- Check internet connection
- Try manual install: `pip install -r requirements.txt`
- See INSTALL.md for detailed troubleshooting

**Out of memory**
- Close other applications
- You need 16GB RAM minimum

**Model download is slow**
- Normal - it's 9.7GB
- Grab coffee, takes 10-30 minutes depending on connection
- Download continues if interrupted

## Next Steps

- Try analyzing your own Nmap/BloodHound/Volatility scans
- Read README.md for more usage examples
- Check INSTALL.md if you have issues

## That's It!

Setup does everything automatically:
- ✓ Installs all dependencies
- ✓ Downloads model
- ✓ Verifies installation
- ✓ FAISS indexes already included

You just run `python setup.py` and wait.

No HuggingFace account needed. No manual downloads. No complex configuration.

---

## Need Help?

**Air-gapped environment?** Pre-configured USB installations available for a small fee.

Contact: info@sydsec.co.uk

**Video tutorials:** https://www.youtube.com/@paularmstrong8306

**Documentation:** See README.md and INSTALL.md for detailed guides
