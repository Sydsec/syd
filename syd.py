import os
import sys

# =============================================================================
# FORCE CPU MODE (GPU freezing issues)
# =============================================================================
os.environ["CUDA_VISIBLE_DEVICES"] = ""  # Disable GPU - use CPU only for stability

# =============================================================================
# PYINSTALLER DLL PATH FIX (must run before llama_cpp import)
# =============================================================================
if getattr(sys, 'frozen', False):
    # Running as PyInstaller bundle - fix DLL loading
    # PyInstaller extracts to sys._MEIPASS temp directory
    import_base = sys._MEIPASS
    llama_lib_path = os.path.join(import_base, 'llama_cpp', 'lib')

    if os.path.exists(llama_lib_path):
        # Add DLL directory for Windows DLL search
        if hasattr(os, 'add_dll_directory'):
            os.add_dll_directory(llama_lib_path)
        # Also add to PATH for older Python versions
        os.environ['PATH'] = llama_lib_path + os.pathsep + os.environ.get('PATH', '')

# =============================================================================
# LLAMA-CPP-PYTHON INITIALIZATION
# =============================================================================
from llama_cpp import Llama
import llama_cpp.llama_cpp as _llama_cpp_lib

# =============================================================================
# PYTORCH ENVIRONMENT (for sentence-transformers embedding model)
# =============================================================================
# These settings are for the embedding model only - NOT for llama-cpp-python
os.environ["ACCELERATE_USE_CPU"] = "1"            # Force accelerate to use CPU
os.environ["TRANSFORMERS_NO_ADVISORY_WARNINGS"] = "1"  # Suppress warnings
os.environ["DISABLE_TELEMETRY"] = "1"             # Disable HuggingFace telemetry
os.environ["TOKENIZERS_PARALLELISM"] = "false"    # Prevent tokenizer warnings
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"    # Disable symlink warnings
os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"   # Fallback for Mac M1/M2

# AIRGAPPED SYSTEM - Force offline mode (use cached models only, no internet)
os.environ["HF_HUB_OFFLINE"] = "1"                # HuggingFace offline mode
os.environ["TRANSFORMERS_OFFLINE"] = "1"          # Transformers offline mode

# When running as EXE, point HuggingFace to the bundled model cache
# The hf_home folder sits next to Syd.exe in the distribution folder
if getattr(sys, 'frozen', False):
    _exe_dir = os.path.dirname(sys.executable)
    _hf_home = os.path.join(_exe_dir, "hf_home")
    os.environ["HF_HOME"] = _hf_home
    os.environ["SENTENCE_TRANSFORMERS_HOME"] = os.path.join(_hf_home, "sentence_transformers")

# Now import torch (after llama-cpp has claimed CUDA)
import torch
# Note: Do NOT call torch.set_default_device() - causes meta tensor issues

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import threading
import re
import json
import ipaddress
from datetime import datetime
from pathlib import Path
import hashlib
import hmac
import platform
import base64
import xml.etree.ElementTree as ET
import pickle
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
# Note: Llama already imported at line 10 (before PyTorch)

# ---------------------------------------------------------------------------
# BASE PATH — resolves correctly whether running as `python syd.py` or as a
# PyInstaller .exe.  All file paths in the app should be relative to BASE_PATH.
# ---------------------------------------------------------------------------
if getattr(sys, 'frozen', False):
    # Running as PyInstaller bundle — files live in _internal/ next to the exe
    BASE_PATH = Path(sys._MEIPASS)
else:
    # Running from source — files live next to syd.py
    BASE_PATH = Path(__file__).resolve().parent

# =============================================================================
# LICENSING — Option B: offline activation bound to hardware fingerprint.
# The license key is validated locally via HMAC.  The activation record is
# stored in %LOCALAPPDATA%\Syd\ and is tied to this machine's fingerprint.
# =============================================================================
_LICENSE_SECRET   = b"sydsec_v3_license_secret_2026_k7"
_OBFUSCATION_KEY  = b"sydsec_v3_obfuscation_key_2026!"
_cached_fingerprint = None

def _get_hardware_fingerprint():
    """Unique fingerprint: computer name + CPU + C: volume serial."""
    global _cached_fingerprint
    if _cached_fingerprint is not None:
        return _cached_fingerprint
    parts = [platform.node() or "unknown", platform.processor() or "unknown"]
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").VolumeSerialNumber"],
            capture_output=True, text=True, timeout=5
        )
        parts.append(result.stdout.strip() or "unknown")
    except Exception:
        parts.append("unknown")
    _cached_fingerprint = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
    return _cached_fingerprint

def _validate_license_key(key):
    """Validate key format and HMAC.  Returns (True, customer_id) or (False, error_msg)."""
    key = key.strip().upper().replace("-", "").replace(" ", "")
    if not key.startswith("SYD3") or len(key) != 20:
        return False, "Invalid key format. Expected: SYD3-XXXX-XXXX-XXXX-XXXX"
    body = key[4:]                                  # 16 hex chars
    try:
        int(body, 16)
    except ValueError:
        return False, "Key contains invalid characters"
    customer_id, check_code = body[:8], body[8:]
    expected = hmac.new(_LICENSE_SECRET, customer_id.encode(), hashlib.sha256).hexdigest()[:8].upper()
    if check_code != expected:
        return False, "License key is not valid"
    return True, customer_id

def _get_activation_path():
    app_data = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
    syd_dir  = app_data / "Syd"
    syd_dir.mkdir(exist_ok=True)
    return syd_dir / "activation.dat"

def _obfuscate(data_bytes):
    key = _OBFUSCATION_KEY
    return base64.b64encode(bytes([b ^ key[i % len(key)] for i, b in enumerate(data_bytes)])).decode()

def _deobfuscate(data_str):
    raw = base64.b64decode(data_str.encode())
    key = _OBFUSCATION_KEY
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(raw)])

def check_activation():
    """Returns (is_activated: bool, license_key_or_None)."""
    path = _get_activation_path()
    if not path.exists():
        return False, None
    try:
        record = json.loads(_deobfuscate(path.read_text().strip()).decode())
        if record.get("fingerprint") != _get_hardware_fingerprint():
            return False, None
        valid, _ = _validate_license_key(record.get("license_key", ""))
        return valid, record.get("license_key") if valid else None
    except Exception:
        return False, None

def activate_license(license_key):
    """Write activation record for this machine.  Returns (success, message)."""
    valid, result = _validate_license_key(license_key)
    if not valid:
        return False, result
    record = {
        "license_key": license_key.strip().upper(),
        "customer_id": result,
        "fingerprint": _get_hardware_fingerprint(),
        "activated_at": datetime.now().isoformat(),
    }
    _get_activation_path().write_text(_obfuscate(json.dumps(record).encode()))
    return True, "Activation successful"

# Global lock for thread-safe model loading
_embedding_model_lock = threading.Lock()
_cached_embedding_model = None

def load_embedding_model(model_name="all-MiniLM-L6-v2", max_retries=3):
    """
    Load SentenceTransformer with PERMANENT fix for PyTorch 2.6.0 meta tensor issue.

    This function implements:
    1. Thread-safe loading with global lock
    2. Model caching to avoid repeated loads
    3. Retry logic with exponential backoff
    4. Explicit CPU device without using set_default_device()

    The key insight: DO NOT use torch.set_default_device() as it interferes
    with how transformers/safetensors loads model weights in PyTorch 2.6.0.

    Works with: PyTorch 2.6.0+, Transformers 4.57+, SentenceTransformers 5.2+

    Args:
        model_name: Name of the sentence-transformers model
        max_retries: Number of retry attempts on failure

    Returns:
        Loaded SentenceTransformer model on CPU
    """
    global _cached_embedding_model

    # Return cached model if available (thread-safe check)
    if _cached_embedding_model is not None:
        return _cached_embedding_model

    with _embedding_model_lock:
        # Double-check after acquiring lock
        if _cached_embedding_model is not None:
            return _cached_embedding_model

        import warnings
        import time

        last_error = None

        for attempt in range(max_retries):
            try:
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore")

                    # CRITICAL: Load with explicit device='cpu' and NO set_default_device
                    # The model_kwargs ensure the underlying transformer also uses CPU
                    model = SentenceTransformer(
                        model_name,
                        device='cpu',
                        trust_remote_code=False,
                        model_kwargs={
                            'low_cpu_mem_usage': False,  # Disable lazy loading that causes meta tensors
                        }
                    )

                model.eval()

                # Verify the model is actually on CPU
                try:
                    device = next(model.parameters()).device
                    if device.type != 'cpu':
                        raise RuntimeError(f"Model loaded on wrong device: {device}")
                except StopIteration:
                    pass  # Model has no parameters (unlikely but handle gracefully)

                # Test encoding to ensure model works
                test_embedding = model.encode("test", show_progress_bar=False)
                if test_embedding is None or len(test_embedding) == 0:
                    raise RuntimeError("Model encoding test failed")

                print(f"[OK] SentenceTransformer loaded successfully (PyTorch {torch.__version__})")
                _cached_embedding_model = model
                return model

            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff: 1, 2, 4 seconds
                    print(f"[RETRY] Model loading failed (attempt {attempt + 1}/{max_retries}): {e}")
                    print(f"[RETRY] Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)

                    # Clear any cached state that might cause issues
                    import gc
                    gc.collect()
                    if hasattr(torch, 'cuda'):
                        try:
                            torch.cuda.empty_cache()
                        except:
                            pass

        # All retries failed
        print(f"[ERROR] SentenceTransformer loading failed after {max_retries} attempts: {last_error}")
        import traceback
        traceback.print_exc()
        raise RuntimeError(
            f"Cannot load embedding model after {max_retries} attempts.\n"
            f"Ensure the 'hf_home' folder is next to Syd.exe with the sentence-transformers model cached inside.\n"
            f"Ask Syd will be unavailable but analysis still works."
        )

# ========== SHARED LLM (Single Instance for All Tools) ==========
_llm_lock = threading.Lock()
_cached_llm = None

def get_shared_llm():
    """
    Load LLM once and share across all tools.
    This prevents loading 4 separate 10GB models (40GB total) into 8GB VRAM.
    """
    global _cached_llm

    with _llm_lock:
        if _cached_llm is not None:
            return _cached_llm

        from pathlib import Path
        # Llama is already imported at top of file (before PyTorch)

        model_path = BASE_PATH / "rag_engine" / "models" / "qwen2.5-14b-instruct-q5_k_m.gguf"
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")

        # Auto-detect CPU threads (use physical cores, not hyperthreads)
        import multiprocessing
        cpu_threads = max(4, multiprocessing.cpu_count() // 2)

        print(f"[LOADING] Initializing shared LLM (Qwen 2.5 14B) on CPU with {cpu_threads} threads...")
        _cached_llm = Llama(
            model_path=str(model_path),
            n_ctx=8192,  # Context window (increased for large BloodHound datasets)
            n_batch=512,  # CPU batch size
            n_threads=cpu_threads,  # Auto-detect CPU cores
            n_gpu_layers=0,  # CPU only - no GPU layers
            chat_format="chatml",
            verbose=False
        )
        print("[OK] Shared LLM ready on CPU (stable mode)")
        return _cached_llm

# Context window budget: n_ctx=8192
_LLM_N_CTX = 8192

def truncate_for_context_window(llm, facts_text, context_text, max_tokens, static_prompt_chars=2000):
    """
    Truncate facts and context text to fit within the LLM context window.
    Prevents 'Requested tokens exceed context window' errors.

    Prioritizes facts (70% of variable budget) over knowledge base context (30%).
    """
    # Budget = n_ctx - max_tokens - overhead (chatml formatting, BOS/EOS, user message)
    overhead_tokens = 400  # chatml tags, user message, safety margin
    token_budget = _LLM_N_CTX - max_tokens - overhead_tokens

    # Estimate tokens for the static part of the prompt (instructions/rules)
    static_tokens = static_prompt_chars // 3  # ~3 chars per token for formatted text
    variable_budget = token_budget - static_tokens

    if variable_budget <= 200:
        # Very tight - give minimal facts and no context
        return facts_text[:600], ""

    # Estimate tokens for facts and context
    try:
        facts_tokens = len(llm.tokenize(facts_text.encode('utf-8', errors='replace')))
        context_tokens = len(llm.tokenize(context_text.encode('utf-8', errors='replace')))
    except Exception:
        # Fallback: ~3 chars per token
        facts_tokens = len(facts_text) // 3
        context_tokens = len(context_text) // 3

    total_variable = facts_tokens + context_tokens

    if total_variable <= variable_budget:
        return facts_text, context_text  # Fits fine, no truncation needed

    # Need to truncate - prioritize facts (70%) over context (30%)
    facts_budget = int(variable_budget * 0.75)
    context_budget = variable_budget - facts_budget

    # Truncate context first (less important)
    if context_tokens > context_budget and context_tokens > 0:
        ratio = context_budget / context_tokens
        max_chars = max(200, int(len(context_text) * ratio * 0.9))
        context_text = context_text[:max_chars] + "\n[...knowledge base truncated to fit context window...]"

    # Truncate facts if still needed
    if facts_tokens > facts_budget and facts_tokens > 0:
        ratio = facts_budget / facts_tokens
        max_chars = max(400, int(len(facts_text) * ratio * 0.9))
        facts_text = facts_text[:max_chars] + "\n[...facts truncated to fit context window - ask shorter questions for remaining details...]"

    return facts_text, context_text

import re as _re

def tag_unverified_cves(answer, verified_cves=None):
    """Tag CVE references in LLM answers that aren't from the scan's CVE results.

    Args:
        answer: The LLM-generated answer text
        verified_cves: Set of CVE IDs confirmed by the CVE query engine (e.g. {'CVE-2019-10149'})
                       If None, ALL CVEs in the answer are tagged as unverified.
    """
    if verified_cves is None:
        verified_cves = set()
    # Normalize to uppercase for comparison
    verified_upper = {c.upper() for c in verified_cves}

    def _replace_cve(match):
        cve_id = match.group(0)
        if cve_id.upper() in verified_upper:
            return cve_id  # Known from scan — leave alone
        return f"{cve_id} [UNVERIFIED]"

    return _re.sub(r'CVE-\d{4}-\d{4,7}', _replace_cve, answer)

APP_NAME = "Sydsec"

# ---------------------------- Catalogs ----------------------------
RED_TOOLS = [
    "Nmap","Metasploit","Sliver","BloodHound","NXC/NetExec","Impacket",
    "Responder","Hashcat","Feroxbuster","Curl/Ncat","Payload Builder"
]
BLUE_TOOLS = [
    "Zeek","Volatility3","YARA","PCAP Analysis","Chainsaw","Suricata","Sysmon Helper",
    "TShark","Raccine","Autopsy/SleuthKit"
]
UTILS = [
    "File Triage","Wordlists Manager","Credential Safe","Artifact Viewer","Report Builder","Settings"
]

# ---------------------------- Styling ----------------------------
BG_DARK = "#111316"
BG = "#171a1f"
PANEL = "#1e232b"
INK = "#e6e6e6"
INK_SOFT = "#b8c0cc"
ACCENT = "#3b82f6"
ACCENT_SOFT = "#2d5fb8"

def init_style(root):
    root.configure(bg=BG)
    s = ttk.Style(root)
    try: s.theme_use("clam")
    except: pass
    s.configure(".", background=PANEL, foreground=INK)
    s.configure("TFrame", background=PANEL)
    s.configure("TLabel", background=PANEL, foreground=INK)
    s.configure("Header.TLabel", font=("Segoe UI", 11, "bold"))
    s.configure("TNotebook", background=BG, borderwidth=0)
    s.configure("TNotebook.Tab", background=PANEL, foreground=INK, padding=(16,8))
    s.map("TNotebook.Tab",
          background=[("selected", ACCENT)],
          foreground=[("selected", "#ffffff"), ("active", INK)])

    # Fix button hover - keep text visible
    s.configure("TButton", background=PANEL, foreground=INK, borderwidth=1)
    s.map("TButton",
          background=[("active", ACCENT), ("pressed", ACCENT)],
          foreground=[("active", "#ffffff"), ("pressed", "#ffffff")])

    # Configure Treeview for dark theme with visible text
    s.configure("Treeview", background=BG_DARK, foreground=INK, fieldbackground=BG_DARK)
    s.configure("Treeview.Heading", background=PANEL, foreground=INK, font=("Segoe UI", 9, "bold"))
    s.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "#ffffff")])

    # Fix combobox selected text - keep visible
    s.configure("TCombobox", fieldbackground=BG_DARK, background=PANEL, foreground=INK,
                selectbackground=ACCENT, selectforeground="#ffffff")
    s.map("TCombobox",
          fieldbackground=[("readonly", BG_DARK)],
          selectbackground=[("readonly", ACCENT)],
          selectforeground=[("readonly", "#ffffff")])

    # Configure Entry widgets for dark theme with visible text
    s.configure("TEntry", fieldbackground=BG_DARK, background=BG_DARK, foreground=INK,
                insertbackground=INK, selectbackground=ACCENT, selectforeground="#ffffff")
    s.map("TEntry",
          fieldbackground=[("focus", BG_DARK), ("!focus", BG_DARK)],
          foreground=[("focus", INK), ("!focus", INK)])

class NmapPage(ttk.Frame):
    """Professional Nmap scanner interface with Ask Syd panel."""

    # Scan profiles mapping
    SCAN_PROFILES = {
        "Quick Scan": "-sV --version-light",
        "Default Scan": "-sV -sC",
        "Intense Scan": "-sV -sC -A",
        "Stealth Scan": "-sS -sV",
        "UDP Scan": "-sU"
    }

    def __init__(self, parent):
        super().__init__(parent)

        # Initialize state variables
        self.scan_process = None
        self.scan_thread = None
        self._syd_data_dir = Path(os.environ.get('LOCALAPPDATA', '.')) / "Syd"
        self._syd_data_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self._syd_data_dir / "nmap_config.json"
        self._default_config_file = BASE_PATH / "nmap_config.json"
        self.output_dir = self._syd_data_dir / "output" / "nmap"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.current_xml_file = None
        self.current_output_file = None

        # Simple RAG components - ONLY for Nmap
        self.embed_model = None
        self.llm = None
        self.faiss_index = None
        self.chunks = None
        self.rag_ready = False

        # Load configuration
        self.config = self.load_config()

        # Main split: LEFT (60%) + RIGHT (40%)
        left_frame = ttk.Frame(self)
        left_frame.pack(side="left", fill="both", expand=True, padx=(5,2), pady=5)

        right_frame = ttk.Frame(self)
        right_frame.pack(side="right", fill="both", expand=False, padx=(2,5), pady=5)
        right_frame.configure(width=500)

        # ========== LEFT COLUMN ==========
        # Group box: Nmap Network Scanner
        scanner_group = ttk.LabelFrame(left_frame, text="Nmap Network Scanner", padding=10)
        scanner_group.pack(fill="x", padx=5, pady=5)

        # Form fields
        form = ttk.Frame(scanner_group)
        form.pack(fill="x")

        # Target
        ttk.Label(form, text="Target:").grid(row=0, column=0, sticky="w", padx=5, pady=3)
        self.txtTarget = tk.Entry(form, bg=BG_DARK, fg=INK, insertbackground=INK)
        self.txtTarget.grid(row=0, column=1, sticky="ew", padx=5, pady=3)

        # Scan Profile
        ttk.Label(form, text="Scan Profile:").grid(row=1, column=0, sticky="w", padx=5, pady=3)
        self.cmbProfile = ttk.Combobox(form, values=list(self.SCAN_PROFILES.keys()), state="readonly")
        self.cmbProfile.current(1)  # Default Scan
        self.cmbProfile.grid(row=1, column=1, sticky="ew", padx=5, pady=3)

        # Ports
        ttk.Label(form, text="Ports:").grid(row=2, column=0, sticky="w", padx=5, pady=3)
        self.txtPorts = tk.Entry(form, bg=BG_DARK, fg=INK, insertbackground=INK)
        self.txtPorts.insert(0, "1-1000")
        self.txtPorts.grid(row=2, column=1, sticky="ew", padx=5, pady=3)

        # Timing
        ttk.Label(form, text="Timing:").grid(row=3, column=0, sticky="w", padx=5, pady=3)
        self.cmbTiming = ttk.Combobox(form, values=["T0 (Paranoid)", "T1 (Sneaky)", "T2 (Polite)", "T3 (Normal)", "T4 (Aggressive)", "T5 (Insane)"])
        self.cmbTiming.current(3)
        self.cmbTiming.grid(row=3, column=1, sticky="ew", padx=5, pady=3)

        form.columnconfigure(1, weight=1)

        # Buttons row
        btn_row = ttk.Frame(scanner_group)
        btn_row.pack(fill="x", pady=(10,0))
        self.btnRunScan = ttk.Button(btn_row, text="Run Scan", command=self.on_run_scan)
        self.btnRunScan.pack(side="left", padx=5)
        self.btnStop = ttk.Button(btn_row, text="Stop", command=self.on_stop, state="disabled")
        self.btnStop.pack(side="left", padx=5)
        self.btnExport = ttk.Button(btn_row, text="Export", command=self.on_export)
        self.btnExport.pack(side="left", padx=5)

        # Preset Commands Section
        preset_group = ttk.LabelFrame(left_frame, text="Popular Scan Presets", padding=10)
        preset_group.pack(fill="x", padx=5, pady=5)

        # Create preset buttons in a grid
        presets_container = ttk.Frame(preset_group)
        presets_container.pack(fill="x")

        # Define popular commands (name, command template)
        self.preset_commands = {
            "Quick Scan": "nmap -T4 -F {target}",
            "Intense Scan": "nmap -T4 -A -v {target}",
            "Stealth SYN": "nmap -sS -T2 {target}",
            "Service Version": "nmap -sV {target}",
            "OS Detection": "nmap -O {target}",
            "All Ports": "nmap -p- {target}",
            "Top 100 Ports": "nmap --top-ports 100 {target}",
            "UDP Scan": "nmap -sU -T4 {target}",
            "Script Scan": "nmap -sC {target}",
            "Vuln Scan": "nmap --script vuln {target}",
            "Aggressive": "nmap -T4 -A -v -Pn {target}",
            "Ping Sweep": "nmap -sn {target}"
        }

        # Create buttons in rows of 4
        row = 0
        col = 0
        for name, cmd_template in self.preset_commands.items():
            btn = ttk.Button(
                presets_container,
                text=name,
                command=lambda c=cmd_template: self.load_preset_command(c),
                width=15
            )
            btn.grid(row=row, column=col, padx=3, pady=3, sticky="ew")
            col += 1
            if col >= 4:
                col = 0
                row += 1

        # Configure grid columns to expand equally
        for i in range(4):
            presets_container.columnconfigure(i, weight=1)

        # Results area with tabs
        results_frame = ttk.Frame(left_frame)
        results_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.tabsResults = ttk.Notebook(results_frame)
        self.tabsResults.pack(fill="both", expand=True)

        # Raw Output tab
        raw_tab = ttk.Frame(self.tabsResults)
        self.txtRawOutput = tk.Text(raw_tab, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word")
        scroll_raw = ttk.Scrollbar(raw_tab, command=self.txtRawOutput.yview)
        self.txtRawOutput.configure(yscrollcommand=scroll_raw.set)
        self.txtRawOutput.pack(side="left", fill="both", expand=True)
        scroll_raw.pack(side="right", fill="y")
        self.tabsResults.add(raw_tab, text="Raw Output")

        # Services Found tab
        services_tab = ttk.Frame(self.tabsResults)
        self.txtServices = tk.Text(services_tab, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word")
        scroll_services = ttk.Scrollbar(services_tab, command=self.txtServices.yview)
        self.txtServices.configure(yscrollcommand=scroll_services.set)
        self.txtServices.pack(side="left", fill="both", expand=True)
        scroll_services.pack(side="right", fill="y")
        self.tabsResults.add(services_tab, text="Services Found")

        # Next Steps tab
        nextsteps_tab = ttk.Frame(self.tabsResults)
        self.txtNextSteps = tk.Text(nextsteps_tab, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word")
        scroll_nextsteps = ttk.Scrollbar(nextsteps_tab, command=self.txtNextSteps.yview)
        self.txtNextSteps.configure(yscrollcommand=scroll_nextsteps.set)
        self.txtNextSteps.pack(side="left", fill="both", expand=True)
        scroll_nextsteps.pack(side="right", fill="y")
        self.tabsResults.add(nextsteps_tab, text="Next Steps")

        # Paste Results tab
        paste_tab = ttk.Frame(self.tabsResults)

        # Text area for pasting
        paste_text_frame = ttk.Frame(paste_tab)
        paste_text_frame.pack(fill="both", expand=True)

        self.txtPasteResults = tk.Text(paste_text_frame, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word")
        scroll_paste = ttk.Scrollbar(paste_text_frame, command=self.txtPasteResults.yview)
        self.txtPasteResults.configure(yscrollcommand=scroll_paste.set)
        self.txtPasteResults.pack(side="left", fill="both", expand=True)
        scroll_paste.pack(side="right", fill="y")
        self._create_context_menu(self.txtPasteResults)

        # Analyze button at bottom
        paste_btn_frame = ttk.Frame(paste_tab)
        paste_btn_frame.pack(fill="x", padx=5, pady=5)
        self.btnAnalyzePaste = ttk.Button(paste_btn_frame, text="Analyze Results", command=self.on_analyze_paste)
        self.btnAnalyzePaste.pack(side="right")

        self.tabsResults.add(paste_tab, text="Paste Results")

        # Bottom command row
        cmd_frame = ttk.Frame(left_frame)
        cmd_frame.pack(fill="x", padx=5, pady=5)

        ttk.Label(cmd_frame, text="Command:").pack(side="left", padx=5)
        self.txtCommand = tk.Entry(cmd_frame, bg=BG_DARK, fg=INK, insertbackground=INK)
        self.txtCommand.pack(side="left", fill="x", expand=True, padx=5)
        self._create_entry_context_menu(self.txtCommand)
        self.btnExecute = ttk.Button(cmd_frame, text="Execute", command=self.on_execute)
        self.btnExecute.pack(side="right", padx=5)

        # Bottom status
        self.lblStatus = ttk.Label(left_frame, text="Nmap ready", foreground=INK_SOFT)
        self.lblStatus.pack(side="left", padx=10, pady=5)

        # ========== RIGHT COLUMN (Ask Syd Panel) ==========
        # Header bar
        header = ttk.Frame(right_frame)
        header.pack(fill="x", padx=5, pady=5)

        title_row = ttk.Frame(header)
        title_row.pack(fill="x")
        ttk.Label(title_row, text="Ask Syd - Nmap Expert", style="Header.TLabel").pack(side="left")
        badge = ttk.Label(title_row, text="Fresh Context", background=ACCENT, foreground="#fff", padding=(5,2))
        badge.pack(side="left", padx=10)

        controls_row = ttk.Frame(header)
        controls_row.pack(fill="x", pady=(5,0))
        ttk.Label(controls_row, text="Tool:").pack(side="left", padx=5)
        self.cmbAskSydTool = ttk.Combobox(controls_row, values=["Nmap"], state="readonly", width=12)
        self.cmbAskSydTool.current(0)
        self.cmbAskSydTool.pack(side="left", padx=5)

        self.btnSetPath = ttk.Button(controls_row, text="Set Path", command=self.on_set_path)
        self.btnSetPath.pack(side="right", padx=2)
        self.btnTestTool = ttk.Button(controls_row, text="Test Tool", command=self.on_test_tool)
        self.btnTestTool.pack(side="right", padx=2)

        source_row = ttk.Frame(header)
        source_row.pack(fill="x", pady=(5,0))
        ttk.Label(source_row, text="Source:").pack(side="left", padx=5)
        self.varSource = tk.StringVar(value="Syd")
        ttk.Radiobutton(source_row, text="Syd", variable=self.varSource, value="Syd").pack(side="left", padx=5)
        ttk.Radiobutton(source_row, text="Customer", variable=self.varSource, value="Customer").pack(side="left", padx=5)

        # Main chat region
        chat_frame = ttk.Frame(right_frame)
        chat_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.txtAskSydMain = tk.Text(chat_frame, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word", height=20)
        scroll_chat = ttk.Scrollbar(chat_frame, command=self.txtAskSydMain.yview)
        self.txtAskSydMain.configure(yscrollcommand=scroll_chat.set)
        self.txtAskSydMain.pack(side="left", fill="both", expand=True)
        scroll_chat.pack(side="right", fill="y")
        self._create_context_menu(self.txtAskSydMain)

        # Lower split panel (logs/secondary)
        log_frame = ttk.Frame(right_frame)
        log_frame.pack(fill="both", expand=False, padx=5, pady=5)

        self.txtAskSydLog = tk.Text(log_frame, bg=BG_DARK, fg=INK_SOFT, insertbackground=INK, wrap="word", height=6)
        scroll_log = ttk.Scrollbar(log_frame, command=self.txtAskSydLog.yview)
        self.txtAskSydLog.configure(yscrollcommand=scroll_log.set)
        self.txtAskSydLog.pack(side="left", fill="both", expand=True)
        scroll_log.pack(side="right", fill="y")

        # Input field for questions - multiline text widget
        input_frame = ttk.Frame(right_frame)
        input_frame.pack(fill="both", expand=False, padx=5, pady=(5,0))

        self.entryQuestion = tk.Text(input_frame, height=3, bg=BG_DARK, fg=INK,
                                     insertbackground=INK, wrap="word", font=('Consolas', 10))
        self.entryQuestion.pack(fill="both", expand=True)
        self.entryQuestion.bind('<Control-Return>', lambda e: self.on_send())

        # Enable right-click copy/paste menu
        self._create_context_menu(self.entryQuestion)

        # Bottom buttons
        bottom_btns = ttk.Frame(right_frame)
        bottom_btns.pack(fill="x", padx=5, pady=5)
        self.btnSend = ttk.Button(bottom_btns, text="Send (Ctrl+Enter)", command=self.on_send)
        self.btnSend.pack(side="left", padx=5)
        self.btnClear = ttk.Button(bottom_btns, text="Clear Chat", command=self.clear_chat_and_output)
        self.btnClear.pack(side="left", padx=5)
        self.btnUpload = ttk.Button(bottom_btns, text="Upload data...", command=self.on_upload)
        self.btnUpload.pack(side="left", padx=5)

        # Initialize RAG in background thread
        threading.Thread(target=self._initialize_rag, daemon=True).start()

    # ========== Context Menu (Right-click) ==========
    def _create_context_menu(self, widget):
        """Add right-click copy/paste menu to Text widget"""
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="Cut", command=lambda: widget.event_generate("<<Cut>>"))
        menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
        menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_separator()
        menu.add_command(label="Select All", command=lambda: widget.tag_add("sel", "1.0", "end"))

        def show_menu(event):
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        widget.bind("<Button-3>", show_menu)  # Right-click

    def _create_entry_context_menu(self, widget):
        """Add right-click copy/paste menu to Entry widget"""
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="Cut", command=lambda: widget.event_generate("<<Cut>>"))
        menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
        menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_separator()
        menu.add_command(label="Select All", command=lambda: widget.select_range(0, tk.END))

        def show_menu(event):
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        widget.bind("<Button-3>", show_menu)  # Right-click

    # ========== Configuration Management ========== 
    def load_config(self):
        """Load configuration from file"""
        default_config = {
            "nmap_path": "nmap",
            "allowlist": []
        }

        # Check user config first, then bundled default
        for cfg_path in [self.config_file, self._default_config_file]:
            if cfg_path.exists():
                try:
                    with open(cfg_path, 'r') as f:
                        return {**default_config, **json.load(f)}
                except Exception:
                    continue
        return default_config

    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)

    # ========== RAG Initialization ==========
    def _initialize_rag(self):
        """Simple RAG: Load Nmap FAISS + LLM, nothing else"""
        try:
            self.log_to_asksyd("[LOADING] Loading Nmap knowledge...")

            # 1. Load embedding model using safe loader
            self.embed_model = load_embedding_model("all-MiniLM-L6-v2")
            self.log_to_asksyd("[OK] Embedding model loaded on cpu")

            # 2. Load Nmap FAISS index (updated knowledge base with correct flags)
            faiss_path = BASE_PATH / "rag_engine" / "embeddings" / "customers" / "customer_syd_nmap_knowledge.faiss"
            pkl_path = BASE_PATH / "rag_engine" / "embeddings" / "customers" / "customer_syd_nmap_knowledge.pkl"

            self.faiss_index = faiss.read_index(str(faiss_path))
            with open(pkl_path, 'rb') as f:
                self.chunks = pickle.load(f)
            self.log_to_asksyd(f"[OK] Loaded {len(self.chunks)} Nmap knowledge chunks")

            # 3. Get shared LLM (single instance for all tools)
            self.llm = get_shared_llm()
            self.log_to_asksyd("[OK] Using shared LLM (Qwen 2.5 14B)")

            # 4. Initialize fact extractor for deterministic parsing
            from nmap_fact_extractor import NmapFactExtractor
            self.fact_extractor = NmapFactExtractor()
            self.verified_cves = set()  # Populated by generate_next_steps CVE results
            self.log_to_asksyd("[OK] Fact extractor ready")

            self.rag_ready = True
            self.log_to_asksyd("[SUCCESS] Ask Syd ready! Type your Nmap question.")

        except Exception as e:
            self.log_to_asksyd("[WARNING] Ask Syd knowledge base could not load. Ensure 'hf_home' folder is present.")
            self.log_to_asksyd("[INFO] Nmap parsing and CVE detection still work!")
            self.log_to_asksyd("[INFO] Paste Nmap results in 'Paste Results' tab")
            self.rag_ready = False
            # Write traceback to user-writable location
            import traceback
            try:
                log_dir = Path(os.environ.get('LOCALAPPDATA', '.')) / "Syd"
                log_dir.mkdir(parents=True, exist_ok=True)
                with open(log_dir / 'rag_error.log', 'w') as f:
                    traceback.print_exc(file=f)
            except Exception:
                pass
            self.log_to_asksyd("[INFO] Error details saved to rag_error.log")

    # ========== Target Validation ========== 
    def is_target_authorized(self, target):
        """Validate target format"""
        # No restrictions - all targets allowed
        return True, "Target accepted"

    def validate_ports(self, ports_str):
        """Validate port specification"""
        if not ports_str:
            return True, ""

        # Allow common nmap port syntax
        if re.match(r'^[\d,\-]+$', ports_str):
            return True, ""

        return False, "Invalid port format. Use: 80,443 or 1-1000"

    # ========== Nmap Command Building ========== 
    def build_nmap_command(self):
        """Build nmap command from UI selections"""
        target = self.txtTarget.get().strip()

        # Validate target
        if not target:
            raise ValueError("Target is required")

        # Get target info
        authorized, reason = self.is_target_authorized(target)

        # Validate ports
        ports = self.txtPorts.get().strip()
        valid, msg = self.validate_ports(ports)
        if not valid:
            raise ValueError(msg)

        # Build command
        nmap_path = self.config.get("nmap_path", "nmap")
        cmd = [nmap_path]

        # Add scan profile flags
        profile = self.cmbProfile.get()
        if profile in self.SCAN_PROFILES:
            cmd.extend(self.SCAN_PROFILES[profile].split())

        # Add timing
        timing = self.cmbTiming.get()
        timing_value = timing.split()[0]  # Extract "T3" from "T3 (Normal)"
        cmd.append(f"-{timing_value}")

        # Add ports
        if ports:
            cmd.extend(["-p", ports])

        # Generate output filenames
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r'[^\w\-.]', '_', target)
        self.current_output_file = self.output_dir / f"scan_{safe_target}_{timestamp}.txt"
        self.current_xml_file = self.output_dir / f"scan_{safe_target}_{timestamp}.xml"

        # Add output formats
        cmd.extend(["-oN", str(self.current_output_file)])
        cmd.extend(["-oX", str(self.current_xml_file)])

        # Add target
        cmd.append(target)

        return cmd, authorized, reason

    # ========== Scan Execution ========== 
    def run_scan_thread(self, cmd):
        """Run scan in background thread"""
        try:
            # Create process
            self.scan_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )

            # Stream output
            for line in iter(self.scan_process.stdout.readline, ''):
                if line:
                    self.append_output(line)

            # Wait for completion
            self.scan_process.wait()

            # Check if completed successfully
            if self.scan_process.returncode == 0:
                self.after(0, self.on_scan_complete)
            else:
                self.update_status("Scan failed")
                self.append_output(f"\n[ERROR] Scan exited with code {self.scan_process.returncode}\n")
                self.append_output(f"[ERROR] Return code explanation: Exit code {self.scan_process.returncode}\n")

        except FileNotFoundError as e:
            self.append_output(f"\n[ERROR] Nmap executable not found: {cmd[0]}\n")
            self.append_output(f"[ERROR] Please check nmap path in Set Path or install Nmap\n")
            self.update_status("Nmap not found")
        except Exception as e:
            self.append_output(f"\n[ERROR] {type(e).__name__}: {str(e)}\n")
            self.update_status("Error")
        finally:
            self.scan_process = None
            self.enable_controls()

    def append_output(self, text):
        """Append text to Raw Output tab (thread-safe)"""
        self.txtRawOutput.after(0, self._append_output_ui, text)

    def _append_output_ui(self, text):
        """UI thread method to append output"""
        self.txtRawOutput.insert(tk.END, text)
        self.txtRawOutput.see(tk.END)

    def update_status(self, text):
        """Update status label (thread-safe)"""
        self.lblStatus.after(0, self.lblStatus.config, {"text": text})

    def enable_controls(self):
        """Re-enable controls after scan (thread-safe)"""
        self.btnRunScan.after(0, self.btnRunScan.config, {"state": "normal"})
        self.btnStop.after(0, self.btnStop.config, {"state": "disabled"})

    def on_scan_complete(self):
        """Handle scan completion - parse results and populate tabs"""
        self.update_status("Processing results...")

        try:
            # Parse XML
            if self.current_xml_file and self.current_xml_file.exists():
                services = self.parse_xml_results(self.current_xml_file)
                self.populate_services_tab(services)
                self.populate_next_steps_tab(services)
                self.populate_paste_results_tab(services)

            self.update_status("Nmap ready")
            self.append_output("\n[SCAN COMPLETE]\n")

        except Exception as e:
            self.append_output(f"\n[ERROR] Failed to parse results: {str(e)}\n")
            self.update_status("Nmap ready")

    # ========== XML Parsing ========== 
    def parse_xml_results(self, xml_file):
        """Parse Nmap XML output"""
        tree = ET.parse(xml_file)
        root = tree.getroot()

        services = []

        for host in root.findall('host'):
            # Get host address (with null safety)
            addr_elem = host.find('address')
            if addr_elem is None:
                continue
            address = addr_elem.get('addr', 'unknown')

            # Get hostname if available
            hostname = ""
            hostnames_elem = host.find('hostnames')
            if hostnames_elem is not None:
                hostname_elem = hostnames_elem.find('hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name', '')

            # Get ports
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        port_id = port.get('portid')
                        protocol = port.get('protocol')

                        service_elem = port.find('service')
                        service_name = ""
                        product = ""
                        version = ""
                        extra_info = ""

                        if service_elem is not None:
                            service_name = service_elem.get('name', '')
                            product = service_elem.get('product', '')
                            version = service_elem.get('version', '')
                            extra_info = service_elem.get('extrainfo', '')

                        services.append({
                            'host': address,
                            'hostname': hostname,
                            'port': port_id,
                            'protocol': protocol,
                            'service': service_name,
                            'product': product,
                            'version': version,
                            'extra_info': extra_info
                        })

        return services

    def populate_services_tab(self, services):
        """Populate Services Found tab"""
        self.txtServices.delete('1.0', tk.END)

        if not services:
            self.txtServices.insert(tk.END, "No open ports found.\n")
            return

        # Create formatted table
        header = f"{ 'HOST':<20} { 'PORT':<10} { 'SERVICE':<15} { 'PRODUCT':<30} { 'VERSION':<15}\n"
        separator = "=" * 100 + "\n"

        self.txtServices.insert(tk.END, header)
        self.txtServices.insert(tk.END, separator)

        for svc in services:
            host_display = svc['hostname'] if svc['hostname'] else svc['host']
            port_display = f"{svc['port']}/{svc['protocol']}"
            product_display = f"{svc['product']} {svc['version']}".strip()

            line = f"{host_display:<20} {port_display:<10} {svc['service']:<15} {product_display:<30}\n"
            self.txtServices.insert(tk.END, line)

        self.txtServices.insert(tk.END, f"\nTotal: {len(services)} open ports\n")

    def populate_next_steps_tab(self, services):
        """Generate actionable next steps with CVE/exploit suggestions"""
        self.txtNextSteps.delete('1.0', tk.END)

        if not services:
            self.txtNextSteps.insert(tk.END, "No services found - no next steps available.\n")
            return

        self.txtNextSteps.insert(tk.END, "VULNERABILITY & EXPLOITATION ANALYSIS\n")
        self.txtNextSteps.insert(tk.END, "=" * 80 + "\n\n")

        for svc in services:
            service = svc['service'].lower()
            product = svc['product']
            version = svc['version']
            port = svc['port']
            host = svc['hostname'] if svc['hostname'] else svc['host']

            # Service header
            self.txtNextSteps.insert(tk.END, f"[{host}:{port}] {svc['service'].upper()}")
            if product:
                self.txtNextSteps.insert(tk.END, f" - {product}")
            if version:
                self.txtNextSteps.insert(tk.END, f" {version}")
            self.txtNextSteps.insert(tk.END, "\n")
            self.txtNextSteps.insert(tk.END, "-" * 80 + "\n")

            # Check for known vulnerable versions and suggest exploits
            vulns = self.check_known_vulnerabilities(service, product, version, port)
            if vulns:
                self.txtNextSteps.insert(tk.END, "\n[!] KNOWN VULNERABILITIES:\n")
                for vuln in vulns:
                    self.txtNextSteps.insert(tk.END, f"  {vuln}\n")
                self.txtNextSteps.insert(tk.END, "\n")

            # Enumeration steps
            enum_steps = self.get_enumeration_steps(service, port, host)
            if enum_steps:
                self.txtNextSteps.insert(tk.END, "[*] ENUMERATION:\n")
                for step in enum_steps:
                    self.txtNextSteps.insert(tk.END, f"  {step}\n")
                self.txtNextSteps.insert(tk.END, "\n")

            # Exploitation suggestions
            exploit_steps = self.get_exploitation_suggestions(service, product, version, port, host)
            if exploit_steps:
                self.txtNextSteps.insert(tk.END, "[+] EXPLOITATION:\n")
                for step in exploit_steps:
                    self.txtNextSteps.insert(tk.END, f"  {step}\n")

            self.txtNextSteps.insert(tk.END, "\n")

    def check_known_vulnerabilities(self, service, product, version, port):
        """Check for known CVEs and vulnerabilities"""
        vulns = []

        # SSH vulnerabilities
        if 'ssh' in service.lower() or 'openssh' in product.lower():
            if version:
                # Known OpenSSH vulnerabilities
                if 'openssh' in product.lower():
                    major_minor = version.split('p')[0] if 'p' in version else version

                    if version.startswith('6.6'):
                        vulns.append("⚠ OpenSSH 6.6.x - User enumeration vulnerability (CVE-2016-6210)")
                        vulns.append("⚠ OpenSSH < 7.2p2 - Username enumeration (CVE-2018-15473)")

                    if version.startswith(('5.', '6.', '7.0', '7.1', '7.2', '7.3', '7.4', '7.5', '7.6')):
                        vulns.append("⚠ OpenSSH < 7.7 - User enumeration timing attack")

                    if version.startswith(('1.', '2.', '3.', '4.', '5.')):
                        vulns.append("[CRITICAL] CRITICAL: OpenSSH < 6.0 - Multiple critical vulnerabilities")

            vulns.append(f"-> Search: searchsploit openssh {version}")
            vulns.append(f"-> Search CVE: https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=openssh+{version}")

        # Apache vulnerabilities
        if 'http' in service.lower() and 'apache' in product.lower():
            if version:
                if version.startswith('2.4.7'):
                    vulns.append("⚠ Apache 2.4.7 - Multiple vulnerabilities (CVE-2014-0098, CVE-2013-6438)")
                    vulns.append("⚠ Apache 2.4.7 - mod_proxy denial of service (CVE-2014-0117)")

                if version.startswith(('2.0.', '2.2.')):
                    vulns.append("[CRITICAL] Apache 2.0/2.2 - End of life, multiple unpatched vulnerabilities")

            vulns.append(f"-> Search: searchsploit apache {version}")
            vulns.append(f"-> Search CVE: https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=apache+{version}")

        # SMB vulnerabilities
        if 'smb' in service.lower() or port in ['139', '445']:
            vulns.append("⚠ Check for EternalBlue (MS17-010) - SMBv1 RCE")
            vulns.append("⚠ Check for SMBGhost (CVE-2020-0796) - SMBv3 RCE")
            vulns.append("-> Run: nmap --script smb-vuln-* -p445 <target>")

        # MySQL vulnerabilities
        if 'mysql' in service.lower() or 'mariadb' in service.lower():
            if version:
                vulns.append(f"-> Search: searchsploit mysql {version}")
                vulns.append("⚠ Check for default credentials (root:root, root:)")

        # RDP vulnerabilities
        if 'rdp' in service.lower() or port == '3389':
            vulns.append("⚠ Check for BlueKeep (CVE-2019-0708) - RDP RCE")
            vulns.append("-> Run: nmap --script rdp-vuln-ms12-020 -p3389 <target>")

        # FTP vulnerabilities
        if 'ftp' in service.lower():
            if 'vsftpd' in product.lower() and '2.3.4' in version:
                vulns.append("[CRITICAL] CRITICAL: vsFTPd 2.3.4 - Backdoor command execution")
            vulns.append("-> Check for anonymous login: ftp <target>")

        return vulns

    def get_enumeration_steps(self, service, port, host):
        """Get enumeration commands"""
        steps = []

        if 'http' in service.lower() or port in ['80', '443', '8080', '8443']:
            steps.append(f"gobuster dir -u http://{host}:{port} -w /path/to/wordlist")
            steps.append(f"nikto -h {host}:{port}")
            steps.append(f"whatweb {host}:{port}")

        if 'smb' in service.lower() or port in ['139', '445']:
            steps.append(f"enum4linux -a {host}")
            steps.append(f"smbclient -L //{host} -N")
            steps.append(f"crackmapexec smb {host} --shares")

        if 'ssh' in service.lower() or port == '22':
            steps.append(f"ssh-audit {host}")
            steps.append(f"nc {host} {port}")  # Banner grab

        if 'ftp' in service.lower():
            steps.append(f"ftp {host}")
            steps.append(f"nmap --script ftp-anon,ftp-bounce -p{port} {host}")

        if 'dns' in service.lower() or port == '53':
            steps.append(f"dig axfr @{host}")
            steps.append(f"dnsenum {host}")

        if 'ldap' in service.lower():
            steps.append(f"ldapsearch -x -h {host} -b 'dc=domain,dc=com'")

        if 'rdp' in service.lower():
            steps.append(f"nmap --script rdp-enum-encryption -p{port} {host}")

        return steps

    def get_exploitation_suggestions(self, service, product, version, port, host):
        """Get exploitation suggestions"""
        suggestions = []

        if 'ssh' in service.lower():
            suggestions.append(f"hydra -L users.txt -P passwords.txt ssh://{host}")
            suggestions.append("Check for weak SSH keys")

        if 'http' in service.lower():
            suggestions.append("Check for SQL injection, XSS, LFI/RFI")
            suggestions.append("Test for default credentials on admin panels")

        if 'smb' in service.lower():
            suggestions.append(f"psexec.py <user>:<pass>@{host}")
            suggestions.append(f"smbexec.py <user>:<pass>@{host}")

        if 'ftp' in service.lower():
            suggestions.append(f"hydra -L users.txt -P passwords.txt ftp://{host}")

        if 'mysql' in service.lower():
            suggestions.append(f"mysql -h {host} -u root -p")
            suggestions.append("Check for SQL injection in web apps using this DB")

        # General searchsploit suggestion
        if product and version:
            suggestions.append(f"searchsploit {product} {version}")

        return suggestions

    def populate_paste_results_tab(self, services):
        """Create clean summary for pasting into chat"""
        self.txtPasteResults.delete('1.0', tk.END)

        if not services:
            self.txtPasteResults.insert(tk.END, "No scan results to paste.\n")
            return

        # Group by host
        hosts = {}
        for svc in services:
            host_key = svc['hostname'] if svc['hostname'] else svc['host']
            if host_key not in hosts:
                hosts[host_key] = []
            hosts[host_key].append(svc)

        # Format summary
        summary = "NMAP SCAN SUMMARY\n"
        summary += "=" * 50 + "\n\n"

        for host, svcs in hosts.items():
            summary += f"Host: {host}\n"
            summary += "-" * 50 + "\n"
            for svc in svcs:
                port_proto = f"{svc['port']}/{svc['protocol']}"
                product = f"{svc['product']} {svc['version']}".strip()
                summary += f"  {port_proto:<12} {svc['service']:<15} {product}\n"
            summary += "\n"

        summary += f"Total: {len(services)} open ports across {len(hosts)} host(s)\n"

        self.txtPasteResults.insert(tk.END, summary)

    # ========== Preset Commands ========== 
    def load_preset_command(self, cmd_template):
        """Load a preset command into the command field"""
        target = self.txtTarget.get().strip()

        if not target:
            # If no target specified, use placeholder
            target = "<target>"
            messagebox.showinfo("Preset Loaded",
                "Command loaded. Please enter a target in the Target field, then click Execute.")

        # Substitute {target} in the template
        command = cmd_template.replace("{target}", target)

        # Update command field
        self.txtCommand.delete(0, tk.END)
        self.txtCommand.insert(0, command)

        # Show info
        if target != "<target>":
            response = messagebox.askyesno("Run Preset Command",
                f"Command loaded:\n{command}\n\nRun this scan now?")
            if response:
                self.on_execute()

    # ========== Event Handlers ========== 
    def on_run_scan(self):
        """Handle Run Scan button"""
        try:
            # Clear previous results
            self.txtRawOutput.delete('1.0', tk.END)
            self.txtServices.delete('1.0', tk.END)
            self.txtNextSteps.delete('1.0', tk.END)
            self.txtPasteResults.delete('1.0', tk.END)

            # Build command
            cmd, authorized, reason = self.build_nmap_command()

            # Display command
            self.append_output(f"[COMMAND] {' '.join(cmd)}\n\n")

            # Update UI
            self.update_status("Scanning...")
            self.btnRunScan.config(state="disabled")
            self.btnStop.config(state="normal")

            # Display command in command box
            self.txtCommand.delete(0, tk.END)
            self.txtCommand.insert(0, ' '.join(cmd))

            # Start scan in background thread
            self.scan_thread = threading.Thread(target=self.run_scan_thread, args=(cmd,), daemon=True)
            self.scan_thread.start()

        except ValueError as e:
            messagebox.showerror("Scan Error", str(e))
            self.txtRawOutput.insert(tk.END, f"[ERROR] {str(e)}\n")
            self.update_status("Nmap ready")

    def on_stop(self):
        """Handle Stop button - kill scan process"""
        if self.scan_process:
            try:
                # On Windows, kill entire process tree
                if os.name == 'nt':
                    subprocess.run(['taskkill', '/F', '/T', '/PID', str(self.scan_process.pid)],
                                   capture_output=True)
                else:
                    self.scan_process.kill()

                self.append_output("\n[SCAN STOPPED BY USER]\n")
                self.update_status("Stopped")

            except Exception as e:
                self.append_output(f"\n[ERROR] Failed to stop scan: {str(e)}\n")
            finally:
                self.scan_process = None
                self.enable_controls()
                self.after(1000, lambda: self.update_status("Nmap ready"))

    def on_export(self):
        """Handle Export button - export current tab content"""
        # Get current tab
        current_tab_id = self.tabsResults.index(self.tabsResults.select())
        tab_names = ["Raw Output", "Services Found", "Next Steps", "Paste Results"]
        current_tab_name = tab_names[current_tab_id]

        # Get content
        text_widgets = [self.txtRawOutput, self.txtServices, self.txtNextSteps, self.txtPasteResults]
        content = text_widgets[current_tab_id].get('1.0', tk.END)

        # Ask for file location
        default_ext = ".txt"
        if current_tab_name == "Services Found":
            filetypes = [("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]
        else:
            filetypes = [("Text files", "*.txt"), ("All files", "*.*")]

        filepath = filedialog.asksaveasfilename(
            defaultextension=default_ext,
            filetypes=filetypes,
            initialfile=f"nmap_{current_tab_name.replace(' ', '_').lower()}.txt"
        )

        if filepath:
            try:
                # Convert to CSV if Services tab and .csv extension
                if current_tab_name == "Services Found" and filepath.endswith('.csv'):
                    # Parse and export as proper CSV with escaping
                    if self.current_xml_file and self.current_xml_file.exists():
                        import csv
                        services = self.parse_xml_results(self.current_xml_file)
                        with open(filepath, 'w', newline='', encoding='utf-8') as f:
                            writer = csv.writer(f)
                            writer.writerow(["Host", "Hostname", "Port", "Protocol", "Service", "Product", "Version", "Extra Info"])
                            for svc in services:
                                writer.writerow([svc['host'], svc['hostname'], svc['port'], svc['protocol'], svc['service'], svc['product'], svc['version'], svc['extra_info']])
                else:
                    # Export as text
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(content)

                messagebox.showinfo("Export Successful", f"Exported to:\n{filepath}")

            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")

    def on_execute(self):
        """Handle Execute button - run custom command"""
        cmd_str = self.txtCommand.get().strip()

        if not cmd_str:
            messagebox.showwarning("Execute", "Command is empty")
            return

        # Parse command
        cmd_parts = cmd_str.split()

        # Replace "nmap" with configured path if command starts with nmap
        if cmd_parts[0].lower() == 'nmap' or cmd_parts[0].lower().endswith('nmap.exe'):
            nmap_path = self.config.get("nmap_path", "nmap")
            cmd_parts[0] = nmap_path

            # Auto-add XML output for parsing (if not already present)
            if '-oX' not in cmd_parts and '-oA' not in cmd_parts:
                # Extract target from command (usually last argument)
                target = cmd_parts[-1]

                # Generate output filenames
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_target = re.sub(r'[^\w\-.]', '_', target)
                self.current_output_file = self.output_dir / f"scan_{safe_target}_{timestamp}.txt"
                self.current_xml_file = self.output_dir / f"scan_{safe_target}_{timestamp}.xml"

                # Insert output flags before target
                cmd_parts.insert(-1, "-oN")
                cmd_parts.insert(-1, str(self.current_output_file))
                cmd_parts.insert(-1, "-oX")
                cmd_parts.insert(-1, str(self.current_xml_file))

        # Clear output
        self.txtRawOutput.delete('1.0', tk.END)
        self.append_output(f"[COMMAND] {' '.join(cmd_parts)}\n\n")

        # Update UI
        self.update_status("Executing...")
        self.btnRunScan.config(state="disabled")
        self.btnStop.config(state="normal")

        # Run in background
        self.scan_thread = threading.Thread(target=self.run_scan_thread, args=(cmd_parts,), daemon=True)
        self.scan_thread.start()

    def on_set_path(self):
        """Handle Set Path button - configure nmap.exe path"""
        filepath = filedialog.askopenfilename(
            title="Select nmap executable",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
        )

        if filepath:
            self.config["nmap_path"] = filepath
            self.save_config()
            messagebox.showinfo("Path Set", f"Nmap path set to:\n{filepath}")
            self.log_to_asksyd(f"Nmap path configured: {filepath}")

    def on_test_tool(self):
        """Handle Test Tool button - verify nmap installation"""
        try:
            nmap_path = self.config.get("nmap_path", "nmap")
            result = subprocess.run(
                [nmap_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )

            output = result.stdout + result.stderr

            if result.returncode == 0:
                self.log_to_asksyd(f"[OK] Nmap test successful\n\n{output}")
                messagebox.showinfo("Test Successful", "Nmap is installed and working!")
            else:
                self.log_to_asksyd(f"[ERROR] Nmap test failed\n\n{output}")
                messagebox.showerror("Test Failed", "Nmap test failed. Check path configuration.")

        except FileNotFoundError:
            msg = "Nmap not found. Please install Nmap or set the path manually."
            self.log_to_asksyd(f"[ERROR] {msg}")
            messagebox.showerror("Nmap Not Found", msg)
        except Exception as e:
            self.log_to_asksyd(f"[ERROR] Error: {str(e)}")
            messagebox.showerror("Test Error", str(e))

    def clear_chat_and_output(self):
        """Clear all chat and output screens"""
        # Clear Ask Syd chat
        self.txtAskSydMain.delete('1.0', tk.END)
        # Clear input field
        self.entryQuestion.delete('1.0', tk.END)
        # Clear all output tabs
        self.txtRawOutput.delete('1.0', tk.END)
        self.txtServices.delete('1.0', tk.END)
        self.txtNextSteps.delete('1.0', tk.END)
        self.txtPasteResults.delete('1.0', tk.END)
        # Clear command and status
        self.txtCommand.delete(0, tk.END)
        self.update_status("Ready")
        # Log the clear action
        self.log_to_asksyd("[INFO] Chat and output cleared")

    def on_send(self):
        """Handle Send button - simple RAG query"""
        if not self.rag_ready:
            messagebox.showwarning("Ask Syd", "Still loading, please wait...")
            return

        question = self.entryQuestion.get("1.0", tk.END).strip()
        if not question:
            return

        self.entryQuestion.delete("1.0", tk.END)
        self.append_chat_message("You", question)

        # Show "Syd is thinking..." indicator
        self.show_thinking_indicator()

        def query_rag():
            try:
                # Get current scan context (thread-safe via main thread)
                _scan_holder = [None]
                _event = threading.Event()
                def _read_scan():
                    _scan_holder[0] = self.txtRawOutput.get("1.0", tk.END).strip()
                    _event.set()
                self.after(0, _read_scan)
                _event.wait(timeout=5)
                current_scan = _scan_holder[0] or ""

                # Check if we have scan data or if this is a general question
                if not current_scan or len(current_scan) < 50:
                    # No scan data - answer general questions using knowledge base only
                    query_vec = self.embed_model.encode([question]).astype('float32')
                    faiss.normalize_L2(query_vec)
                    distances, indices = self.faiss_index.search(query_vec, 5)

                    contexts = []
                    for idx in indices[0]:
                        if idx < len(self.chunks):
                            chunk = self.chunks[idx]
                            text = chunk.get('content', str(chunk))
                            contexts.append(text)
                    context_text = "\n\n".join(contexts)

                    # Build general knowledge prompt
                    system_prompt = f"""You are Syd, an expert penetration testing analyst specializing in Nmap, network reconnaissance, and exploit development.

The user has asked a general question without providing scan data. Answer their question using your knowledge of Nmap, network scanning, penetration testing, and exploitation.

KNOWLEDGE BASE:
{context_text}

RESPONSE GUIDELINES:
- Provide clear, practical explanations
- Include examples when helpful
- Mention relevant Nmap flags and techniques
- If asked about exploits, provide guidance on exploit development, proof-of-concept writing, and ExploitDB usage for authorized penetration testing
- If asked about CVEs, explain the vulnerability and potential exploitation approaches
- Keep answers concise but informative
- If the question requires scan data to answer, politely explain that and ask them to provide scan data"""

                    user_message = f"Question: {question}"

                    response = self.llm.create_chat_completion(
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_message}
                        ],
                        max_tokens=1536,
                        temperature=0.2,
                        top_p=0.9,
                        stop=["Question:", "Q:"]
                    )
                    answer = response['choices'][0]['message']['content'].strip()
                    answer = tag_unverified_cves(answer, getattr(self, 'verified_cves', None))

                    # Remove thinking indicator and show answer
                    self.after(0, lambda: self.remove_thinking_indicator())
                    self.after(0, lambda: self.append_chat_message("Syd", answer))
                    return

                # === STAGE A: DETERMINISTIC FACT EXTRACTION ===
                # Extract facts using deterministic parser (100% accurate)
                facts = self.fact_extractor.extract_facts(current_scan)
                facts_text = self.fact_extractor.facts_to_text(facts)

                # Inject verified CVEs from Next Steps so Ask Syd can reference them
                if getattr(self, 'verified_cves', None):
                    cve_map = getattr(self, 'cve_service_map', {})
                    if cve_map:
                        cve_lines = []
                        for cve_id in sorted(cve_map.keys()):
                            cve_lines.append(f"  - {cve_id} affects {cve_map[cve_id]}")
                        cve_detail = '\n'.join(cve_lines)
                        facts_text += f"\n\nQ: What CVEs were identified by the vulnerability scan?\nA: The CVE engine confirmed the following vulnerabilities:\n{cve_detail}\n"
                    else:
                        cve_list = ', '.join(sorted(self.verified_cves))
                        facts_text += f"\n\nQ: What CVEs were identified by the vulnerability scan?\nA: The following CVEs were confirmed by the CVE engine: {cve_list}\n"

                # === STAGE B: LLM ANSWERS FROM FACTS ONLY ===
                # Get knowledge base context (for explaining concepts, not facts)
                query_vec = self.embed_model.encode([question]).astype('float32')
                faiss.normalize_L2(query_vec)
                distances, indices = self.faiss_index.search(query_vec, 3)

                contexts = []
                for idx in indices[0]:
                    if idx < len(self.chunks):
                        chunk = self.chunks[idx]
                        text = chunk.get('content', str(chunk))
                        contexts.append(text)
                context_text = "\n\n".join(contexts)

                # Truncate facts and context to fit within context window
                facts_text, context_text = truncate_for_context_window(
                    self.llm, facts_text, context_text,
                    max_tokens=1536, static_prompt_chars=1800
                )

                # Build system prompt with facts - HYBRID APPROACH (Gemini's fix)
                system_prompt = f"""You are Syd, an expert penetration testing analyst analyzing Nmap scan results.

ANSWERING STRATEGY (3-Tier Approach):

1. SPECIFIC SCAN DATA (Facts-First - NEVER Invent):
   - For IPs, port numbers, versions, services, MAC addresses: Use ONLY the facts below
   - NEVER invent or guess: IP addresses, port numbers, version strings, service names
   - If not in facts, say "Not present in the facts"

2. INFERENCE FROM EVIDENCE (Connect the Dots):
   - OS Detection: "Ubuntu" in banners = Linux, "Microsoft" = Windows
   - Service Implications: CUPS = Linux printing, IIS = Windows web server
   - Service Synonyms: microsoft-ds = SMB, ms-wbt-server = RDP, domain = DNS
   - Virtualization: VirtualBox/VMware in MAC vendor = VM
   - Security Issues: "SMB signing disabled" = high risk
   - Port Count Math: CALCULATE (open + closed + filtered). If ~1000 = default scan, if ~100 = fast scan (-F), if ~65535 = full scan (-p-)
   - Use phrases like: "Based on the banners..." or "The evidence suggests..."

3. GENERAL SECURITY KNOWLEDGE (Explain Concepts):
   - Definitions: What "closed ports" means, what NSE scripts do
   - Standard practices: Common Nmap flags, typical next steps
   - Risk assessment: Why certain findings matter
   - Exploitation: If asked about exploits, provide exploitation guidance, proof-of-concept approaches, and relevant ExploitDB references for authorized penetration testing
   - Use phrases like: "In penetration testing..." or "Generally..."

CRITICAL RULES:
   - If a CVE is listed in the FACTS below (from the CVE engine), treat it as CONFIRMED and discuss it fully.
   - If the user asks about a specific CVE by number, you may discuss it - explain the vulnerability and exploitation approach.
   - Do NOT invent additional CVE numbers beyond what is in the facts or what the user asked about. If you want to mention a vulnerability class, describe it by name (e.g. "buffer overflow", "heap overflow") without guessing a CVE number.
   - NEVER attribute a CVE to the wrong product (e.g. do not cite a PHP CVE for an FTP service).
   - When discussing exploits, focus on the TECHNIQUE (e.g. "anonymous FTP login", "SQL injection via INTO OUTFILE") rather than guessing CVE numbers.

FACTS FROM THIS SCAN:
{facts_text}

KNOWLEDGE BASE (for general Nmap/security concepts):
{context_text}

RESPONSE FORMAT:
- Start with facts from the scan
- Add inferences based on evidence
- Include general knowledge if helpful
- Always distinguish: Facts vs Inference vs General knowledge"""

                user_message = f"Question: {question}\n\nAnswer based on the facts above:"

                # Use chat completion API with Qwen
                response = self.llm.create_chat_completion(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ],
                    max_tokens=1536,
                    temperature=0.1,
                    top_p=0.9,
                    stop=["Question:", "Q:"]
                )
                answer = response['choices'][0]['message']['content'].strip()

                # Tag any CVE references not found by the CVE engine as unverified
                answer = tag_unverified_cves(answer, getattr(self, 'verified_cves', None))

                # === STAGE C: VALIDATION LAYER ===
                # Validate answer against extracted facts
                validation_result = self._validate_answer_against_facts(answer, facts)

                if not validation_result['valid']:
                    # Warn about potential hallucination but show full answer
                    warning = f"[WARNING - POSSIBLE HALLUCINATION]\n\n"
                    warning += f"Syd's answer may contain information not confirmed in the scan data:\n"
                    for issue in validation_result['issues']:
                        warning += f"  - {issue}\n"
                    warning += f"\nPlease verify the following answer against your scan results:\n"
                    warning += f"{'=' * 50}\n\n"
                    answer = warning + answer

                # === SUGGESTION FOR "NOT PRESENT" ANSWERS ===
                # If the LLM returned a terse "Not present", suggest the relevant Nmap flag
                # using knowledge base only (no LLM call — avoids unvalidated output)
                if answer.strip() in ("Not present in the facts", "Not present in the facts."):
                    # Search knowledge base for relevant flags based on the question
                    suggestion_vec = self.embed_model.encode([question]).astype('float32')
                    faiss.normalize_L2(suggestion_vec)
                    s_distances, s_indices = self.faiss_index.search(suggestion_vec, 2)
                    kb_snippets = []
                    for idx in s_indices[0]:
                        if idx < len(self.chunks):
                            chunk = self.chunks[idx]
                            text = chunk.get('content', str(chunk))
                            # Extract just the first 2 lines as a hint
                            lines = [l.strip() for l in text.split('\n') if l.strip()][:2]
                            if lines:
                                kb_snippets.append('\n'.join(lines))
                    if kb_snippets:
                        answer += f"\n\n💡 This info isn't in the current scan. You may need a different scan type — check the knowledge base:\n" + '\n'.join(kb_snippets)

                # Remove thinking indicator and show answer
                self.after(0, lambda: self.remove_thinking_indicator())
                self.after(0, lambda: self.append_chat_message("Syd", answer))

            except Exception as e:
                self.after(0, lambda: self.remove_thinking_indicator())
                self.after(0, lambda: self.append_chat_message("System", f"Error: {e}"))
                import traceback
                traceback.print_exc()

        threading.Thread(target=query_rag, daemon=True).start()

    def _validate_answer(self, answer, scan_text):
        """Validate answer against scan to detect hallucinations (legacy method)"""
        import re

        issues = []
        scan_lower = scan_text.lower()
        answer_lower = answer.lower()

        # Extract potential IPs from answer
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        answer_ips = set(re.findall(ip_pattern, answer))
        scan_ips = set(re.findall(ip_pattern, scan_text))

        # Check for invented IPs
        invented_ips = answer_ips - scan_ips
        if invented_ips:
            issues.append(f"Invented IP addresses: {', '.join(invented_ips)}")

        # Extract potential port numbers from answer
        port_pattern = r'\b(\d{1,5})/tcp\b'
        answer_ports = set(re.findall(port_pattern, answer_lower))
        scan_ports = set(re.findall(port_pattern, scan_lower))

        # Check for invented ports
        invented_ports = answer_ports - scan_ports
        if invented_ports:
            issues.append(f"Invented ports: {', '.join(invented_ports)}")

        # Check for services not in scan
        common_services = ['smb', 'ftp', 'telnet', 'rdp', 'kerberos', 'ldap', 'dns']
        for service in common_services:
            if service in answer_lower and service not in scan_lower:
                issues.append(f"Mentioned '{service}' which is not in the scan")

        # Validation result
        is_valid = len(issues) == 0
        return {
            'is_valid': is_valid,
            'issues': '\n'.join(f"- {issue}" for issue in issues) if issues else 'None'
        }

    def _validate_answer_against_facts(self, answer, facts):
        """Validate answer against extracted facts - Stage C of new architecture"""
        import re

        issues = []

        # Extract all port numbers mentioned in answer
        mentioned_ports = set(re.findall(r'\b(\d{1,5})/(?:tcp|udp)\b', answer))
        mentioned_ports.update(re.findall(r'\bport\s+(\d{1,5})\b', answer.lower()))

        # Get valid ports from facts
        valid_ports = set()
        for host in facts['hosts']:
            for port_info in host['open_ports']:
                valid_ports.add(str(port_info['port']))
            for port_info in host['filtered_ports']:
                valid_ports.add(str(port_info['port']))

        # Check for invented ports
        invented_ports = mentioned_ports - valid_ports
        if invented_ports:
            issues.append(f"Invented ports: {', '.join(invented_ports)}")

        # Check service names with SYNONYM MAPPING (Gemini's fix)
        # Map common service names to their Nmap service name variations
        SERVICE_SYNONYMS = {
            'smb': ['smb', 'microsoft-ds', 'netbios-ssn', 'cifs', 'smb2', 'smb2-security-mode'],
            'rdp': ['rdp', 'ms-wbt-server', 'terminal services', 'terminal-services', 'ms-term-serv'],
            'dns': ['dns', 'domain'],
            'http': ['http', 'www', 'http-alt', 'https', 'ssl/http', 'http-proxy'],
            'https': ['https', 'ssl/http', 'http-ssl'],
            'ssh': ['ssh', 'openssh'],
            'ftp': ['ftp', 'ftps', 'ftp-data'],
            'telnet': ['telnet'],
            'smtp': ['smtp', 'smtps', 'submission'],
            'ldap': ['ldap', 'ldaps', 'ssl/ldap'],
            'vnc': ['vnc', 'vnc-http'],
            'mysql': ['mysql', 'mariadb'],
            'postgresql': ['postgresql', 'postgres'],
            'rpc': ['rpc', 'msrpc', 'rpcbind', 'ncacn_http'],
            'kerberos': ['kerberos', 'kerberos-sec', 'kpasswd5'],
        }

        # Build set of valid services from scan (including all variations)
        valid_services = set()
        for host in facts['hosts']:
            for port_info in host['open_ports']:
                service_name = port_info['service'].lower()
                valid_services.add(service_name)
                # Also add version info which might contain service names
                if port_info.get('version_info'):
                    valid_services.add(port_info['version_info'].lower())

        # Check each common service
        common_services = ['ftp', 'telnet', 'smtp', 'smb', 'rdp', 'vnc', 'mysql', 'postgresql']
        for service in common_services:
            if service in answer.lower():
                # Check if this service (or any synonym) is in the scan
                synonyms = SERVICE_SYNONYMS.get(service, [service])
                found = any(syn in ' '.join(valid_services) for syn in synonyms)
                if not found:
                    issues.append(f"Mentioned '{service}' not in scan")

        # Check IPs - use negative lookbehind/lookahead to skip OIDs (e.g. 1.3.6.1.4.1.77.1)
        # Real IPs have exactly 4 octets; OIDs have 5+ dotted segments
        ip_pattern = r'(?<!\d\.)(?<!\d)\b(?:\d{1,3}\.){3}\d{1,3}\b(?!\.\d)'
        mentioned_ips = set(re.findall(ip_pattern, answer))

        # Build valid IPs from targets AND host target strings (handles both
        # "Nmap scan report for 10.0.5.10 (hostname)" and "... for hostname (10.0.5.10)")
        valid_ips = set()
        for t in facts.get('targets', []):
            valid_ips.update(re.findall(ip_pattern, t))
        for host in facts.get('hosts', []):
            target_str = host.get('target', '')
            valid_ips.update(re.findall(ip_pattern, target_str))

        invented_ips = mentioned_ips - valid_ips
        if invented_ips:
            issues.append(f"Invented IPs: {', '.join(invented_ips)}")

        return {
            'valid': len(issues) == 0,
            'issues': issues
        }

    def append_chat_message(self, sender, message):
        """Append a message to the chat display"""
        self.txtAskSydMain.insert(tk.END, f"\n{'='*60}\n")
        self.txtAskSydMain.insert(tk.END, f"[{sender}]\n")
        self.txtAskSydMain.insert(tk.END, f"{message}\n")
        self.txtAskSydMain.see(tk.END)

    def show_thinking_indicator(self):
        """Show 'Syd is thinking...' with animated dots"""
        # Store the starting position of the thinking message
        self.thinking_start = self.txtAskSydMain.index(tk.END)

        # Add the thinking message
        self.txtAskSydMain.insert(tk.END, f"\n{'='*60}\n")
        self.txtAskSydMain.insert(tk.END, "[Syd]\n")
        self.thinking_text_start = self.txtAskSydMain.index(tk.END)
        self.txtAskSydMain.insert(tk.END, "Thinking.\n")
        self.txtAskSydMain.see(tk.END)

        # Start animation
        self.thinking_dots = 1
        self.thinking_active = True
        self.animate_thinking()

    def animate_thinking(self):
        """Animate the thinking dots (. .. ... . .. ...)"""
        if not hasattr(self, 'thinking_active') or not self.thinking_active:
            return

        # Update dots
        dots = "." * self.thinking_dots
        self.thinking_dots = (self.thinking_dots % 3) + 1

        # Update the text
        try:
            self.txtAskSydMain.delete(self.thinking_text_start, f"{self.thinking_text_start} lineend")
            self.txtAskSydMain.insert(self.thinking_text_start, f"Thinking{dots}")
            self.txtAskSydMain.see(tk.END)
        except:
            pass  # If something goes wrong, just stop animating

        # Schedule next animation (every 500ms)
        if self.thinking_active:
            self.after(500, self.animate_thinking)

    def remove_thinking_indicator(self):
        """Remove the 'Syd is thinking...' message"""
        self.thinking_active = False

        try:
            # Delete the thinking message
            if hasattr(self, 'thinking_start'):
                self.txtAskSydMain.delete(self.thinking_start, tk.END)
        except:
            pass  # If something goes wrong, just continue

    def on_analyze_paste(self):
        """Analyze pasted scan results and populate Services + Next Steps"""
        pasted_text = self.txtPasteResults.get("1.0", tk.END).strip()
        if not pasted_text:
            messagebox.showwarning("Analyze", "Please paste scan results first")
            return

        try:
            # Populate Raw Output tab with pasted scan (for Ask Syd context)
            self.txtRawOutput.delete("1.0", tk.END)
            self.txtRawOutput.insert(tk.END, pasted_text)

            # Parse services from nmap output
            services = self.parse_services_from_text(pasted_text)

            # Populate Services tab - separate confirmed from unconfirmed
            self.txtServices.delete("1.0", tk.END)
            if services:
                confirmed = [s for s in services if s.get('state') == 'open']
                unconfirmed = [s for s in services if s.get('state') == 'open|filtered']

                def _csv_field(val):
                    s = "" if val is None else str(val)
                    s = s.replace('"', '""')
                    return f"\"{s}\""

                if confirmed:
                    self.txtServices.insert(tk.END, "=== CONFIRMED OPEN SERVICES ===\n")
                    self.txtServices.insert(tk.END, "Host,Port,Protocol,Service,Product,Version,Extra Info\n")
                    for svc in confirmed:
                        row = ",".join([
                            _csv_field(svc.get('host')),
                            _csv_field(svc.get('port')),
                            _csv_field(svc.get('protocol')),
                            _csv_field(svc.get('service')),
                            _csv_field(svc.get('product')),
                            _csv_field(svc.get('version')),
                            _csv_field(svc.get('extra_info')),
                        ])
                        self.txtServices.insert(tk.END, f"{row}\n")

                if unconfirmed:
                    self.txtServices.insert(tk.END, "\n=== UNCONFIRMED (open|filtered) ===\n")
                    self.txtServices.insert(tk.END, "Host,Port,Protocol,Service\n")
                    for svc in unconfirmed:
                        row = ",".join([
                            _csv_field(svc.get('host')),
                            _csv_field(svc.get('port')),
                            _csv_field(svc.get('protocol')),
                            _csv_field(svc.get('service')),
                        ])
                        self.txtServices.insert(tk.END, f"{row}\n")
            else:
                self.txtServices.insert(tk.END, "No services detected in pasted text.\n")

            # Generate Next Steps (uses its own parser on the full text)
            self.txtNextSteps.delete("1.0", tk.END)
            next_steps = self.generate_next_steps(services)
            self.txtNextSteps.insert(tk.END, next_steps)

            # Extract verified CVE IDs with service context from Next Steps output
            import re as _re_local
            self.verified_cves = set(_re_local.findall(r'CVE-\d{4}-\d{4,7}', next_steps))

            # Build CVE-to-service mapping for Ask Syd context
            # Parses "Service: <product> <version> on <host> port <port>/<proto>" (or old format without host)
            self.cve_service_map = {}
            current_service = "unknown service"
            for line in next_steps.split('\n'):
                # New format: "Service: Apache httpd 2.4.29 on 192.168.1.20 port 80/tcp"
                # Old format: "Service: Apache httpd 2.4.29 on port 80/tcp" (backwards compatible)
                svc_match = _re_local.match(r'\s*Service:\s*\S+\s+(.+?)\s+on\s+(.+?)\s+port\s+(\d+/\w+)', line)
                if svc_match:
                    product_version = svc_match.group(1).strip()
                    host = svc_match.group(2).strip()
                    port = svc_match.group(3)
                    current_service = f"{product_version} on {host} (port {port})"
                else:
                    # Fallback: old format without host
                    svc_match_old = _re_local.match(r'\s*Service:\s*\S+\s+(.+?)\s+on\s+port\s+(\d+/\w+)', line)
                    if svc_match_old:
                        current_service = f"{svc_match_old.group(1).strip()} (port {svc_match_old.group(2)})"

                cve_match = _re_local.search(r'(CVE-\d{4}-\d{4,7})', line)
                if cve_match and 'Service:' not in line:
                    self.cve_service_map[cve_match.group(1)] = current_service

            # Switch to Services tab to show results
            self.tabsResults.select(1)

            confirmed_count = sum(1 for s in services if s.get('state') == 'open')
            unconfirmed_count = sum(1 for s in services if s.get('state') == 'open|filtered')
            messagebox.showinfo("Success", f"Analyzed {len(services)} service(s) ({confirmed_count} confirmed, {unconfirmed_count} unconfirmed)")

        except Exception as e:
            messagebox.showerror("Analysis Error", str(e))
            import traceback
            traceback.print_exc()

    def parse_services_from_text(self, text):
        """Parse services from pasted nmap output"""
        services = []
        current_host = "unknown"
        current_hostname = ""

        for line in text.split('\n'):
            line = line.strip()
            # Match host line: "Nmap scan report for 10.10.10.1"
            if "Nmap scan report for" in line:
                parts = line.split("Nmap scan report for")[-1].strip().split()
                if len(parts) >= 1:
                    current_hostname = parts[0] if len(parts) > 1 and '(' in line else ""
                    current_host = parts[-1].replace('(', '').replace(')', '')

            # Match service line: "22/tcp   open  ssh     OpenSSH 7.2p2"
            match = re.match(r'(\d+)/(tcp|udp)\s+(open(?:\|filtered)?|filtered|closed)\s+(\S+)\s*(.*)', line)
            if match:
                port = match.group(1)
                protocol = match.group(2)
                state = match.group(3)
                service = match.group(4)
                version_info = match.group(5).strip()

                # Filter out nmap reason strings that aren't real version info
                if version_info.lower() in ("no-response", "udp-response", "echo-reply",
                                             "syn-ack", "reset", "conn-refused"):
                    version_info = ""

                # If the "service" token is actually a reason, treat as unknown
                if service.lower() in ("no-response", "reset", "filtered", "unfiltered", "open|filtered"):
                    service = "unknown"

                # Parse version info - FIXED to handle "Apache httpd 2.4.52"
                product = ""
                version = ""
                extra = version_info

                # Special-case VNC protocol banner: "VNC (protocol 3.8)"
                if service.lower() == "vnc" and "protocol" in version_info.lower():
                    ver_match = re.search(r'(\d+(?:\.\d+)*)', version_info)
                    product = "VNC"
                    version = ver_match.group(1) if ver_match else ""
                    extra = ""
                    if state in ("open", "open|filtered"):
                        services.append({
                            'host': current_host,
                            'hostname': current_hostname,
                            'port': port,
                            'protocol': protocol,
                            'state': state,
                            'service': service,
                            'product': product,
                            'version': version,
                            'extra_info': extra
                        })
                    continue

                # Smarter parsing: Find first version-like string (contains digits and dots)
                parts = version_info.split()
                if len(parts) >= 1:
                    version_idx = -1
                    # Find first part that looks like a version (e.g., "2.4.52", "8.9p1")
                    # Must START with a digit - rejects daemon names like "pop3d", "x11vnc"
                    for i, part in enumerate(parts):
                        if not part or not part[0].isdigit():
                            continue
                        # Avoid treating dates/times as versions (e.g., 2026-02-10 or 14:02:10Z)
                        if re.match(r'^\d{4}-\d{2}-\d{2}$', part):
                            continue
                        if re.match(r'^\d{2}:\d{2}:\d{2}Z?[\)\]]?$', part):
                            continue
                        version_idx = i
                        break

                    if version_idx > 0:
                        # Product is everything before version
                        product = " ".join(parts[:version_idx])
                        version = parts[version_idx]
                        extra = " ".join(parts[version_idx+1:]) if len(parts) > version_idx+1 else ""
                    elif len(parts) >= 2 and parts[1][0].isdigit():
                        if re.match(r'^\d{4}-\d{2}-\d{2}$', parts[1]) or re.match(r'^\d{2}:\d{2}:\d{2}Z?[\)\]]?$', parts[1]):
                            # Treat date/time as part of product, not a version
                            product = " ".join(parts)
                            version = ""
                            extra = ""
                        else:
                            # Fallback: first part is product, second is version
                            # Version must START with a digit (e.g. "3.0.3", "8.2p1")
                            # Rejects daemon names like "pop3d", "smtpd" that contain digits mid-word
                            product = parts[0]
                            version = parts[1]
                            extra = " ".join(parts[2:]) if len(parts) > 2 else ""
                    else:
                        # No numeric version found - entire string is product name
                        # e.g. "Linux telnetd", "Dovecot pop3d", "Postfix smtpd"
                        product = " ".join(parts)
                        version = ""
                        extra = ""

                if state in ("open", "open|filtered"):
                    services.append({
                        'host': current_host,
                        'hostname': current_hostname,
                        'port': port,
                        'protocol': protocol,
                        'state': state,
                        'service': service,
                        'product': product,
                        'version': version,
                        'extra_info': extra
                    })

        # If we have confirmed open services for a host/port/proto, drop open|filtered duplicates
        confirmed_keys = {
            (s['host'], s['port'], s['protocol'])
            for s in services if s.get('state') == 'open'
        }
        services = [
            s for s in services
            if not (s.get('state') == 'open|filtered' and (s['host'], s['port'], s['protocol']) in confirmed_keys)
        ]

        return services

    def on_upload(self):
        """Handle Upload button - upload scan results to chat"""
        filepath = filedialog.askopenfilename(
            title="Select scan results to upload",
            filetypes=[("Text files", "*.txt"), ("XML files", "*.xml"), ("All files", "*.*")]
        )

        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                self.txtAskSydMain.insert(tk.END, f"\n[UPLOADED: {os.path.basename(filepath)}]\n")
                self.txtAskSydMain.insert(tk.END, content[:5000])  # Limit to 5000 chars
                if len(content) > 5000:
                    self.txtAskSydMain.insert(tk.END, "\n\n[... truncated ...]")

            except Exception as e:
                messagebox.showerror("Upload Error", str(e))

    def log_to_asksyd(self, message):
        """Helper to log messages to Ask Syd log panel (thread-safe)"""
        def _update():
            self.txtAskSydLog.insert(tk.END, f"{message}\n")
            self.txtAskSydLog.see(tk.END)

        # Schedule GUI update on main thread
        try:
            self.after(0, _update)
        except:
            # Fallback if called before widget fully initialized
            pass

    # Vulnerability pattern dictionary - NO SERVICE NAMES
    VULN_PATTERNS = {
        'NO_AUTH': {
            'patterns': [
                r'(no|missing|empty|without)\s*(auth|password|login|credential)',
                r'authentication:\s*0',
                r'anonymous.*allowed',
                r'authentication.*disabled',
                r'auth.*bypass',
                r'no password required'
            ],
            'score': 10,
            'severity': 'CRITICAL',
            'category': 'Authentication Bypass'
        },
        'UNAUTH_ACCESS': {
            'patterns': [
                r'accessible without (authentication|auth|password|login)',
                r'(public|open)\s*access',
                r'unauthenticated.*access',
                r'stream.*accessible',
                r'(video|camera|feed).*accessible'
            ],
            'score': 10,
            'severity': 'CRITICAL',
            'category': 'Unauthorized Access'
        },
        'CLEARTEXT': {
            'patterns': [
                r'(no|without)\s*encryption',
                r'cleartext',
                r'unencrypted',
                r'plain.*text',
                r'data.*sent.*clear'
            ],
            'score': 7,
            'severity': 'HIGH',
            'category': 'Cleartext Protocol'
        },
        'INFO_LEAK': {
            'patterns': [
                r'\.git/',
                r'\.svn/',
                r'\.env',
                r'config\.(php|xml|json)',
                r'backup.*found',
                r'database.*exposed',
                r'credentials.*found',
                r'sensitive.*file'
            ],
            'score': 8,
            'severity': 'HIGH',
            'category': 'Information Disclosure'
        },
        'RCE_LIKELY': {
            'patterns': [
                r'(script|admin|debug)\s*console.*accessible',
                r'shell.*accessible',
                r'code execution',
                r'command injection',
                r'eval.*enabled'
            ],
            'score': 10,
            'severity': 'CRITICAL',
            'category': 'Remote Code Execution'
        },
        'VULN_STATE': {
            'patterns': [
                r'state:\s*vulnerable',
                r'status:\s*vulnerable',
                r'vulnerable:',
                r'\bvulnerable\b.*exploit'
            ],
            'score': 8,
            'severity': 'HIGH',
            'category': 'Confirmed Vulnerability'
        },
        'SQL_INJECTION': {
            'patterns': [
                r'sql.*injection',
                r'sqlmap.*vulnerable',
                r'sql.*error',
                r'mysql.*error.*syntax',
                r'postgresql.*error',
                r'oracle.*error.*ORA-',
                r'microsoft.*sql.*server.*error',
                r'syntax.*error.*sql'
            ],
            'score': 10,
            'severity': 'CRITICAL',
            'category': 'SQL Injection'
        },
        'XSS': {
            'patterns': [
                r'cross.*site.*scripting',
                r'\bxss\b',
                r'reflected.*xss',
                r'stored.*xss',
                r'dom.*based.*xss',
                r'script.*injection'
            ],
            'score': 8,
            'severity': 'HIGH',
            'category': 'Cross-Site Scripting'
        },
        'DEFAULT_CREDS': {
            'patterns': [
                r'default.*credential',
                r'default.*password',
                r'admin:admin',
                r'root:root',
                r'administrator:password',
                r'tomcat:tomcat',
                r'weak.*credential',
                r'guest.*account.*enabled'
            ],
            'score': 10,
            'severity': 'CRITICAL',
            'category': 'Default Credentials'
        },
        'SMB_VULN': {
            'patterns': [
                r'eternalblue',
                r'ms17-010',
                r'smb.*signing.*disabled',
                r'smb.*null.*session',
                r'smb.*anonymous.*access',
                r'smbv1.*enabled',
                r'smb.*guest.*enabled'
            ],
            'score': 10,
            'severity': 'CRITICAL',
            'category': 'SMB Vulnerability'
        },
        'PATH_TRAVERSAL': {
            'patterns': [
                r'directory.*traversal',
                r'path.*traversal',
                r'\.\./\.\.',
                r'file.*inclusion',
                r'local.*file.*inclusion',
                r'remote.*file.*inclusion',
                r'lfi.*vulnerable',
                r'rfi.*vulnerable'
            ],
            'score': 9,
            'severity': 'CRITICAL',
            'category': 'Path Traversal'
        },
        'XXE': {
            'patterns': [
                r'xml.*external.*entit',
                r'\bxxe\b',
                r'xml.*injection',
                r'soap.*injection',
                r'xml.*vulnerable'
            ],
            'score': 9,
            'severity': 'CRITICAL',
            'category': 'XML External Entity'
        },
        'OUTDATED_SOFTWARE': {
            'patterns': [
                r'end.*of.*life',
                r'unsupported.*version',
                r'outdated.*software',
                r'deprecated.*version',
                r'no.*longer.*maintained',
                r'eol.*version'
            ],
            'score': 7,
            'severity': 'HIGH',
            'category': 'Outdated Software'
        },
        'SSL_VULN': {
            'patterns': [
                r'sslv2',
                r'sslv3',
                r'tlsv1\.0',
                r'heartbleed',
                r'poodle',
                r'beast',
                r'weak.*cipher',
                r'self.*signed.*certificate',
                r'expired.*certificate',
                r'sweet32',
                r'crime.*compression'
            ],
            'score': 8,
            'severity': 'HIGH',
            'category': 'SSL/TLS Vulnerability'
        },
        'OPEN_SHARE': {
            'patterns': [
                r'open.*share',
                r'writable.*share',
                r'directory.*listing.*enabled',
                r'indexes.*enabled',
                r'autoindex.*on',
                r'public.*readable'
            ],
            'score': 7,
            'severity': 'HIGH',
            'category': 'Open Share/Directory'
        },
        'WEAK_AUTH': {
            'patterns': [
                r'basic.*authentication.*http',
                r'ntlm.*authentication',
                r'weak.*hash',
                r'md5.*hash',
                r'sha1.*hash',
                r'no.*rate.*limit',
                r'brute.*force.*possible'
            ],
            'score': 7,
            'severity': 'HIGH',
            'category': 'Weak Authentication'
        }
    }

    def parse_nmap_vulnerabilities(self, nmap_text):
        """Parse Nmap NSE script output with EXPLOIT INTELLIGENCE - considers exploitability"""
        vulnerabilities = []
        total_score = 0

        # Load vulnerability intelligence database
        vuln_intel = self._load_vulnerability_intelligence()

        lines = nmap_text.split('\n')
        current_port = None
        current_service = None
        current_protocol = None
        current_version = None

        for i, line in enumerate(lines):
            # Extract port and service info for context only
            port_match = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?', line)
            if port_match:
                current_port = port_match.group(1)
                current_protocol = port_match.group(2)
                current_service = port_match.group(3)
                current_version = port_match.group(4) if port_match.group(4) else ""

            # Match against ALL vulnerability patterns
            for vuln_type, vuln_config in self.VULN_PATTERNS.items():
                for pattern in vuln_config['patterns']:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Check if there's intelligence for this pattern
                        pattern_intel = vuln_intel.get('vulnerability_patterns', {})
                        intel_key = self._map_vuln_type_to_intel(vuln_type, line)
                        intel = pattern_intel.get(intel_key, {})

                        # Calculate score with intelligence boost
                        base_score = vuln_config['score']
                        priority_boost = intel.get('priority_boost', 0)
                        final_score = base_score + (priority_boost / 10)  # Normalize boost

                        vulnerabilities.append({
                            'type': vuln_type,
                            'severity': vuln_config['severity'],
                            'score': final_score,
                            'base_score': base_score,
                            'priority_boost': priority_boost,
                            'category': vuln_config['category'],
                            'port': current_port,
                            'protocol': current_protocol,
                            'service': current_service,
                            'details': line.strip(),
                            'matched_pattern': pattern,
                            'exploitability': intel.get('exploitability', 'UNKNOWN'),
                            'wormable': intel.get('wormable', False),
                            'metasploit': intel.get('metasploit_module'),
                            'intel_notes': intel.get('notes', '')
                        })
                        total_score += final_score
                        break  # Only match once per line per type

            # CVE pattern with CVSS scoring + INTELLIGENCE LOOKUP
            cve_match = re.search(r'(CVE-\d{4}-\d+)\s+(\d+\.?\d*)', line)
            if cve_match:
                cve_id = cve_match.group(1)
                cvss = float(cve_match.group(2))
                if cvss >= 7.0:
                    # Base score from CVSS
                    base_score = 5 if cvss < 9.0 else 8

                    # CRITICAL: Lookup CVE intelligence
                    cve_intel = vuln_intel.get('cve_intelligence', {}).get(cve_id, {})
                    priority_boost = cve_intel.get('priority_boost', 0)

                    # Calculate final score with intelligence
                    final_score = base_score + (priority_boost / 10)  # Normalize

                    # Override severity for known critical exploits
                    exploitability = cve_intel.get('exploitability', 'UNKNOWN')
                    if exploitability == 'TRIVIAL' or priority_boost >= 85:
                        severity = 'CRITICAL'
                    elif cvss >= 9.0:
                        severity = 'CRITICAL'
                    else:
                        severity = 'HIGH'

                    vulnerabilities.append({
                        'type': 'CVE',
                        'cve_id': cve_id,
                        'cve_name': cve_intel.get('name', cve_id),
                        'severity': severity,
                        'score': final_score,
                        'base_score': base_score,
                        'priority_boost': priority_boost,
                        'category': 'Known CVE',
                        'cvss': cvss,
                        'port': current_port,
                        'protocol': current_protocol,
                        'service': current_service,
                        'details': line.strip(),
                        'exploitability': exploitability,
                        'wormable': cve_intel.get('wormable', False),
                        'metasploit': cve_intel.get('metasploit_module'),
                        'intel_notes': cve_intel.get('notes', '')
                    })
                    total_score += final_score

        return vulnerabilities, total_score

    def _load_vulnerability_intelligence(self):
        """Load vulnerability intelligence database from JSON"""
        import json
        from pathlib import Path

        intel_file = BASE_PATH / "vulnerability_intelligence.json"
        if intel_file.exists():
            try:
                with open(intel_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Could not load vulnerability intelligence: {e}")
                return {}
        return {}

    def _map_vuln_type_to_intel(self, vuln_type, line):
        """Map vulnerability type to intelligence database key"""
        # Map internal vuln types to intelligence keys
        mapping = {
            'NO_AUTH': 'no_password' if 'no password' in line.lower() or 'root:' in line else 'anonymous_ftp' if 'ftp' in line.lower() else 'no_auth_required',
            'DEFAULT_CREDS': 'default_credentials',
            'RCE_LIKELY': 'sql_injection' if 'sql' in line.lower() else 'rce',
            'CLEARTEXT': 'vnc_no_auth' if 'vnc' in line.lower() else 'cleartext',
            'INFO_LEAK': 'exposed_sensitive_files'
        }

        # Check for specific patterns
        if 'xp_cmdshell' in line.lower():
            return 'xp_cmdshell_enabled'
        elif 'anonymous ftp' in line.lower():
            return 'anonymous_ftp'
        elif 'sql' in line.lower() and 'injection' in line.lower():
            return 'sql_injection'
        elif 'vnc' in line.lower() and ('no auth' in line.lower() or 'no encryption' in line.lower()):
            return 'vnc_no_auth'

        return mapping.get(vuln_type, vuln_type.lower())

    # Generic exploit templates - mapped by VULNERABILITY TYPE, not service name
    EXPLOIT_TEMPLATES = {
        'NO_AUTH': {
            'priority': 1,
            'description': 'Service allows connections without authentication',
            'commands': [
                '# Try direct connection (adjust tool based on service)',
                'nc {host} {port}',
                'telnet {host} {port}',
                '# Or use service-specific client without credentials'
            ]
        },
        'UNAUTH_ACCESS': {
            'priority': 1,
            'description': 'Resource accessible without authentication',
            'commands': [
                '# Access the resource directly',
                'curl http://{host}:{port}/{path}',
                'wget http://{host}:{port}/{path}',
                '# For streams: vlc {protocol}://{host}:{port}/{path}'
            ]
        },
        'CLEARTEXT': {
            'priority': 2,
            'description': 'Protocol transmits data in cleartext',
            'commands': [
                '# Intercept traffic',
                'tcpdump -i {interface} -A port {port}',
                'wireshark # Filter: tcp.port == {port}',
                '# Credentials may be visible in packet captures'
            ]
        },
        'INFO_LEAK': {
            'priority': 2,
            'description': 'Exposed sensitive files or directories',
            'commands': [
                'wget -r http://{host}:{port}/{path}',
                'curl http://{host}:{port}/{path}',
                '# For Git: git-dumper http://{host}/.git/ ./dump',
                '# Search extracted files: grep -riE "password|key|secret|token"'
            ]
        },
        'RCE_LIKELY': {
            'priority': 1,
            'description': 'Potential remote code execution vector',
            'commands': [
                '# Navigate to console/admin panel',
                'curl http://{host}:{port}/script',
                'curl http://{host}:{port}/admin',
                '# Attempt command injection or code execution'
            ]
        },
        'VULN_STATE': {
            'priority': 2,
            'description': 'Service confirmed vulnerable by Nmap scripts',
            'commands': [
                '# Search for exploits',
                'searchsploit {service}',
                'msfconsole # search {service} {version}'
            ]
        },
        'CVE': {
            'priority': 2,
            'description': 'Known CVE detected',
            'commands': [
                'searchsploit {cve_id}',
                'msfconsole # search {cve_id}',
                '# Check: https://nvd.nist.gov/vuln/detail/{cve_id}'
            ]
        }
    }

    def generate_next_steps(self, services):
        """Generate next steps using SCORE-BASED prioritization"""
        from rag_engine.nmap_advice import parse_nmap_text, plan_next_steps

        # Get the full pasted text to scan for vulnerabilities
        pasted_text = self.txtPasteResults.get("1.0", tk.END).strip()

        # Parse vulnerabilities using pattern matching
        vulnerabilities, total_score = self.parse_nmap_vulnerabilities(pasted_text)

        # Parse the FULL pasted text for service findings (preserves XML, CPE, extrainfo)
        # This is critical for backporting detection and accurate CVE matching
        service_findings = parse_nmap_text(pasted_text)

        # Determine risk level based on TOTAL SCORE
        if total_score >= 20:
            risk_level = "[CRITICAL] CRITICAL"
        elif total_score >= 10:
            risk_level = "[CRITICAL] HIGH"
        elif total_score >= 5:
            risk_level = "🟡 MEDIUM"
        else:
            risk_level = "🟢 LOW"

        # Generate recommendations
        if service_findings:
            recommendations = plan_next_steps(service_findings, cve_counts=total_score)

            # Build critical section using SCORE-BASED prioritization
            if vulnerabilities:
                # Sort by score descending
                vulnerabilities_sorted = sorted(vulnerabilities, key=lambda v: v['score'], reverse=True)
                critical_section = ["[WARNING]" * 40, "[ALERT] IMMEDIATE ACTION REQUIRED - CRITICAL VULNERABILITIES DETECTED:", "[WARNING]" * 40, ""]

                critical_section.append(f"Total Vulnerability Score: {total_score} | Risk Level: {risk_level}")
                critical_section.append("")

                # DEDUPLICATION: Track unique vulnerabilities in the list too
                seen_vulns = set()

                # List vulnerabilities sorted by score
                for vuln in vulnerabilities_sorted:
                    vuln_type = vuln['type']
                    port = vuln.get('port', 'unknown')
                    service = vuln.get('service', 'unknown')
                    category = vuln.get('category', 'Unknown')
                    severity = vuln.get('severity', 'UNKNOWN')
                    score = vuln.get('score', 0)

                    # Create unique key for vulnerability listing
                    if vuln_type == 'CVE':
                        vuln_key = f"{vuln.get('cve_id')}|{service}|{port}"
                    else:
                        vuln_key = f"{category}|{service}|{port}"

                    # Skip duplicates in vulnerability list
                    if vuln_key in seen_vulns:
                        continue
                    seen_vulns.add(vuln_key)

                    # Build vulnerability line with intelligence
                    exploitability = vuln.get('exploitability', 'UNKNOWN')
                    wormable = vuln.get('wormable', False)
                    metasploit = vuln.get('metasploit')

                    # Priority indicators
                    indicators = []
                    if exploitability == 'TRIVIAL':
                        indicators.append('🔥TRIVIAL EXPLOIT')
                    elif exploitability == 'EASY':
                        indicators.append('⚡EASY')
                    if wormable:
                        indicators.append('🦠WORMABLE')
                    if metasploit:
                        indicators.append('🎯MSF')

                    indicator_str = f" [{' | '.join(indicators)}]" if indicators else ""

                    if vuln_type == 'CVE':
                        cve_name = vuln.get('cve_name', vuln.get('cve_id'))
                        critical_section.append(f"[Score: {score:.1f}] {severity} - {cve_name} on {service}:{port} (CVSS: {vuln.get('cvss', 'N/A')}){indicator_str}")
                    else:
                        critical_section.append(f"[Score: {score:.1f}] {severity} - {category} on {service}:{port}{indicator_str}")

                critical_section.append("")
                critical_section.append("💥 **RECOMMENDED EXPLOITS (Prioritized by Score):**")
                critical_section.append("")

                # DEDUPLICATION: Track unique vuln+service+port combinations
                seen_exploits = set()

                # Generate exploits using GENERIC TEMPLATES (NO service name checks)
                for vuln in vulnerabilities_sorted:
                    vuln_type = vuln['type']
                    template = self.EXPLOIT_TEMPLATES.get(vuln_type)

                    if not template:
                        continue  # Skip if no template defined

                    port = vuln.get('port', 'unknown')
                    service = vuln.get('service', 'unknown')
                    category = vuln.get('category', 'Unknown')

                    # Create unique key for deduplication
                    exploit_key = f"{vuln_type}|{service}|{port}|{category}"

                    # Skip if we've already shown this exact exploit
                    if exploit_key in seen_exploits:
                        continue
                    seen_exploits.add(exploit_key)

                    # Add intelligence indicators to exploit section
                    exploitability = vuln.get('exploitability', '')
                    wormable = vuln.get('wormable', False)
                    metasploit = vuln.get('metasploit')
                    intel_notes = vuln.get('intel_notes', '')

                    # Build header with indicators
                    header = f"**[{category}] {service.upper()}:{port}**"
                    if exploitability:
                        header += f" [Exploitability: {exploitability}]"
                    if wormable:
                        header += " [🦠 WORMABLE]"

                    critical_section.append(header)
                    critical_section.append(f"   {template['description']}")

                    # Add intelligence notes if available
                    if intel_notes:
                        critical_section.append(f"   ℹ️  {intel_notes}")

                    critical_section.append("   ```bash")

                    # Add Metasploit module if available
                    if metasploit:
                        critical_section.append(f"   # Metasploit module available:")
                        critical_section.append(f"   msfconsole")
                        critical_section.append(f"   use {metasploit}")
                        critical_section.append(f"   set RHOSTS <target>")
                        critical_section.append(f"   set RPORT {port}")
                        critical_section.append(f"   exploit")
                        critical_section.append("")

                    for cmd in template['commands']:
                        # Replace placeholders
                        cmd_formatted = cmd.replace('{host}', '<target>').replace('{port}', str(port))
                        if vuln_type == 'CVE':
                            cmd_formatted = cmd_formatted.replace('{cve_id}', vuln.get('cve_id', ''))
                        cmd_formatted = cmd_formatted.replace('{service}', service)
                        cmd_formatted = cmd_formatted.replace('{protocol}', vuln.get('protocol', 'tcp'))
                        cmd_formatted = cmd_formatted.replace('{path}', '')
                        cmd_formatted = cmd_formatted.replace('{interface}', 'eth0')

                        critical_section.append(f"   {cmd_formatted}")

                    critical_section.append("   ```")
                    critical_section.append("")

                critical_section.append("[WARNING]" * 40)
                critical_section.append("")

                return "\n".join(critical_section + recommendations)

            return "\n".join(recommendations)
        else:
            return "No services to analyze."


class VolatilityPage(ttk.Frame):
    """Volatility 3 Memory Forensics Interface with tabbed output"""

    def __init__(self, parent):
        super().__init__(parent)

        # State
        self.dump_path = tk.StringVar()
        self.current_process = None

        # Auto-analyze state
        self.auto_analyze_running = False
        self.auto_analyze_results = {}  # Store results from all plugins
        self.auto_analyze_progress = tk.StringVar(value="")

        # RAG components for Ask Syd
        self.embed_model = None
        self.llm = None
        self.faiss_index = None
        self.chunks = None
        self.rag_ready = False

        # Layout: Two columns (Left: Tool, Right: Ask Syd)
        main_paned = ttk.PanedWindow(self, orient="horizontal")
        main_paned.pack(fill="both", expand=True)

        left_frame = ttk.Frame(main_paned)
        right_frame = ttk.Frame(main_paned)
        main_paned.add(left_frame, weight=3)
        main_paned.add(right_frame, weight=2)

        # Controls section
        controls_frame = ttk.Frame(left_frame)
        controls_frame.pack(fill="x", padx=5, pady=5)

        ttk.Label(controls_frame, text="Volatility 3 - Memory Forensics", style="Header.TLabel").pack(anchor="w", pady=(0,10))

        # Path configuration
        path_frame = ttk.Frame(controls_frame)
        path_frame.pack(fill="x", pady=(0,8))
        ttk.Label(path_frame, text="Vol.py Path:").pack(side="left", padx=5)

        # Auto-detect vol.py in Syd directory
        import os
        default_vol_path = os.path.join(str(BASE_PATH), "vol.py")
        if not os.path.exists(default_vol_path):
            default_vol_path = ""

        self.vol_path = tk.StringVar(value=default_vol_path)
        path_entry = ttk.Entry(path_frame, textvariable=self.vol_path, width=35)
        path_entry.pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(path_frame, text="Browse", command=self._browse_vol_path).pack(side="left", padx=2)
        ttk.Button(path_frame, text="Test", command=self._test_vol).pack(side="left")

        # Memory dump selector
        dump_frame = ttk.Frame(controls_frame)
        dump_frame.pack(fill="x", pady=(0,8))
        ttk.Label(dump_frame, text="Memory Dump:").pack(side="left", padx=5)
        dump_entry = ttk.Entry(dump_frame, textvariable=self.dump_path, width=40)
        dump_entry.pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(dump_frame, text="Browse", command=self._browse_dump).pack(side="left")

        # Plugin selector
        plugin_frame = ttk.Frame(controls_frame)
        plugin_frame.pack(fill="x", pady=(0,8))
        ttk.Label(plugin_frame, text="Plugin:").pack(side="left", padx=5)

        self.plugin_var = tk.StringVar(value="windows.pslist.PsList")
        plugins = [
            "--- Windows Plugins ---",
            "windows.pslist.PsList",
            "windows.pstree.PsTree",
            "windows.psscan.PsScan",
            "windows.netscan.NetScan",
            "windows.malfind.Malfind",
            "windows.filescan.FileScan",
            "windows.dlllist.DllList",
            "windows.hashdump.Hashdump",
            "windows.cmdline.CmdLine",
            "windows.handles.Handles",
            "--- Linux Plugins (Need Symbols) ---",
            "linux.pslist.PsList",
            "linux.pstree.PsTree",
            "linux.lsof.Lsof",
            "linux.malfind.Malfind",
            "--- Linux Plugins (No Symbols) ---",
            "linux.bash.Bash",
            "linux.psaux.PsAux",
            "banners.Banners",
            "--- Mac Plugins ---",
            "mac.pslist.PsList",
            "mac.pstree.PsTree",
            "mac.bash.Bash",
            "mac.lsof.Lsof"
        ]
        plugin_dropdown = ttk.Combobox(plugin_frame, textvariable=self.plugin_var, values=plugins, width=30)
        plugin_dropdown.pack(side="left", padx=5)

        ttk.Button(plugin_frame, text="Run Plugin", command=self._run_plugin).pack(side="left", padx=5)
        ttk.Button(plugin_frame, text="Stop", command=self._stop_process).pack(side="left")

        # Auto-analyze buttons
        auto_frame = ttk.Frame(controls_frame)
        auto_frame.pack(fill="x", pady=(8,0))
        ttk.Label(auto_frame, text="Quick Analysis:", font=("Segoe UI", 9, "bold")).pack(side="left", padx=5)
        ttk.Button(auto_frame, text="🖥️ Analyze Windows Memory", command=self._auto_analyze_windows, style="Accent.TButton").pack(side="left", padx=5)
        ttk.Button(auto_frame, text="🐧 Analyze Linux Memory", command=self._auto_analyze_linux, style="Accent.TButton").pack(side="left", padx=5)

        # Progress indicator
        progress_frame = ttk.Frame(controls_frame)
        progress_frame.pack(fill="x", pady=(5,0))
        self.lbl_progress = ttk.Label(progress_frame, textvariable=self.auto_analyze_progress, foreground=ACCENT, font=("Segoe UI", 9, "italic"))
        self.lbl_progress.pack(side="left", padx=5)

        # Tabbed results area
        results_frame = ttk.Frame(left_frame)
        results_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.tabs_results = ttk.Notebook(results_frame)
        self.tabs_results.pack(fill="both", expand=True)

        # Tab 1: Raw Output
        raw_tab = ttk.Frame(self.tabs_results)
        self.txt_raw = tk.Text(raw_tab, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word", font=("Consolas", 9))
        scroll_raw = ttk.Scrollbar(raw_tab, command=self.txt_raw.yview)
        self.txt_raw.configure(yscrollcommand=scroll_raw.set)
        self.txt_raw.pack(side="left", fill="both", expand=True)
        scroll_raw.pack(side="right", fill="y")
        self.tabs_results.add(raw_tab, text="Raw Output")

        # Tab 2: Parsed Results
        parsed_tab = ttk.Frame(self.tabs_results)

        # Add "Copy All" button at top
        parsed_header = ttk.Frame(parsed_tab)
        parsed_header.pack(fill="x", padx=5, pady=5)
        ttk.Button(parsed_header, text="Copy All Processes", command=self._copy_all_processes).pack(side="right")

        columns = ("PID", "Process", "PPID", "Threads", "Handles", "Details")
        self.tree_results = ttk.Treeview(parsed_tab, columns=columns, show="headings")
        for col in columns:
            self.tree_results.heading(col, text=col)
            self.tree_results.column(col, width=100)
        scroll_tree = ttk.Scrollbar(parsed_tab, command=self.tree_results.yview)
        self.tree_results.configure(yscrollcommand=scroll_tree.set)
        self.tree_results.pack(side="left", fill="both", expand=True)
        scroll_tree.pack(side="right", fill="y")
        self.tabs_results.add(parsed_tab, text="Parsed Results")

        # Tab 3: Next Steps
        nextsteps_tab = ttk.Frame(self.tabs_results)
        self.txt_nextsteps = tk.Text(nextsteps_tab, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word", font=("Consolas", 9))
        scroll_nextsteps = ttk.Scrollbar(nextsteps_tab, command=self.txt_nextsteps.yview)
        self.txt_nextsteps.configure(yscrollcommand=scroll_nextsteps.set)
        self.txt_nextsteps.pack(side="left", fill="both", expand=True)
        scroll_nextsteps.pack(side="right", fill="y")
        self.tabs_results.add(nextsteps_tab, text="Next Steps")

        # Tab 4: Paste Results
        paste_tab = ttk.Frame(self.tabs_results)
        self.txt_paste = tk.Text(paste_tab, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word", font=("Consolas", 9))
        scroll_paste = ttk.Scrollbar(paste_tab, command=self.txt_paste.yview)
        self.txt_paste.configure(yscrollcommand=scroll_paste.set)
        self.txt_paste.pack(side="left", fill="both", expand=True)
        scroll_paste.pack(side="right", fill="y")

        paste_btn_frame = ttk.Frame(paste_tab)
        paste_btn_frame.pack(fill="x", side="bottom", padx=5, pady=5)
        ttk.Button(paste_btn_frame, text="Analyze Pasted Results", command=self._analyze_paste).pack(side="right")

        self.tabs_results.add(paste_tab, text="Paste Results")

        # ========== RIGHT COLUMN (Ask Syd Panel) ==========
        # Header bar
        header = ttk.Frame(right_frame)
        header.pack(fill="x", padx=5, pady=5)

        title_row = ttk.Frame(header)
        title_row.pack(fill="x")
        ttk.Label(title_row, text="Ask Syd - Memory Forensics Expert", style="Header.TLabel").pack(side="left")
        badge = ttk.Label(title_row, text="Fresh Context", background=ACCENT, foreground="#fff", padding=(5,2))
        badge.pack(side="left", padx=10)

        controls_row = ttk.Frame(header)
        controls_row.pack(fill="x", pady=(5,0))
        ttk.Label(controls_row, text="Tool:").pack(side="left", padx=5)
        self.cmb_tool = ttk.Combobox(controls_row, values=["Volatility3"], state="readonly", width=12)
        self.cmb_tool.current(0)
        self.cmb_tool.pack(side="left", padx=5)

        source_row = ttk.Frame(header)
        source_row.pack(fill="x", pady=(5,0))
        ttk.Label(source_row, text="Source:").pack(side="left", padx=5)
        self.var_source = tk.StringVar(value="Syd")
        ttk.Radiobutton(source_row, text="Syd", variable=self.var_source, value="Syd").pack(side="left", padx=5)
        ttk.Radiobutton(source_row, text="Customer", variable=self.var_source, value="Customer").pack(side="left", padx=5)

        # Main chat region
        chat_frame = ttk.Frame(right_frame)
        chat_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.txt_chat = tk.Text(chat_frame, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word", height=20)
        scroll_chat = ttk.Scrollbar(chat_frame, command=self.txt_chat.yview)
        self.txt_chat.configure(yscrollcommand=scroll_chat.set)
        self.txt_chat.pack(side="left", fill="both", expand=True)
        scroll_chat.pack(side="right", fill="y")

        # Lower split panel (logs/secondary)
        log_frame = ttk.Frame(right_frame)
        log_frame.pack(fill="both", expand=False, padx=5, pady=5)

        self.txt_log = tk.Text(log_frame, bg=BG_DARK, fg=INK_SOFT, insertbackground=INK, wrap="word", height=6)
        scroll_log = ttk.Scrollbar(log_frame, command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=scroll_log.set)
        self.txt_log.pack(side="left", fill="both", expand=True)
        scroll_log.pack(side="right", fill="y")

        # Input field for questions - multiline text widget
        input_frame = ttk.Frame(right_frame)
        input_frame.pack(fill="both", expand=False, padx=5, pady=(5,0))

        self.entry_question = tk.Text(input_frame, height=3, bg=BG_DARK, fg=INK,
                                     insertbackground=INK, wrap="word", font=('Consolas', 10))
        self.entry_question.pack(fill="both", expand=True)
        self.entry_question.bind('<Control-Return>', lambda e: self._send_to_syd())

        # Bottom buttons
        bottom_btns = ttk.Frame(right_frame)
        bottom_btns.pack(fill="x", padx=5, pady=5)
        ttk.Button(bottom_btns, text="Send (Ctrl+Enter)", command=self._send_to_syd).pack(side="left", padx=5)
        ttk.Button(bottom_btns, text="Clear Chat", command=self._clear_chat_and_output).pack(side="left", padx=5)
        ttk.Button(bottom_btns, text="Upload data...", command=self._upload_data).pack(side="left", padx=5)

        # Add right-click context menus for copy/paste
        self._create_context_menu(self.txt_raw)
        self._create_context_menu(self.txt_nextsteps)
        self._create_context_menu(self.txt_paste)
        self._create_context_menu(self.txt_chat)
        self._create_context_menu(self.txt_log)
        self._create_context_menu(self.entry_question)

        # Initialize RAG in background
        import threading
        threading.Thread(target=self._initialize_rag, daemon=True).start()

    def _browse_vol_path(self):
        """Browse for vol.py file"""
        from tkinter import filedialog
        filename = filedialog.askopenfilename(
            title="Select vol.py",
            filetypes=[("Python Scripts", "vol.py *.py"), ("All Files", "*.*")]
        )
        if filename:
            self.vol_path.set(filename)
            self.log_to_asksyd(f"Volatility path set to: {filename}")

    def _test_vol(self):
        """Test Volatility 3 installation"""
        vol_path = self.vol_path.get().strip()

        if not vol_path:
            from tkinter import messagebox
            messagebox.showwarning("No Path", "Please set the vol.py path first or leave blank to auto-detect")
            return

        try:
            import subprocess
            import sys

            if vol_path:
                # Test with configured path
                python_exe = sys.executable
                result = subprocess.run(
                    [python_exe, vol_path, "--help"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            else:
                # Test auto-detect
                python_exe = sys.executable
                result = subprocess.run(
                    [python_exe, "-m", "volatility3.cli", "--help"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

            output = result.stdout + result.stderr

            if result.returncode == 0 and "Volatility" in output:
                self.log_to_asksyd(f"[OK] Volatility 3 test successful\n\n{output[:200]}")
                from tkinter import messagebox
                messagebox.showinfo("Test Successful", "Volatility 3 is working correctly!")
            else:
                self.log_to_asksyd(f"[ERROR] Volatility 3 test failed\n\n{output}")
                from tkinter import messagebox
                messagebox.showerror("Test Failed", f"Volatility 3 test failed.\n\n{output[:300]}")

        except FileNotFoundError:
            msg = "Python not found or vol.py path is incorrect."
            self.log_to_asksyd(f"[ERROR] {msg}")
            from tkinter import messagebox
            messagebox.showerror("Test Error", msg)
        except Exception as e:
            self.log_to_asksyd(f"[ERROR] Error: {str(e)}")
            from tkinter import messagebox
            messagebox.showerror("Test Error", str(e))

    def _browse_dump(self):
        """Browse for memory dump file"""
        from tkinter import filedialog
        filename = filedialog.askopenfilename(
            title="Select Memory Dump",
            filetypes=[("Memory Dumps", "*.mem *.raw *.dmp *.vmem *.bin *.elf"), ("All Files", "*.*")]
        )
        if filename:
            self.dump_path.set(filename)

    def _run_plugin(self):
        """Run selected Volatility plugin"""
        dump = self.dump_path.get().strip()
        if not dump:
            from tkinter import messagebox
            messagebox.showwarning("No Dump", "Please select a memory dump file first")
            return

        plugin = self.plugin_var.get()

        self.txt_raw.delete("1.0", "end")
        self.txt_raw.insert("end", f"Running {plugin} on {dump}...\n\n")

        def run_in_thread():
            try:
                import subprocess
                import os

                # Check if file exists
                if not os.path.exists(dump):
                    self.after(0, lambda: self.txt_raw.insert("end", f"ERROR: File not found: {dump}\n"))
                    return

                # Check for Linux/ELF files and suggest correct plugins
                if dump.lower().endswith('.elf') and plugin.startswith('windows.'):
                    self.after(0, lambda: self.txt_raw.insert("end", "\n[WARNING] ELF file detected but using Windows plugin!\n"))
                    self.after(0, lambda: self.txt_raw.insert("end", "For Linux memory dumps, use plugins like:\n"))
                    self.after(0, lambda: self.txt_raw.insert("end", "   - linux.pslist.PsList\n"))
                    self.after(0, lambda: self.txt_raw.insert("end", "   - linux.bash.Bash\n"))
                    self.after(0, lambda: self.txt_raw.insert("end", "   - linux.lsof.Lsof\n\n"))

                # Get configured vol.py path or use auto-detection
                import sys
                python_exe = sys.executable
                vol_path = self.vol_path.get().strip()

                # CRITICAL: Validate vol_path is actually a Python script, not a memory dump
                if vol_path and os.path.exists(vol_path):
                    # Check if user accidentally set memory dump as vol.py path
                    vol_path_lower = vol_path.lower()
                    if (vol_path_lower.endswith(('.mem', '.raw', '.dmp', '.vmem', '.bin', '.elf', '.lime')) or
                        'memdump' in vol_path_lower or 'memory' in vol_path_lower):
                        self.after(0, lambda: self.txt_raw.insert("end", "\n" + "="*80 + "\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "[ERROR] INCORRECT FILE SELECTED FOR VOL.PY PATH\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "="*80 + "\n\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", f"You selected: {vol_path}\n\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "This appears to be a MEMORY DUMP file, not vol.py!\n\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "SOLUTION:\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "1. Use the 'Browse' button next to 'Memory Dump:' (NOT 'Vol.py Path:')\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", f"2. Select your memory dump: {os.path.basename(vol_path)}\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "3. Leave 'Vol.py Path:' EMPTY or point it to vol.py\n\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "Vol.py locations:\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "   - Download from: https://github.com/volatilityfoundation/volatility3\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "   - Or leave empty to auto-detect (uses: python -m volatility3.cli)\n"))
                        return

                    # Validate it's actually a .py file
                    if not vol_path_lower.endswith('.py'):
                        self.after(0, lambda: self.txt_raw.insert("end", f"\n[WARNING] Vol.py path doesn't end with .py: {vol_path}\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "Attempting to use it anyway, but this may fail.\n\n"))

                    # Use configured vol.py path
                    vol_cmd = f'"{python_exe}" "{vol_path}"'
                else:
                    # Auto-detection: Try multiple methods to find Volatility 3
                    # Method 1: Try global 'vol' command
                    # Method 2: Try python -m volatility3.vol
                    # Method 3: Try python -m volatility3.cli
                    # Method 4: Search for vol.py in common locations

                    vol_cmd = None

                    # Try Method 1: Global 'vol' command (pip installed)
                    try:
                        import shutil
                        if shutil.which('vol'):
                            vol_cmd = 'vol'
                            self.after(0, lambda: self.txt_raw.insert("end", "[AUTO-DETECT] Using global 'vol' command\n\n"))
                    except:
                        pass

                    # Try Method 2: Python module volatility3.vol
                    if not vol_cmd:
                        try:
                            import importlib.util
                            if importlib.util.find_spec('volatility3.vol'):
                                vol_cmd = f'"{python_exe}" -m volatility3.vol'
                                self.after(0, lambda: self.txt_raw.insert("end", "[AUTO-DETECT] Using python -m volatility3.vol\n\n"))
                        except:
                            pass

                    # Try Method 3: Search for vol.py in common locations
                    if not vol_cmd:
                        import glob
                        search_paths = [
                            os.path.join(str(BASE_PATH), "vol.py"),
                            os.path.join(str(BASE_PATH), "volatility3", "vol.py"),
                            os.path.expanduser("~/volatility3/vol.py"),
                            "C:/volatility3/vol.py",
                            os.path.join(os.environ.get('USERPROFILE', ''), "Downloads", "volatility3", "vol.py"),
                        ]

                        # Also search in Python site-packages
                        try:
                            import site
                            for site_dir in site.getsitepackages():
                                search_paths.append(os.path.join(site_dir, "volatility3", "vol.py"))
                        except:
                            pass

                        for path in search_paths:
                            if os.path.exists(path):
                                vol_cmd = f'"{python_exe}" "{path}"'
                                self.after(0, lambda p=path: self.txt_raw.insert("end", f"[AUTO-DETECT] Found vol.py at: {p}\n\n"))
                                break

                    # Fallback: Try python -m volatility3.cli (may fail with __main__ error)
                    if not vol_cmd:
                        vol_cmd = f'"{python_exe}" -m volatility3.cli'
                        self.after(0, lambda: self.txt_raw.insert("end", "[AUTO-DETECT] Trying python -m volatility3.cli (may fail)\n\n"))

                # Build command as a list to avoid shell injection
                # Parse vol_cmd (which may contain quoted paths) into a proper list
                import shlex
                try:
                    cmd_list = shlex.split(vol_cmd, posix=False)
                except ValueError:
                    cmd_list = vol_cmd.replace('"', '').split()
                cmd_list.extend(['-f', str(dump), plugin])

                cmd_display = ' '.join(f'"{c}"' if ' ' in c else c for c in cmd_list)
                self.after(0, lambda d=cmd_display: self.txt_raw.insert("end", f"Command: {d}\n\n"))

                # Run process and capture output (shell=False for security)
                self.current_process = subprocess.Popen(
                    cmd_list,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=False,
                    errors='replace'  # Replace invalid unicode characters
                )

                # Use communicate() to avoid deadlocks and hanging
                try:
                    stdout_output, stderr_output = self.current_process.communicate(timeout=300)  # 5 minute timeout

                    # Display formatted output
                    if stdout_output:
                        formatted_output = self._format_volatility_output(stdout_output, plugin)
                        self.after(0, lambda out=formatted_output: self.txt_raw.insert("end", out))
                        self.after(0, lambda: self.txt_raw.see("end"))

                except subprocess.TimeoutExpired:
                    self.current_process.kill()
                    stdout_output, stderr_output = self.current_process.communicate()
                    self.after(0, lambda: self.txt_raw.insert("end", "\n[ERROR] Process timed out after 5 minutes\n"))
                    if stdout_output:
                        self.after(0, lambda out=stdout_output: self.txt_raw.insert("end", out))
                    if stderr_output:
                        stderr_output += "\n[Process killed due to timeout]"

                # Capture return code before clearing current_process (with null check for race conditions)
                if self.current_process:
                    return_code = self.current_process.returncode
                else:
                    return_code = 1  # Assume error if process became None

                # Show stderr if any
                if stderr_output:
                    self.after(0, lambda s=stderr_output: self.txt_raw.insert("end", f"\n[STDERR]:\n{s}\n"))

                if return_code == 0:
                    self.after(0, lambda: self.txt_raw.insert("end", "\n[SUCCESS] Completed successfully\n"))
                    # Auto-parse results
                    self.after(0, self._auto_parse_output)
                else:
                    self.after(0, lambda rc=return_code: self.txt_raw.insert("end", f"\n[ERROR] Process exited with code {rc}\n"))

                    # Check for specific error types and provide helpful messages
                    if "symbol_table_name" in stdout_output or "symbol_table_name" in stderr_output:
                        # Missing Linux kernel symbols
                        self.after(0, lambda: self.txt_raw.insert("end", "\n" + "="*80 + "\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "[ISSUE] MISSING LINUX KERNEL SYMBOLS\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "="*80 + "\n\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "The memory dump requires Linux kernel symbol files.\n\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "SOLUTION - Download Symbols:\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "1. Identify kernel version from dump:\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", f'   python vol.py -f "{dump}" banners.Banners\n\n'))
                        self.after(0, lambda: self.txt_raw.insert("end", "2. Download symbols from Volatility:\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "   https://github.com/volatilityfoundation/volatility3#symbol-tables\n\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "3. Place symbols in:\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "   volatility3/symbols/linux/\n\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "ALTERNATIVE - Use banner scanning (slower but works without symbols):\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", f'   python vol.py -f "{dump}" linux.bash.Bash\n'))
                        self.after(0, lambda: self.txt_raw.insert("end", f'   python vol.py -f "{dump}" linux.psaux.PsAux\n\n'))

                        # Also show in Next Steps tab
                        self.after(0, lambda: self._show_symbol_error_in_nextsteps(dump))

                    elif return_code == 1 and stderr_output and ("not recognized" in stderr_output or "No module named" in stderr_output):
                        self.after(0, lambda: self.txt_raw.insert("end", "\n[FIX] Download vol.py:\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "   1. Download: https://github.com/volatilityfoundation/volatility3\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "   2. Extract the ZIP file\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "   3. Find vol.py in the extracted folder\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "   4. Click 'Browse' and select vol.py\n"))
                        self.after(0, lambda: self.txt_raw.insert("end", "   5. Click 'Test' to verify it works\n"))

            except FileNotFoundError:
                self.after(0, lambda: self.txt_raw.insert("end", "\nERROR: Volatility 3 (vol3) not found in PATH.\n"))
                self.after(0, lambda: self.txt_raw.insert("end", "Please install: pip install volatility3\n"))
            except Exception as e:
                import traceback
                error_msg = f"\nERROR: {str(e)}\n{traceback.format_exc()}\n"
                self.after(0, lambda msg=error_msg: self.txt_raw.insert("end", msg))
            finally:
                self.current_process = None

        import threading
        threading.Thread(target=run_in_thread, daemon=True).start()

    def _format_volatility_output(self, output: str, plugin: str) -> str:
        """
        Format Volatility output for better readability
        Handles different plugin types with appropriate formatting
        """
        lines = output.split('\n')
        formatted_lines = []

        # Remove progress lines (they clutter the output)
        lines = [line for line in lines if not line.strip().startswith('Progress:')]

        # Detect plugin type
        plugin_lower = plugin.lower()
        is_pstree = 'pstree' in plugin_lower
        is_pslist = 'pslist' in plugin_lower and not is_pstree
        is_netscan = 'netscan' in plugin_lower or 'netstat' in plugin_lower
        is_malfind = 'malfind' in plugin_lower
        is_cmdline = 'cmdline' in plugin_lower
        is_dlllist = 'dlllist' in plugin_lower

        # Add formatted header
        formatted_lines.append("=" * 80)
        formatted_lines.append(f"VOLATILITY OUTPUT: {plugin}")
        formatted_lines.append("=" * 80)
        formatted_lines.append("")

        if is_pstree:
            # Format process tree with better indentation
            formatted_lines.append("[PROCESS TREE]")
            formatted_lines.append("-" * 80)
            formatted_lines.append("")

            header_found = False
            for line in lines:
                # Skip Volatility version line
                if 'Volatility 3 Framework' in line:
                    continue

                # Detect header line
                if 'PID' in line and 'PPID' in line and 'ImageFileName' in line:
                    header_found = True
                    formatted_lines.append(line)
                    formatted_lines.append("-" * 80)
                    continue

                if header_found and line.strip():
                    # Count asterisks for indentation level
                    asterisk_count = len(line) - len(line.lstrip('*'))
                    if asterisk_count > 0:
                        # Process tree entry with indentation
                        clean_line = line.lstrip('*').strip()
                        indent = "  " * asterisk_count
                        formatted_lines.append(f"{indent}└─ {clean_line}")
                    elif line.strip() and not line.startswith(' '):
                        # Root process (no asterisks)
                        formatted_lines.append(f"• {line.strip()}")

        elif is_pslist:
            # Format process list as table
            formatted_lines.append("[PROCESS LIST]")
            formatted_lines.append("-" * 80)
            formatted_lines.append("")

            header_found = False
            for line in lines:
                if 'Volatility 3 Framework' in line:
                    continue

                if 'PID' in line and 'PPID' in line:
                    header_found = True
                    formatted_lines.append(line)
                    formatted_lines.append("-" * 80)
                    continue

                if header_found and line.strip():
                    formatted_lines.append(line)

        elif is_netscan:
            # Group network connections by state
            formatted_lines.append("[NETWORK CONNECTIONS]")
            formatted_lines.append("-" * 80)
            formatted_lines.append("")

            established = []
            listening = []
            other = []
            header_line = ""

            header_found = False
            for line in lines:
                if 'Volatility 3 Framework' in line:
                    continue

                if 'Offset' in line and 'Proto' in line:
                    header_found = True
                    header_line = line
                    continue

                if header_found and line.strip():
                    if 'ESTABLISHED' in line:
                        established.append(line)
                    elif 'LISTENING' in line or 'LISTEN' in line:
                        listening.append(line)
                    else:
                        other.append(line)

            if established:
                formatted_lines.append(f"[ESTABLISHED CONNECTIONS: {len(established)}]")
                formatted_lines.append(header_line)
                formatted_lines.append("-" * 80)
                for conn in established[:20]:  # Limit to 20
                    formatted_lines.append(conn)
                if len(established) > 20:
                    formatted_lines.append(f"... and {len(established) - 20} more ESTABLISHED connections")
                formatted_lines.append("")

            if listening:
                formatted_lines.append(f"[LISTENING PORTS: {len(listening)}]")
                formatted_lines.append(header_line)
                formatted_lines.append("-" * 80)
                for conn in listening[:20]:  # Limit to 20
                    formatted_lines.append(conn)
                if len(listening) > 20:
                    formatted_lines.append(f"... and {len(listening) - 20} more LISTENING ports")
                formatted_lines.append("")

            if other:
                formatted_lines.append(f"[OTHER STATES: {len(other)}]")
                formatted_lines.append(header_line)
                formatted_lines.append("-" * 80)
                for conn in other[:10]:
                    formatted_lines.append(conn)
                if len(other) > 10:
                    formatted_lines.append(f"... and {len(other) - 10} more connections")

        elif is_malfind:
            # Highlight RWX memory regions
            formatted_lines.append("[CODE INJECTION SCAN - MALFIND]")
            formatted_lines.append("-" * 80)
            formatted_lines.append("")

            for line in lines:
                if 'Volatility 3 Framework' in line:
                    continue

                # Highlight RWX memory
                if 'PAGE_EXECUTE_READWRITE' in line or 'RWX' in line:
                    formatted_lines.append(f"[!] {line}")
                elif 'MZ' in line and '0x' in line:  # PE header in memory
                    formatted_lines.append(f"[!!] {line}")
                else:
                    formatted_lines.append(line)

        elif is_cmdline:
            # Format command lines
            formatted_lines.append("[COMMAND LINES]")
            formatted_lines.append("-" * 80)
            formatted_lines.append("")

            for line in lines:
                if 'Volatility 3 Framework' in line:
                    continue
                formatted_lines.append(line)

        elif is_dlllist:
            # Format DLL list
            formatted_lines.append("[DLL LIST]")
            formatted_lines.append("-" * 80)
            formatted_lines.append("")

            for line in lines:
                if 'Volatility 3 Framework' in line:
                    continue
                formatted_lines.append(line)

        else:
            # Generic formatting for unknown plugins
            formatted_lines.append("[PLUGIN OUTPUT]")
            formatted_lines.append("-" * 80)
            formatted_lines.append("")

            for line in lines:
                if 'Volatility 3 Framework' in line:
                    continue
                if line.strip():
                    formatted_lines.append(line)

        # Add footer
        formatted_lines.append("")
        formatted_lines.append("=" * 80)
        formatted_lines.append("[END OF OUTPUT]")
        formatted_lines.append("=" * 80)
        formatted_lines.append("")

        return '\n'.join(formatted_lines)

    def _auto_parse_output(self):
        """Automatically parse output after plugin runs"""
        output = self.txt_raw.get("1.0", "end")
        self._parse_and_display(output)

    def _show_symbol_error_in_nextsteps(self, dump):
        """Display Linux symbol error help in Next Steps tab"""
        help_text = f"""
================================================================================
LINUX KERNEL SYMBOLS REQUIRED
================================================================================

The memory dump needs Linux kernel symbol files to be analyzed.

QUICK FIX - Try These Plugins (No symbols needed):
================================================================================
These plugins work without symbols by scanning for patterns:

1. linux.bash.Bash - Extract bash command history
   Command: python vol.py -f "{dump}" linux.bash.Bash

2. linux.psaux.PsAux - Process list (slower, scans memory)
   Command: python vol.py -f "{dump}" linux.psaux.PsAux

3. banners.Banners - Find kernel version and system info
   Command: python vol.py -f "{dump}" banners.Banners


PERMANENT FIX - Download Symbol Files:
================================================================================
If you need full plugin support (pslist, lsof, etc.), you need symbols:

Step 1: Find the kernel version
   Run: python vol.py -f "{dump}" banners.Banners
   Look for: "Linux version X.X.X"

Step 2: Download matching symbols
   Visit: https://github.com/volatilityfoundation/volatility3
   Or: Download from your distribution's debug packages

Step 3: Install symbols
   For Volatility installed via pip:
   - Place .json.xz files in: C:\\Users\\pa249\\AppData\\Roaming\\Python\\Python313\\site-packages\\volatility3\\symbols\\linux\\

   For vol.py in Syd directory:
   - Create: C:\\Users\\pa249\\OneDrive\\Desktop\\Syd_V3\\volatility3\\symbols\\linux\\
   - Place .json.xz files there


UNDERSTANDING THE ERROR:
================================================================================
- Volatility 3 needs to know the kernel data structures
- These vary by Linux kernel version
- Symbol files tell Volatility where to find processes, files, network connections
- Without symbols, only pattern-based plugins work (bash, psaux, banners)


TRY THIS NOW:
================================================================================
Click "Paste Results" tab and paste output from:
   python vol.py -f "{dump}" linux.bash.Bash

This will show bash command history without needing symbols!
"""
        self.txt_nextsteps.delete("1.0", "end")
        self.txt_nextsteps.insert("1.0", help_text)

    def _analyze_paste(self):
        """Analyze pasted Volatility output"""
        pasted = self.txt_paste.get("1.0", "end").strip()

        if not pasted:
            from tkinter import messagebox
            messagebox.showwarning("No Input", "Please paste Volatility output first")
            return

        # Check pasted content size
        from tkinter import messagebox
        pasted_size_mb = len(pasted.encode('utf-8')) / (1024 * 1024)

        if pasted_size_mb > 20:
            result = messagebox.askyesno(
                "Large Content Warning",
                f"Pasted content is {pasted_size_mb:.1f}MB.\n\n"
                "Large pastes (>20MB) may cause GUI freezing.\n\n"
                "Recommended: Paste output from specific Volatility plugins only.\n\n"
                "Continue anyway?"
            )
            if not result:
                return
        elif pasted_size_mb > 10:
            messagebox.showinfo(
                "Performance Notice",
                f"Pasted content is {pasted_size_mb:.1f}MB.\n\n"
                "Analysis may take 10-20 seconds. Please be patient."
            )

        # Populate txt_raw with pasted data (for Ask Syd context)
        self.txt_raw.delete("1.0", "end")
        self.txt_raw.insert("1.0", pasted)

        self._parse_and_display(pasted)
        self.tabs_results.select(1)  # Switch to Parsed Results tab

    def _parse_and_display(self, output):
        """Parse output and display in structured tabs using new fact extractor (handles multi-plugin output)"""
        try:
            # Clear previous facts to prevent stale data from showing
            self.current_facts = None
            self.current_facts_text = None

            # Use NEW fact extractor (can handle multiple plugins at once!)
            if not hasattr(self, 'fact_extractor'):
                from volatility_fact_extractor import VolatilityFactExtractor
                self.fact_extractor = VolatilityFactExtractor()

            facts = self.fact_extractor.extract_facts(output)

            # Store for Ask Syd to use
            self.current_facts = facts
            self.current_facts_text = self.fact_extractor.facts_to_text(facts)

            # Clear tree
            for item in self.tree_results.get_children():
                self.tree_results.delete(item)

            # Configure tree for COMPREHENSIVE VIEW (shows ALL findings)
            columns = ("Type", "PID", "Details", "Status")
            self.tree_results.configure(columns=columns)
            for col in columns:
                self.tree_results.heading(col, text=col)
                width = 400 if col == "Details" else (80 if col in ["PID", "Type"] else 120)
                self.tree_results.column(col, width=width)

            # Add ALL processes
            for proc in facts['processes'][:50]:  # Limit to first 50
                ppid_str = f"→ PPID {proc.get('ppid', 'N/A')}" if proc.get('ppid') else ""
                self.tree_results.insert("", "end", values=(
                    "PROCESS",
                    proc['pid'],
                    f"{proc['name']} {ppid_str}",
                    "NORMAL"
                ))

            # Add ALL network connections
            for conn in facts['network_connections'][:30]:  # Limit to first 30
                local = f"{conn.get('local_ip', 'N/A')}:{conn.get('local_port', 'N/A')}"
                remote = f"{conn.get('remote_ip', 'N/A')}:{conn.get('remote_port', 'N/A')}"
                process = conn.get('process', 'Unknown')

                # Detect suspicious connections
                status = "NORMAL"
                if conn.get('process') in ['powershell.exe', 'cmd.exe', 'rundll32.exe']:
                    status = "[WARNING] SUSPICIOUS"
                if conn.get('remote_port') in [445, 5985, 5986]:  # SMB, WinRM
                    status = "[CRITICAL] LATERAL MOVEMENT"

                self.tree_results.insert("", "end", values=(
                    "NETWORK",
                    conn.get('pid', 'N/A'),
                    f"{local} → {remote} [{conn.get('state', 'N/A')}] ({process})",
                    status
                ))

            # Add ALL command lines
            for cmd in facts['command_lines'][:20]:  # Limit to first 20
                cmdline = cmd['cmdline'][:150]

                # Detect encoded/obfuscated commands
                status = "NORMAL"
                if any(x in cmdline.lower() for x in ['-enc', '-e ', 'invoke-expression', 'downloadstring', 'hidden']):
                    status = "[CRITICAL] MALWARE"
                elif 'rundll32' in cmd['process'].lower():
                    status = "[WARNING] SUSPICIOUS"

                self.tree_results.insert("", "end", values=(
                    "CMDLINE",
                    cmd['pid'],
                    f"{cmd['process']}: {cmdline}",
                    status
                ))

            # Add ALL malfind results (code injection indicators)
            for mal in facts['malfind_results']:
                self.tree_results.insert("", "end", values=(
                    "MALFIND",
                    mal['pid'],
                    f"{mal['process']}: {mal['protection']} (CODE INJECTION DETECTED!)",
                    "[CRITICAL] INJECTED"
                ))

            # Run threat pattern detection on raw output
            threat_analysis = None
            try:
                from volatility_analyzer import detect_threats
                threats_list, total_score = detect_threats(output)
                if threats_list:
                    threat_analysis = {
                        'threats': threats_list,
                        'total_threat_score': total_score
                    }
            except Exception as e:
                pass  # Silently fail if analyzer unavailable

            # Generate summary for Next Steps
            next_steps = f"""
================================================================================
VOLATILITY ANALYSIS SUMMARY
================================================================================

MEMORY DUMP OVERVIEW:
  • Plugin Type: {facts['plugin_type']}
  • Processes Found: {len(facts['processes'])}
  • Network Connections: {len(facts['network_connections'])}
  • Command Lines: {len(facts['command_lines'])}
  • Code Injection Indicators: {len(facts['malfind_results'])}

DETECTED PIDs:
  {', '.join(map(str, facts['all_pids'])) if facts['all_pids'] else 'None'}

"""

            # Add threat detection results
            if threat_analysis and threat_analysis.get('threats'):
                threats = threat_analysis['threats']
                critical_threats = [t for t in threats if t['severity'] == 'CRITICAL']
                high_threats = [t for t in threats if t['severity'] == 'HIGH']

                if critical_threats or high_threats:
                    next_steps += "\n🚨 THREAT DETECTION RESULTS:\n"
                    next_steps += "=" * 80 + "\n"
                    next_steps += f"Total Threat Score: {threat_analysis.get('total_threat_score', 0)}/100\n"
                    next_steps += f"Threats Found: {len(threats)} ({len(critical_threats)} CRITICAL, {len(high_threats)} HIGH)\n\n"

                    if critical_threats:
                        next_steps += "CRITICAL THREATS:\n"
                        for threat in critical_threats[:5]:
                            next_steps += f"  • [{threat['category']}] {threat['description']}\n"
                            next_steps += f"    PID {threat.get('pid', 'N/A')}: {threat.get('process', 'Unknown')}\n"
                            next_steps += f"    Evidence: {threat['evidence'][:100]}\n\n"

                    if high_threats:
                        next_steps += "HIGH SEVERITY THREATS:\n"
                        for threat in high_threats[:5]:
                            next_steps += f"  • [{threat['category']}] {threat['description']}\n"
                            next_steps += f"    PID {threat.get('pid', 'N/A')}: {threat.get('process', 'Unknown')}\n\n"
                else:
                    next_steps += "\n✓ THREAT SCAN: No critical threats detected\n"
                    next_steps += f"Threat Score: {threat_analysis.get('total_threat_score', 0)}/100 (Low Risk)\n\n"

            # Add suspicious findings
            if facts['malfind_results']:
                next_steps += "\n🚨 CRITICAL FINDINGS - CODE INJECTION DETECTED:\n"
                for mal in facts['malfind_results']:
                    next_steps += f"  • PID {mal['pid']} ({mal['process']}): {mal['protection']}\n"
                next_steps += "\n"

            # Add suspicious processes
            suspicious_procs = [p for p in facts['processes'] if p['name'].lower() in ['rundll32.exe', 'powershell.exe', 'cmd.exe']]
            if suspicious_procs:
                next_steps += "\n⚠️  SUSPICIOUS PROCESSES:\n"
                for proc in suspicious_procs[:10]:
                    next_steps += f"  • PID {proc['pid']}: {proc['name']}\n"
                next_steps += "\n"

            # Add network findings
            if facts['network_connections']:
                lateral_movement = [c for c in facts['network_connections'] if c.get('remote_port') in [445, 5985, 5986, 3389]]
                if lateral_movement:
                    next_steps += "\n🔴 LATERAL MOVEMENT DETECTED:\n"
                    for conn in lateral_movement[:5]:
                        next_steps += f"  • PID {conn.get('pid')} ({conn.get('process')}): {conn.get('remote_ip')}:{conn.get('remote_port')}\n"
                    next_steps += "\n"

            # Add comprehensive analysis recommendations
            plugin = facts['plugin_type']
            if plugin == 'netscan':
                next_steps += "\n" + "=" * 80 + "\n"
                next_steps += "RECOMMENDED: Run Additional Plugins for Complete Analysis\n"
                next_steps += "=" * 80 + "\n"
                next_steps += "Network scan complete. For comprehensive threat hunting, run:\n\n"
                next_steps += "1. windows.cmdline.CmdLine - CRITICAL for detecting:\n"
                next_steps += "   • Encoded PowerShell commands (Base64 obfuscation)\n"
                next_steps += "   • Malicious rundll32/regsvr32 usage\n"
                next_steps += "   • Fileless malware (IEX, DownloadString)\n\n"
                next_steps += "2. windows.malfind.Malfind - Detects:\n"
                next_steps += "   • Code injection (RWX memory regions)\n"
                next_steps += "   • Process hollowing\n"
                next_steps += "   • Reflective DLL injection\n\n"
                next_steps += "3. windows.pslist.PsList - Shows:\n"
                next_steps += "   • All running processes with timestamps\n"
                next_steps += "   • Process relationships (PPID)\n"
                next_steps += "   • Hidden/suspicious processes\n\n"
                next_steps += "WHY: Network connections alone don't reveal dormant malware,\n"
                next_steps += "     persistence mechanisms, or memory-resident threats.\n\n"
            elif plugin == 'pstree':
                next_steps += "\n" + "=" * 80 + "\n"
                next_steps += "RECOMMENDED: Run Additional Plugins for Complete Analysis\n"
                next_steps += "=" * 80 + "\n"
                next_steps += "Process tree complete. Continue investigation with:\n\n"
                next_steps += "1. windows.cmdline.CmdLine - MOST IMPORTANT\n"
                next_steps += "   Reveals HOW processes were launched and with what arguments\n\n"
                next_steps += "2. windows.netscan.NetScan\n"
                next_steps += "   Shows network connections (C2 communication)\n\n"
                next_steps += "3. windows.malfind.Malfind\n"
                next_steps += "   Detects code injection in memory\n\n"

            # Add exploit database correlation
            try:
                from volatility_analyzer import correlate_exploits, format_exploit_results
                parsed_data = {'processes': facts['processes']}
                exploit_data = correlate_exploits(parsed_data)

                if exploit_data.get('total_vulnerable', 0) > 0:
                    exploit_results = format_exploit_results(exploit_data)
                    next_steps += exploit_results
                    next_steps += "\n"
            except Exception as e:
                # Silently fail if exploit database not available
                pass

            next_steps += """
NEXT STEPS:
  1. Investigate suspicious processes (powershell, rundll32, cmd)
  2. Check network connections for C2 communication
  3. Review command lines for encoded/obfuscated commands
  4. Investigate malfind results for code injection
  5. Cross-reference with threat intelligence

ASK SYD:
  Try asking: "What is PID 6888 doing?" or "Are there suspicious network connections?"
"""

            self.txt_nextsteps.delete("1.0", "end")
            self.txt_nextsteps.insert("1.0", next_steps)

        except Exception as e:
            import traceback
            self.txt_nextsteps.delete("1.0", "end")
            self.txt_nextsteps.insert("1.0", f"Error parsing output:\n{str(e)}\n\n{traceback.format_exc()}")

    def _check_cve_exploits(self, output, parsed):
        """Check CVE and exploit databases for detected threats"""
        results = []

        try:
            # Extract potential CVE indicators from output
            import re

            # Search for version numbers in process names or output
            version_patterns = [
                r'(\w+)\s+v?([\d\.]+)',
                r'(\w+)[\-_]v?([\d\.]+)',
                r'version\s+([\d\.]+)',
            ]

            # Exclude Volatility's own output and common false positives
            exclude_keywords = ['pid', 'ppid', 'tid', 'offset', 'volatility', 'framework', 'syd',
                               'python', 'progress', 'scanning', 'vol', 'layer']

            found_versions = {}
            for pattern in version_patterns:
                matches = re.finditer(pattern, output, re.IGNORECASE)
                for match in matches:
                    if len(match.groups()) >= 2:
                        software = match.group(1)
                        version = match.group(2)
                        # Only add if not in exclusion list
                        if software.lower() not in exclude_keywords:
                            found_versions[software] = version

            # Only show version detection if meaningful versions found
            if found_versions:
                results.append("\n[INFO] VERSION DETECTION:")
            if found_versions:
                for software, version in found_versions.items():
                    results.append(f"   * {software} {version}")
                    results.append(f"     -> Search CVE: https://nvd.nist.gov/vuln/search/results?query={software}+{version}")
                    results.append(f"     -> Search Exploits: searchsploit {software} {version}")
                results.append("")
            else:
                results.append("   No version information detected in output")
                results.append("")

            # Check for exploit database matches on malicious processes
            suspicious = parsed.get('suspicious', {})
            malicious_names = suspicious.get('malicious_names', [])

            if malicious_names:
                results.append("\n[SEARCH] MALWARE/TOOL DATABASE LOOKUP:")
                for proc in malicious_names:
                    name = proc.get('name', '')
                    results.append(f"\n   [CRITICAL] {name}")

                    # Known hacking tools and their purposes
                    tool_info = {
                        'mimikatz': {
                            'purpose': 'Credential dumping and Pass-the-Hash attacks',
                            'cve': 'Exploits MS14-068, CVE-2014-6324',
                            'mitigation': 'Enable Credential Guard, restrict LSASS access'
                        },
                        'procdump': {
                            'purpose': 'Process memory dumping (used for LSASS credential theft)',
                            'cve': 'N/A - Legitimate tool abused',
                            'mitigation': 'Monitor for LSASS dumps, enable protected process light'
                        },
                        'psexec': {
                            'purpose': 'Remote command execution and lateral movement',
                            'cve': 'N/A - Legitimate tool abused',
                            'mitigation': 'Restrict admin shares, monitor SMB activity'
                        },
                        'netcat': {
                            'purpose': 'Reverse shells and data exfiltration',
                            'cve': 'N/A - Network utility',
                            'mitigation': 'Block outbound connections, monitor network traffic'
                        },
                        'nc.exe': {
                            'purpose': 'Reverse shells and data exfiltration',
                            'cve': 'N/A - Network utility',
                            'mitigation': 'Block outbound connections, monitor network traffic'
                        },
                        'pwdump': {
                            'purpose': 'Password hash extraction from SAM database',
                            'cve': 'N/A - Hacking tool',
                            'mitigation': 'Enable LSA protection, monitor SAM access'
                        },
                        'fgdump': {
                            'purpose': 'Cached credential and hash extraction',
                            'cve': 'N/A - Hacking tool',
                            'mitigation': 'Limit cached credentials, monitor registry access'
                        },
                        'cobalt': {
                            'purpose': 'Cobalt Strike C2 beacon - Advanced persistent threat framework',
                            'cve': 'N/A - Commercial tool abused',
                            'mitigation': 'Block C2 traffic, hunt for named pipes, monitor SMB beaconing'
                        },
                        'meterpreter': {
                            'purpose': 'Metasploit payload - Full remote control',
                            'cve': 'N/A - Exploitation framework',
                            'mitigation': 'EDR detection, memory scanning, network monitoring'
                        },
                        'rubeus': {
                            'purpose': 'Kerberos abuse toolkit - Ticket manipulation and attacks',
                            'cve': 'N/A - Kerberos attack tool',
                            'mitigation': 'Monitor for abnormal Kerberos traffic, enable logging'
                        },
                        'sharphound': {
                            'purpose': 'BloodHound data collector - Active Directory reconnaissance',
                            'cve': 'N/A - AD enumeration tool',
                            'mitigation': 'Monitor LDAP queries, detect mass enumeration'
                        },
                        'lazagne': {
                            'purpose': 'Password recovery tool - Extracts stored credentials',
                            'cve': 'N/A - Credential harvesting',
                            'mitigation': 'Prevent credential storage in browser/apps'
                        },
                        'wce': {
                            'purpose': 'Windows Credential Editor - Pass-the-hash attacks',
                            'cve': 'N/A - Credential theft tool',
                            'mitigation': 'Enable Credential Guard, monitor LSASS access'
                        },
                        'empire': {
                            'purpose': 'PowerShell Empire - Post-exploitation framework',
                            'cve': 'N/A - C2 framework',
                            'mitigation': 'PowerShell logging, script block logging, AMSI'
                        },
                        'covenant': {
                            'purpose': '.NET C2 framework - Command and control',
                            'cve': 'N/A - C2 framework',
                            'mitigation': 'Monitor for .NET reflection, suspicious HTTP beaconing'
                        },
                        'crackmapexec': {
                            'purpose': 'Network authentication attack and lateral movement tool',
                            'cve': 'N/A - Lateral movement tool',
                            'mitigation': 'Monitor failed auth attempts, SMB/WMI activity'
                        },
                        'impacket': {
                            'purpose': 'Python network protocol toolkit - Various attacks',
                            'cve': 'N/A - Python attack library',
                            'mitigation': 'Monitor for suspicious SMB/RPC/Kerberos activity'
                        },
                        'invoke-mimikatz': {
                            'purpose': 'PowerShell version of Mimikatz - Credential dumping',
                            'cve': 'Exploits MS14-068, CVE-2014-6324',
                            'mitigation': 'PowerShell logging, AMSI, Credential Guard'
                        },
                        'bloodhound': {
                            'purpose': 'Active Directory attack path analysis tool',
                            'cve': 'N/A - Reconnaissance tool',
                            'mitigation': 'Detect mass LDAP queries, neo4j traffic monitoring'
                        },
                        # ROOTKIT SIGNATURES
                        'tdl4': {
                            'purpose': 'TDL4/TDSS Rootkit - MBR/VBR bootkit with kernel driver',
                            'cve': 'N/A - Rootkit malware',
                            'mitigation': 'Scan MBR/VBR, use anti-rootkit tools, rebuild MBR if infected'
                        },
                        'tdss': {
                            'purpose': 'TDSS Rootkit family (Alureon) - Kernel-mode rootkit',
                            'cve': 'N/A - Rootkit malware',
                            'mitigation': 'Anti-rootkit scanner, kernel memory analysis, MBR restoration'
                        },
                        'necurs': {
                            'purpose': 'Necurs Rootkit - Kernel-mode rootkit and botnet',
                            'cve': 'N/A - Rootkit malware',
                            'mitigation': 'Kernel driver signature verification, boot-time scanning'
                        },
                        'rustock': {
                            'purpose': 'Rustock Rootkit - Spam botnet with kernel rootkit',
                            'cve': 'N/A - Rootkit malware',
                            'mitigation': 'Kernel memory forensics, driver enumeration comparison'
                        },
                        'zeoaccess': {
                            'purpose': 'ZeroAccess Rootkit (Max++) - Click-fraud botnet rootkit',
                            'cve': 'N/A - Rootkit malware',
                            'mitigation': 'Volume shadow copy analysis, kernel memory scanning'
                        },
                        'max++': {
                            'purpose': 'ZeroAccess (Max++) - Advanced kernel-mode rootkit',
                            'cve': 'N/A - Rootkit malware',
                            'mitigation': 'Compare pslist/psscan, check for hidden processes'
                        },
                        'rovnix': {
                            'purpose': 'Rovnix Bootkit - VBR bootkit with banking trojan',
                            'cve': 'N/A - Rootkit malware',
                            'mitigation': 'VBR analysis, boot sector restoration, memory forensics'
                        },
                        'olmasco': {
                            'purpose': 'Olmasco Rootkit - File and process hiding rootkit',
                            'cve': 'N/A - Rootkit malware',
                            'mitigation': 'Compare file system views, check SSDT hooks'
                        },
                        'sirefef': {
                            'purpose': 'Sirefef (ZeroAccess variant) - Kernel rootkit',
                            'cve': 'N/A - Rootkit malware',
                            'mitigation': 'Driver signature checks, kernel hook detection'
                        },
                        'srizbi': {
                            'purpose': 'Srizbi Rootkit - Spam botnet rootkit',
                            'cve': 'N/A - Rootkit malware',
                            'mitigation': 'Network traffic analysis, kernel driver enumeration'
                        },
                        'stuxnet': {
                            'purpose': 'Stuxnet - Advanced persistent threat with rootkit components',
                            'cve': 'CVE-2010-2568, CVE-2010-2729 (MS10-046, MS10-061)',
                            'mitigation': 'Patch vulnerabilities, scan for .lnk and .pnf files'
                        },
                        'finfisher': {
                            'purpose': 'FinFisher (FinSpy) - Government surveillance rootkit',
                            'cve': 'N/A - Surveillance tool',
                            'mitigation': 'Deep memory analysis, network anomaly detection'
                        },
                        'hacker defender': {
                            'purpose': 'Hacker Defender - Classic user-mode rootkit',
                            'cve': 'N/A - Rootkit tool',
                            'mitigation': 'User-mode hook detection, file system comparison'
                        },
                        'fu': {
                            'purpose': 'FU Rootkit - Kernel-mode rootkit toolkit',
                            'cve': 'N/A - Rootkit tool',
                            'mitigation': 'DKOM detection, process/driver enumeration comparison'
                        }
                    }

                    tool_name = name.lower()
                    for tool_key in tool_info:
                        if tool_key in tool_name:
                            info = tool_info[tool_key]
                            results.append(f"      Purpose: {info['purpose']}")
                            results.append(f"      Related CVE: {info['cve']}")
                            results.append(f"      Mitigation: {info['mitigation']}")
                            results.append(f"      >> More info: https://attack.mitre.org/")
                            break
                    else:
                        results.append(f"      [WARNING]  Unknown hacking tool or malware")
                        results.append(f"      -> Submit to VirusTotal: https://www.virustotal.com/")
                        results.append(f"      -> Search Malware DB: https://malpedia.caad.fkie.fraunhofer.de/")

                results.append("")

            # Check for ransomware family identification
            from volatility_analyzer import detect_threats
            threats, _ = detect_threats(output)

            ransomware_threats = [t for t in threats if 'RANSOMWARE' in t.get('category', '')]
            if ransomware_threats:
                results.append("\n[RANSOMWARE] RANSOMWARE IDENTIFICATION:")
                results.append("   Based on the detected shadow copy deletion and recovery disabling,")
                results.append("   this appears to be ransomware activity.")
                results.append("")
                results.append("   >> Identify ransomware variant:")
                results.append("      -> ID Ransomware: https://id-ransomware.malwarehunterteam.com/")
                results.append("      -> No More Ransom: https://www.nomoreransom.org/")
                results.append("")
                results.append("   [SEARCH] Check for decryptors:")
                results.append("      -> Avast Decryptors: https://www.avast.com/ransomware-decryption-tools")
                results.append("      -> Kaspersky Decryptors: https://noransom.kaspersky.com/")
                results.append("")

            # ROOTKIT BEHAVIORAL DETECTION
            rootkit_indicators = []

            # Pattern 1: Hidden processes (DKOM - Direct Kernel Object Manipulation)
            if re.search(r'(hidden|unlinked).*process', output, re.IGNORECASE):
                rootkit_indicators.append({
                    'type': 'Hidden Process Detection',
                    'severity': 'CRITICAL',
                    'description': 'Process hidden from standard enumeration (DKOM technique)',
                    'detection': 'Compare pslist vs psscan outputs - differences indicate hidden processes'
                })

            # Pattern 2: SSDT hooks
            if re.search(r'(ssdt|system.*service.*descriptor.*table).*hook', output, re.IGNORECASE):
                rootkit_indicators.append({
                    'type': 'SSDT Hook Detection',
                    'severity': 'CRITICAL',
                    'description': 'System Service Descriptor Table hooked - kernel-level interception',
                    'detection': 'SSDT entries point to non-kernel addresses'
                })

            # Pattern 3: IDT hooks
            if re.search(r'(idt|interrupt.*descriptor.*table).*hook', output, re.IGNORECASE):
                rootkit_indicators.append({
                    'type': 'IDT Hook Detection',
                    'severity': 'CRITICAL',
                    'description': 'Interrupt Descriptor Table hooked - low-level system interception',
                    'detection': 'IDT entries modified to point to malicious handlers'
                })

            # Pattern 4: Hidden drivers/modules
            if re.search(r'(hidden|unlinked).*driver', output, re.IGNORECASE) or re.search(r'(hidden|unlinked).*module', output, re.IGNORECASE):
                rootkit_indicators.append({
                    'type': 'Hidden Driver Detection',
                    'severity': 'CRITICAL',
                    'description': 'Kernel driver hidden from module list (rootkit technique)',
                    'detection': 'Compare modules vs driverscan - differences indicate hidden drivers'
                })

            # Pattern 5: Inline hooks
            if re.search(r'inline.*hook', output, re.IGNORECASE) or re.search(r'(jmp|trampoline).*hook', output, re.IGNORECASE):
                rootkit_indicators.append({
                    'type': 'Inline Hook Detection',
                    'severity': 'HIGH',
                    'description': 'Inline API hooks detected - code redirection at function level',
                    'detection': 'API function prologue modified with JMP instruction'
                })

            # Pattern 6: Registry hiding
            if re.search(r'(hidden|unlinked).*registry', output, re.IGNORECASE) or re.search(r'(hidden|unlinked).*hive', output, re.IGNORECASE):
                rootkit_indicators.append({
                    'type': 'Hidden Registry Detection',
                    'severity': 'HIGH',
                    'description': 'Registry hive hidden from enumeration',
                    'detection': 'Compare hivelist vs hivescan outputs'
                })

            # Pattern 7: Code injection indicators
            if re.search(r'(code.*injection|dll.*injection|process.*hollowing|reflective.*load)', output, re.IGNORECASE):
                rootkit_indicators.append({
                    'type': 'Code Injection Detection',
                    'severity': 'HIGH',
                    'description': 'Code injection technique detected',
                    'detection': 'Suspicious memory regions or DLLs loaded into processes'
                })

            # Pattern 8: MBR/VBR manipulation
            if re.search(r'(mbr|master.*boot.*record|vbr|volume.*boot.*record).*(modified|infected|hook)', output, re.IGNORECASE):
                rootkit_indicators.append({
                    'type': 'Bootkit Detection',
                    'severity': 'CRITICAL',
                    'description': 'Boot sector (MBR/VBR) modified - bootkit infection',
                    'detection': 'Master/Volume Boot Record contains suspicious code'
                })

            # Pattern 9: Kernel memory manipulation
            if re.search(r'kernel.*(patch|modif|manipulat)', output, re.IGNORECASE):
                rootkit_indicators.append({
                    'type': 'Kernel Modification Detection',
                    'severity': 'CRITICAL',
                    'description': 'Kernel memory structures modified',
                    'detection': 'Kernel code or data structures show signs of modification'
                })

            # Pattern 10: Suspicious driver paths
            suspicious_driver_paths = [
                r'\\Device\\[a-z0-9]{6,}',  # Random device names
                r'\\Driver\\[a-z0-9]{6,}',  # Random driver names
                r'\\temp\\',
                r'\\users\\.*\\appdata',
                r'\\programdata\\.*\.sys'
            ]
            for pattern in suspicious_driver_paths:
                if re.search(pattern, output, re.IGNORECASE):
                    rootkit_indicators.append({
                        'type': 'Suspicious Driver Path',
                        'severity': 'HIGH',
                        'description': 'Driver loaded from unusual location',
                        'detection': 'Legitimate drivers typically load from \\Windows\\System32\\drivers\\'
                    })
                    break  # Only add once

            # Display rootkit indicators if found
            if rootkit_indicators:
                results.append("\n[ROOTKIT] ROOTKIT BEHAVIORAL INDICATORS DETECTED:")
                results.append("   *** CRITICAL: Rootkit activity detected in memory dump ***")
                results.append("")

                for indicator in rootkit_indicators:
                    results.append(f"   [{indicator['severity']}] {indicator['type']}")
                    results.append(f"      Description: {indicator['description']}")
                    results.append(f"      Detection: {indicator['detection']}")
                    results.append("")

                results.append("   [ACTION] Recommended Volatility Commands for Rootkit Analysis:")
                results.append("      1. Process comparison:")
                results.append("         vol3 -f <dump> windows.pslist")
                results.append("         vol3 -f <dump> windows.psscan")
                results.append("         (Compare outputs - hidden processes appear in psscan only)")
                results.append("")
                results.append("      2. Driver comparison:")
                results.append("         vol3 -f <dump> windows.modules")
                results.append("         vol3 -f <dump> windows.driverscan")
                results.append("         (Compare outputs - hidden drivers appear in driverscan only)")
                results.append("")
                results.append("      3. SSDT analysis:")
                results.append("         vol3 -f <dump> windows.ssdt")
                results.append("         (Check for hooked system calls)")
                results.append("")
                results.append("      4. Check loaded modules:")
                results.append("         vol3 -f <dump> windows.ldrmodules")
                results.append("         (Find hidden DLLs and unlinked modules)")
                results.append("")
                results.append("   [REMEDIATION]:")
                results.append("      -> Isolate infected system immediately")
                results.append("      -> DO NOT boot from infected disk")
                results.append("      -> Use offline scanning with trusted tools")
                results.append("      -> Consider full system rebuild")
                results.append("      -> Anti-rootkit tools: GMER, TDSSKiller, RootkitRevealer")
                results.append("")

            # Check for known CVE patterns in output
            cve_matches = re.findall(r'(CVE-\d{4}-\d+)', output, re.IGNORECASE)
            if cve_matches:
                results.append("\n[ALERT] CVE REFERENCES FOUND IN OUTPUT:")
                for cve in set(cve_matches):
                    results.append(f"   * {cve.upper()}")
                    results.append(f"     -> Details: https://nvd.nist.gov/vuln/detail/{cve.upper()}")
                    results.append(f"     -> Exploits: searchsploit {cve.upper()}")
                results.append("")

            # Suggest additional checks
            results.append("\n[TIP] RECOMMENDED DATABASE CHECKS:")
            results.append("   1. Hash Analysis:")
            results.append("      -> Extract process: vol3 -f <dump> windows.pslist --pid <PID> --dump")
            results.append("      -> Calculate hash: sha256sum dumped_process.exe")
            results.append("      -> Check VirusTotal: https://www.virustotal.com/")
            results.append("")
            results.append("   2. Network IOC Checks:")
            results.append("      -> Check IPs against AbuseIPDB: https://www.abuseipdb.com/")
            results.append("      -> Check against Threat Intelligence feeds")
            results.append("")
            results.append("   3. YARA Rules:")
            results.append("      -> Run YARA scan: vol3 -f <dump> windows.yarascan --yara-rules malware.yar")
            results.append("      -> Rules: https://github.com/Yara-Rules/rules")
            results.append("")

        except Exception as e:
            results.append(f"\nError checking CVE/exploit databases: {str(e)}")

        return "\n".join(results) if results else ""

    # ========== AUTO-ANALYZE FUNCTIONALITY ==========

    def _get_windows_plugin_suite(self):
        """Return curated list of Windows plugins for comprehensive analysis"""
        return [
            ("windows.pslist.PsList", "Process List"),
            ("windows.pstree.PsTree", "Process Tree"),
            ("windows.cmdline.CmdLine", "Command Lines"),
            ("windows.netscan.NetScan", "Network Connections"),
            ("windows.malfind.Malfind", "Code Injection Detection"),
            ("windows.dlllist.DllList", "Loaded DLLs"),
            ("windows.handles.Handles", "Open Handles"),
            ("windows.registry.userassist.UserAssist", "Program Execution History"),
            ("windows.registry.hivelist.HiveList", "Registry Hives"),
            ("windows.filescan.FileScan", "File Objects"),
        ]

    def _get_linux_plugin_suite(self):
        """Return curated list of Linux plugins for comprehensive analysis"""
        return [
            ("linux.pslist.PsList", "Process List"),
            ("linux.pstree.PsTree", "Process Tree"),
            ("linux.bash.Bash", "Bash History"),
            ("linux.psaux.PsAux", "Process Details"),
            ("linux.lsof.Lsof", "Open Files"),
            ("linux.mount.Mount", "Mounted Filesystems"),
        ]

    def _supplement_facts_from_grid_output(self, facts):
        """
        Supplement fact extractor results with data parsed from Volatility 3 grid format.
        The fact extractor expects 'PID: 1234' labeled format for malfind/dlllist,
        but Volatility 3 outputs grid/table format with PID as a column value.
        This method adds malfind and cmdline data that the extractor misses.
        """
        if not hasattr(self, 'auto_analyze_results') or not self.auto_analyze_results:
            return facts

        import re

        # Supplement malfind results from grid output
        if not facts.get('malfind_results'):
            malfind_entries = []
            for plugin, output in self.auto_analyze_results.items():
                if 'malfind' not in plugin.lower():
                    continue
                for line in output.split('\n'):
                    if not line.strip():
                        continue
                    # Skip header line
                    if 'PID' in line and 'Process' in line and ('Start VPN' in line or 'Protection' in line):
                        continue
                    if '---' in line:
                        continue
                    # Parse grid-format malfind line: PID  Process  Start_VPN  End_VPN  Tag  Protection  ...
                    parts = line.split()
                    if len(parts) >= 6 and parts[0].isdigit():
                        pid = int(parts[0])
                        process = parts[1]
                        # Find protection field (PAGE_*)
                        protection = None
                        start_vpn = None
                        end_vpn = None
                        for i, part in enumerate(parts):
                            if part.startswith('PAGE_'):
                                protection = part
                            elif part.startswith('0x') and start_vpn is None:
                                start_vpn = part
                            elif part.startswith('0x') and start_vpn and end_vpn is None:
                                end_vpn = part

                        if protection:
                            malfind_entries.append({
                                "pid": pid,
                                "process": process,
                                "start_vpn": start_vpn,
                                "end_vpn": end_vpn,
                                "protection": protection,
                                "suspicious": "EXECUTE_READWRITE" in protection or "EXECUTE_WRITECOPY" in protection,
                                "raw_line": line.strip()
                            })

            if malfind_entries:
                facts["malfind_results"] = malfind_entries
                # Add malfind PIDs to all_pids
                for entry in malfind_entries:
                    if entry["pid"] not in facts.get("all_pids", []):
                        facts.setdefault("all_pids", []).append(entry["pid"])
                    proc_name = entry["process"].lower()
                    if proc_name not in [p.lower() for p in facts.get("all_process_names", [])]:
                        facts.setdefault("all_process_names", []).append(proc_name)

        # Supplement network connections if netscan parser missed some
        if not facts.get('network_connections'):
            connections = []
            for plugin, output in self.auto_analyze_results.items():
                if 'netscan' not in plugin.lower():
                    continue
                for line in output.split('\n'):
                    if not line.strip() or 'Offset' in line or 'Proto' in line or '---' in line:
                        continue
                    # Extract IPs and ports using regex
                    ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                    port_matches = re.findall(r':(\d+)\b|\s(\d{1,5})\s', line)
                    state_match = re.search(r'\b(ESTABLISHED|LISTENING|CLOSE_WAIT|TIME_WAIT|CLOSED)\b', line, re.IGNORECASE)
                    process_match = re.search(r'\b([a-zA-Z0-9_\-]+\.exe)\b', line, re.IGNORECASE)

                    # Find PID - number right before .exe name
                    pid = None
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part.isdigit() and i + 1 < len(parts) and '.exe' in parts[i+1].lower():
                            pid = int(part)
                            break

                    if ips or pid:
                        # Extract ports from the line more carefully
                        local_port = None
                        remote_port = None
                        for i, part in enumerate(parts):
                            if part.isdigit() and 1 <= int(part) <= 65535:
                                if i > 0 and (parts[i-1] in ips):
                                    if local_port is None:
                                        local_port = int(part)
                                    elif remote_port is None:
                                        remote_port = int(part)

                        connections.append({
                            "local_ip": ips[0] if len(ips) > 0 else None,
                            "local_port": local_port,
                            "remote_ip": ips[1] if len(ips) > 1 else None,
                            "remote_port": remote_port,
                            "state": state_match.group(1) if state_match else None,
                            "pid": pid,
                            "process": process_match.group(1) if process_match else None,
                            "protocol": None,
                            "raw_line": line.strip()
                        })

            if connections:
                facts["network_connections"] = connections
                for conn in connections:
                    if conn.get("pid") and conn["pid"] not in facts.get("all_pids", []):
                        facts.setdefault("all_pids", []).append(conn["pid"])
                    if conn.get("local_ip") and conn["local_ip"] not in facts.get("all_ips", []):
                        facts.setdefault("all_ips", []).append(conn["local_ip"])
                    if conn.get("remote_ip") and conn["remote_ip"] not in facts.get("all_ips", []):
                        facts.setdefault("all_ips", []).append(conn["remote_ip"])
                    if conn.get("local_port") and conn["local_port"] not in facts.get("all_ports", []):
                        facts.setdefault("all_ports", []).append(conn["local_port"])
                    if conn.get("remote_port") and conn["remote_port"] not in facts.get("all_ports", []):
                        facts.setdefault("all_ports", []).append(conn["remote_port"])
                    if conn.get("process"):
                        proc_name = conn["process"].lower()
                        if proc_name not in [p.lower() for p in facts.get("all_process_names", [])]:
                            facts.setdefault("all_process_names", []).append(proc_name)

        # Clean up false positives from cross-parser contamination
        # Remove processes where name is a hex address (malfind grid lines parsed as processes)
        if facts.get("processes"):
            facts["processes"] = [
                proc for proc in facts["processes"]
                if not (proc.get("name", "").startswith("0x") or proc.get("name", "").startswith("0X"))
            ]

        # Remove network connections where both IPs are None (parser noise from pslist lines)
        if facts.get("network_connections"):
            facts["network_connections"] = [
                conn for conn in facts["network_connections"]
                if conn.get("local_ip") or conn.get("remote_ip")
            ]

        # Remove cmdlines that look like pslist/malfind output (have hex offsets or PAGE_ flags)
        if facts.get("command_lines"):
            facts["command_lines"] = [
                cmd for cmd in facts["command_lines"]
                if not re.search(r'0x[0-9a-fA-F]{5,}', cmd.get("cmdline", ""))
                and 'PAGE_' not in cmd.get("cmdline", "")
            ]

        # Sort aggregated lists
        if facts.get("all_pids"):
            facts["all_pids"] = sorted(set(facts["all_pids"]))
        if facts.get("all_ports"):
            facts["all_ports"] = sorted(set(facts["all_ports"]))

        return facts

    def _auto_analyze_windows(self):
        """Run comprehensive Windows memory analysis"""
        if self.auto_analyze_running:
            messagebox.showwarning("Analysis Running", "An auto-analysis is already in progress!")
            return

        dump = self.dump_path.get().strip()
        if not dump:
            messagebox.showerror("No Dump Selected", "Please select a memory dump first!")
            return

        self.auto_analyze_running = True
        self.auto_analyze_results = {}
        self.current_facts = None  # Clear facts for new analysis (will be initialized as dict during extraction)
        self.current_facts_text = ""  # Clear text facts
        self.txt_raw.delete("1.0", "end")
        self.txt_raw.insert("end", "═" * 80 + "\n")
        self.txt_raw.insert("end", "           WINDOWS MEMORY ANALYSIS - COMPREHENSIVE SUITE\n")
        self.txt_raw.insert("end", "═" * 80 + "\n\n")

        plugin_suite = self._get_windows_plugin_suite()

        import threading
        threading.Thread(target=self._run_plugin_suite, args=(plugin_suite, "Windows"), daemon=True).start()

    def _auto_analyze_linux(self):
        """Run comprehensive Linux memory analysis"""
        if self.auto_analyze_running:
            messagebox.showwarning("Analysis Running", "An auto-analysis is already in progress!")
            return

        dump = self.dump_path.get().strip()
        if not dump:
            messagebox.showerror("No Dump Selected", "Please select a memory dump first!")
            return

        self.auto_analyze_running = True
        self.auto_analyze_results = {}
        self.current_facts = None  # Clear facts for new analysis (will be initialized as dict during extraction)
        self.current_facts_text = ""  # Clear text facts
        self.txt_raw.delete("1.0", "end")
        self.txt_raw.insert("end", "═" * 80 + "\n")
        self.txt_raw.insert("end", "           LINUX MEMORY ANALYSIS - COMPREHENSIVE SUITE\n")
        self.txt_raw.insert("end", "═" * 80 + "\n\n")

        plugin_suite = self._get_linux_plugin_suite()

        import threading
        threading.Thread(target=self._run_plugin_suite, args=(plugin_suite, "Linux"), daemon=True).start()

    def _run_plugin_suite(self, plugin_suite, os_type):
        """Run a suite of plugins sequentially and generate unified report"""
        import subprocess
        import os
        import sys
        import time

        dump = self.dump_path.get().strip()
        start_time = time.time()

        try:
            # Get vol.py command
            python_exe = sys.executable
            vol_path = self.vol_path.get().strip()

            if vol_path and os.path.exists(vol_path):
                vol_cmd = f'"{python_exe}" "{vol_path}"'
            else:
                # Auto-detect
                vol_cmd = None
                try:
                    import shutil
                    if shutil.which('vol'):
                        vol_cmd = 'vol'
                except:
                    pass

                if not vol_cmd:
                    try:
                        import importlib.util
                        if importlib.util.find_spec('volatility3.vol'):
                            vol_cmd = f'"{python_exe}" -m volatility3.vol'
                    except:
                        pass

                if not vol_cmd:
                    vol_cmd = f'"{python_exe}" -m volatility3.cli'

            # Run each plugin
            total_plugins = len(plugin_suite)
            for idx, (plugin, description) in enumerate(plugin_suite, 1):
                # Update progress
                progress_msg = f"[{idx}/{total_plugins}] Running: {description}..."
                self.after(0, lambda msg=progress_msg: self.auto_analyze_progress.set(msg))
                self.after(0, lambda p=plugin: self.txt_raw.insert("end", f"\n▶ Running {p}...\n"))
                self.after(0, lambda: self.txt_raw.see("end"))

                # Run plugin - build command list directly (avoid shlex quote issues on Windows)
                if vol_path and os.path.exists(vol_path):
                    # Use explicit vol.py path
                    cmd_list = [python_exe, vol_path]
                else:
                    # Use module form
                    cmd_list = [python_exe, '-m', 'volatility3.cli']
                cmd_list.extend(['-f', str(dump), plugin])

                try:
                    result = subprocess.run(
                        cmd_list,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        shell=False,
                        timeout=180,  # 3 minute timeout per plugin
                        errors='replace'
                    )

                    if result.stdout:
                        # Store raw output
                        self.auto_analyze_results[plugin] = result.stdout
                        self.after(0, lambda out=result.stdout: self.txt_raw.insert("end", f"✓ Completed\n"))

                        # Extract facts for Ask Syd (same pattern as manual plugin analysis)
                        try:
                            # Initialize fact extractor if not already done
                            if not hasattr(self, 'fact_extractor'):
                                from volatility_fact_extractor import VolatilityFactExtractor
                                self.fact_extractor = VolatilityFactExtractor()

                            # Strip progress/framework lines before extraction
                            clean_output = "\n".join(
                                line for line in result.stdout.split("\n")
                                if not line.strip().startswith("Progress:")
                                and "Volatility 3 Framework" not in line
                            )

                            # Extract structured facts from this plugin's output
                            plugin_facts = self.fact_extractor.extract_facts(clean_output)

                            # Initialize current_facts dict if needed (not a list!)
                            if not hasattr(self, 'current_facts') or self.current_facts is None:
                                self.current_facts = {
                                    "plugin_type": "multiple",
                                    "processes": [],
                                    "network_connections": [],
                                    "command_lines": [],
                                    "dll_list": [],
                                    "malfind_results": [],
                                    "registry_keys": [],
                                    "file_handles": [],
                                    "metadata": {},
                                    "all_pids": [],
                                    "all_process_names": [],
                                    "all_ips": [],
                                    "all_ports": []
                                }

                            # Merge facts from this plugin into cumulative facts
                            for key in ["processes", "network_connections", "command_lines", "dll_list",
                                       "malfind_results", "registry_keys", "file_handles"]:
                                if key in plugin_facts and plugin_facts[key]:
                                    self.current_facts[key].extend(plugin_facts[key])

                            # Merge aggregated lists (avoiding duplicates)
                            for key in ["all_pids", "all_process_names", "all_ips", "all_ports"]:
                                if key in plugin_facts:
                                    self.current_facts[key] = list(set(self.current_facts[key] + plugin_facts[key]))

                        except Exception as fact_err:
                            # Log error to CONSOLE (visible for debugging) and GUI
                            import traceback
                            error_details = f"Fact extraction error for {plugin}: {str(fact_err)}"
                            self.after(0, lambda err=error_details: self.txt_raw.insert("end", f"⚠ {err}\n"))
                    else:
                        self.after(0, lambda: self.txt_raw.insert("end", f"⚠ No output\n"))

                    if result.stderr and result.returncode != 0:
                        self.after(0, lambda err=result.stderr: self.txt_raw.insert("end", f"Error: {err[:200]}\n"))

                except subprocess.TimeoutExpired:
                    self.after(0, lambda: self.txt_raw.insert("end", f"⏱ Timeout (skipped)\n"))
                except Exception as e:
                    self.after(0, lambda err=str(e): self.txt_raw.insert("end", f"❌ Error: {err}\n"))

            # Analysis complete - generate unified report
            elapsed_time = time.time() - start_time
            minutes = int(elapsed_time // 60)
            seconds = int(elapsed_time % 60)

            self.after(0, lambda: self.auto_analyze_progress.set(f"✓ Analysis complete ({minutes}m {seconds}s) - Generating report..."))
            self.after(0, lambda: self.txt_raw.insert("end", f"\n{'═' * 80}\n"))
            self.after(0, lambda: self.txt_raw.insert("end", f"Analysis complete! Generating unified report...\n"))
            self.after(0, lambda: self.txt_raw.insert("end", f"{'═' * 80}\n"))

            # Generate unified report
            unified_report = self._generate_unified_report(os_type, minutes, seconds)

            # Display in Parsed Results tab as Text widget
            self.after(0, lambda: self._display_unified_report(unified_report))

            # FALLBACK: If per-plugin fact extraction failed, extract per-plugin from stored results
            if not self.current_facts or not isinstance(self.current_facts, dict):
                try:
                    if not hasattr(self, 'fact_extractor'):
                        from volatility_fact_extractor import VolatilityFactExtractor
                        self.fact_extractor = VolatilityFactExtractor()

                    # Initialize facts dict
                    self.current_facts = {
                        "plugin_type": "multiple",
                        "processes": [], "network_connections": [], "command_lines": [],
                        "dll_list": [], "malfind_results": [], "registry_keys": [],
                        "file_handles": [], "metadata": {},
                        "all_pids": [], "all_process_names": [], "all_ips": [], "all_ports": []
                    }

                    # Extract facts from each plugin's output separately (avoids cross-contamination)
                    for plugin, output in self.auto_analyze_results.items():
                        try:
                            clean_output = "\n".join(
                                line for line in output.split("\n")
                                if not line.strip().startswith("Progress:")
                                and "Volatility 3 Framework" not in line
                            )
                            if not clean_output.strip():
                                continue

                            plugin_facts = self.fact_extractor.extract_facts(clean_output)

                            for key in ["processes", "network_connections", "command_lines", "dll_list",
                                       "malfind_results", "registry_keys", "file_handles"]:
                                if key in plugin_facts and plugin_facts[key]:
                                    self.current_facts[key].extend(plugin_facts[key])

                            for key in ["all_pids", "all_process_names", "all_ips", "all_ports"]:
                                if key in plugin_facts and plugin_facts[key]:
                                    self.current_facts[key] = list(set(self.current_facts[key] + plugin_facts[key]))
                        except Exception as plugin_err:
                            pass  # Skip plugins that fail during fallback extraction

                except Exception as fallback_err:
                    pass  # Fallback extraction failed silently

            # Supplement facts with grid-format data (malfind, netscan) that the extractor may miss
            if hasattr(self, 'current_facts') and self.current_facts and isinstance(self.current_facts, dict):
                self.current_facts = self._supplement_facts_from_grid_output(self.current_facts)

            # Convert facts to text for LLM
            if hasattr(self, 'current_facts') and self.current_facts:
                try:
                    # Count total facts
                    fact_count = (len(self.current_facts.get('processes', [])) +
                                 len(self.current_facts.get('network_connections', [])) +
                                 len(self.current_facts.get('command_lines', [])) +
                                 len(self.current_facts.get('dll_list', [])) +
                                 len(self.current_facts.get('malfind_results', [])) +
                                 len(self.current_facts.get('file_handles', [])) +
                                 len(self.current_facts.get('registry_keys', [])))

                    if fact_count > 0:
                        # Convert structured facts to text format for LLM
                        self.current_facts_text = self.fact_extractor.facts_to_text(self.current_facts)
                        self.after(0, lambda fc=fact_count: self.txt_raw.insert("end", f"\n✓ Extracted {fc} facts for Ask Syd\n"))
                        self.after(0, lambda fc=fact_count: self.log_to_asksyd(f"Auto-analysis complete. Extracted {fc} facts from {total_plugins} plugins."))
                    else:
                        self.after(0, lambda: self.log_to_asksyd("Auto-analysis complete. Warning: No structured facts found in output."))
                except Exception as text_err:
                    self.after(0, lambda: self.log_to_asksyd(f"Auto-analysis complete. Warning: Could not convert facts to text: {str(text_err)}"))
            else:
                self.after(0, lambda: self.log_to_asksyd("Auto-analysis complete. Warning: No facts extracted for Ask Syd."))

            self.after(0, lambda: self.auto_analyze_progress.set(""))

        except Exception as e:
            import traceback
            error_msg = f"Auto-analysis error: {str(e)}\n{traceback.format_exc()}"
            self.after(0, lambda msg=error_msg: self.txt_raw.insert("end", f"\n{msg}\n"))
            self.after(0, lambda: self.auto_analyze_progress.set(""))

        finally:
            self.auto_analyze_running = False

    def _generate_unified_report(self, os_type, minutes, seconds):
        """Generate a unified, easy-to-read report from all plugin outputs"""
        import re
        from datetime import datetime

        report = []
        dump_name = os.path.basename(self.dump_path.get())

        # Header
        report.append("═" * 80)
        report.append("                    MEMORY ANALYSIS SUMMARY")
        report.append("═" * 80)
        report.append(f"Memory Dump: {dump_name}")
        report.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Operating System: {os_type}")
        report.append(f"Total Analysis Time: {minutes}m {seconds}s")
        report.append("")

        # Parse results from stored outputs
        processes = []
        suspicious_procs = []
        network_connections = []
        injected_code = []
        command_lines = {}
        all_threats = []

        # Extract data from plugin outputs
        for plugin, output in self.auto_analyze_results.items():
            # Parse process list
            if 'pslist' in plugin.lower() and 'pstree' not in plugin.lower():
                for line in output.split('\n'):
                    if line.strip() and not line.startswith(('PID', '*', '-', '=')):
                        parts = line.split()
                        if len(parts) >= 2 and parts[0].isdigit():
                            processes.append(line.strip())

            # Parse command lines
            elif 'cmdline' in plugin.lower():
                current_pid = None
                for line in output.split('\n'):
                    pid_match = re.search(r'PID\s+(\d+)', line)
                    if pid_match:
                        current_pid = pid_match.group(1)
                    elif current_pid and line.strip() and not line.startswith(('*', '-', '=')):
                        command_lines[current_pid] = line.strip()

                        # Check for suspicious commands
                        line_lower = line.lower()
                        if any(sus in line_lower for sus in ['powershell -enc', '-encodedcommand', 'invoke-expression', 'downloadstring', 'certutil', 'bitsadmin', 'rundll32', 'regsvr32', 'mshta', 'wmic']):
                            suspicious_procs.append(f"PID {current_pid}: {line.strip()}")

            # Parse network connections
            elif 'netscan' in plugin.lower():
                for line in output.split('\n'):
                    if 'ESTABLISHED' in line or 'LISTENING' in line:
                        network_connections.append(line.strip())

            # Parse code injection
            elif 'malfind' in plugin.lower():
                # List of legitimate processes that commonly use RWX memory (JIT compilers, security software, etc.)
                legitimate_rwx = ['msmpeng.exe', 'mssense.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe',
                                  'java.exe', 'javaw.exe', 'node.exe', 'dotnet.exe', 'python.exe',
                                  'searchhost.exe', 'onedrive.exe', 'smartscreen.exe', 'runtimebroker.exe',
                                  'applicationframehost.exe', 'systemsettings.exe']

                for line in output.split('\n'):
                    # Skip header rows and empty lines
                    if not line.strip() or ('PID' in line and 'Process' in line and 'Start VPN' in line):
                        continue

                    # Look for rows with PAGE_EXECUTE_READWRITE (RWX memory)
                    if 'PAGE_EXECUTE_READWRITE' in line:
                        parts = line.split()
                        if len(parts) >= 2 and parts[0].isdigit():
                            pid = parts[0]
                            process = parts[1].lower()

                            # Mark as benign if it's a known legitimate process
                            if process in legitimate_rwx:
                                injected_code.append(f"PID {pid} ({parts[1]}): RWX memory [LIKELY BENIGN - JIT/Security Software]")
                            else:
                                injected_code.append(f"PID {pid} ({parts[1]}): RWX memory [INVESTIGATE]")

                    # Look for MZ headers (PE files in memory)
                    elif 'MZ' in line and '4d 5a' in line.lower():
                        # Try to extract PID from context
                        parts = line.split()
                        if len(parts) >= 1:
                            injected_code.append(f"PE header (MZ) detected in memory")

        # Run threat detection on command lines
        if command_lines:
            try:
                from volatility_analyzer import parse_volatility_output
                cmdline_output = '\n'.join([f"PID {pid}: {cmd}" for pid, cmd in command_lines.items()])
                threat_result = parse_volatility_output(cmdline_output)
                all_threats = threat_result.get('threats', [])
            except Exception as e:
                print(f"[WARN] Threat analysis in report failed: {e}")

        # Executive Summary
        report.append("═" * 80)
        report.append("                    🎯 EXECUTIVE SUMMARY")
        report.append("═" * 80)
        report.append(f"• Total Processes: {len(processes)}")
        report.append(f"• Network Connections: {len([c for c in network_connections if 'ESTABLISHED' in c])} established, {len([c for c in network_connections if 'LISTENING' in c])} listening")

        # Threat summary
        critical_threats = [t for t in all_threats if t.get('severity') == 'CRITICAL']
        high_threats = [t for t in all_threats if t.get('severity') == 'HIGH']
        medium_threats = [t for t in all_threats if t.get('severity') == 'MEDIUM']

        report.append(f"• Threats Detected: {len(critical_threats)} CRITICAL, {len(high_threats)} HIGH, {len(medium_threats)} MEDIUM")

        # Separate benign vs suspicious code injections
        benign_injections = [i for i in injected_code if 'LIKELY BENIGN' in i]
        suspicious_injections = [i for i in injected_code if 'INVESTIGATE' in i or 'MZ' in i]

        if benign_injections and suspicious_injections:
            report.append(f"• Code Injection: {len(suspicious_injections)} suspicious, {len(benign_injections)} benign (total: {len(injected_code)})")
        elif benign_injections:
            report.append(f"• Code Injection: {len(benign_injections)} benign instances (expected behavior)")
        elif suspicious_injections:
            report.append(f"• Code Injection: {len(suspicious_injections)} suspicious instances detected")
        else:
            report.append(f"• Code Injection: {len(injected_code)} instances detected")

        report.append(f"• Suspicious Processes: {len(suspicious_procs)}")

        # Calculate risk score (only count suspicious injections, not benign ones)
        risk_score = min(100, (len(critical_threats) * 25) + (len(high_threats) * 10) + (len(medium_threats) * 3) + (len(suspicious_injections) * 15))
        risk_level = "CRITICAL" if risk_score >= 75 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 25 else "LOW"
        report.append(f"• Overall Risk Score: {risk_score}/100 ({risk_level})")
        report.append("")

        # Critical Threats Section
        if critical_threats or high_threats:
            report.append("═" * 80)
            report.append("                    🚨 CRITICAL & HIGH THREATS")
            report.append("═" * 80)
            report.append("")

            for threat in (critical_threats + high_threats):  # Show all critical/high threats
                report.append(f"[{threat.get('severity')}] {threat.get('type', 'Unknown')} (Score: {threat.get('score')})")
                if threat.get('process'):
                    report.append(f"  • Process: {threat.get('process')} (PID {threat.get('pid', 'N/A')})")
                report.append(f"  • Evidence: {threat.get('evidence', '')[:100]}...")
                report.append(f"  • Category: {threat.get('category', 'Unknown')}")
                report.append("")

        # Suspicious Processes Section
        if suspicious_procs:
            report.append("═" * 80)
            report.append("                    📊 SUSPICIOUS PROCESSES")
            report.append("═" * 80)
            report.append("")
            for proc in suspicious_procs:  # Show all suspicious processes
                report.append(f"  • {proc}")
            report.append("")

        # Network Activity Section
        if network_connections:
            report.append("═" * 80)
            report.append("                    🌐 NETWORK ACTIVITY")
            report.append("═" * 80)
            report.append("")

            established = [c for c in network_connections if 'ESTABLISHED' in c]
            listening = [c for c in network_connections if 'LISTENING' in c]

            if established:
                report.append("Active Connections (ESTABLISHED):")
                for conn in established:  # Show all established connections
                    report.append(f"  {conn}")
                report.append("")

            if listening:
                report.append("Listening Ports:")
                for conn in listening:  # Show all listening ports
                    report.append(f"  {conn}")
                report.append("")

        # Code Injection Section
        if injected_code:
            report.append("═" * 80)
            report.append("                    💉 CODE INJECTION ANALYSIS")
            report.append("═" * 80)
            report.append("")

            # Show suspicious injections first
            if suspicious_injections:
                report.append("⚠️  SUSPICIOUS (Requires Investigation):")
                report.append("")
                for injection in suspicious_injections:  # Show ALL suspicious injections
                    report.append(f"  • {injection}")
                report.append("")

            # Then show benign ones
            if benign_injections:
                report.append("✓ BENIGN (Expected Behavior):")
                report.append("")
                for injection in benign_injections[:5]:  # Show top 5
                    report.append(f"  • {injection}")
                if len(benign_injections) > 5:
                    report.append(f"  ... and {len(benign_injections) - 5} more instances")
                report.append("")
                report.append("Note: These processes legitimately use RWX memory for JIT compilation,")
                report.append("security scanning, or browser sandboxing. This is normal behavior.")
                report.append("")

        # Recommendations Section
        report.append("═" * 80)
        report.append("                    🎯 RECOMMENDED NEXT STEPS")
        report.append("═" * 80)
        report.append("")

        # Use dynamic numbering
        step_num = 1

        if critical_threats or high_threats:
            report.append(f"{step_num}. IMMEDIATE ACTION REQUIRED:")
            report.append("   • Isolate the system from the network")
            report.append("   • Review and decode any suspicious command lines")
            report.append("   • Dump suspicious processes for malware analysis")
            report.append("")
            step_num += 1

        if injected_code:
            report.append(f"{step_num}. INVESTIGATE CODE INJECTION:")
            report.append("   • Dump memory regions with RWX permissions")
            report.append("   • Scan for PE files and shellcode")
            report.append("   • Check for process hollowing or DLL injection")
            report.append("")
            step_num += 1

        if suspicious_procs:
            report.append(f"{step_num}. ANALYZE SUSPICIOUS PROCESSES:")
            report.append("   • Review parent-child process relationships")
            report.append("   • Check process creation times")
            report.append("   • Investigate loaded DLLs and handles")
            report.append("")
            step_num += 1

        report.append(f"{step_num}. ADDITIONAL ANALYSIS:")
        report.append("   • Check persistence mechanisms (Registry Run keys)")
        report.append("   • Review scheduled tasks and services")
        report.append("   • Scan for YARA rules matching known malware")
        report.append("   • Correlate with host-based indicators (files, registry)")
        report.append("")

        # Ask Syd prompt
        report.append("═" * 80)
        report.append("💬 Have questions? Ask Syd on the right →")
        report.append("   Examples: 'What are the most suspicious processes?'")
        report.append("             'Explain the critical threats detected'")
        report.append("             'How do I investigate PID 1234?'")
        report.append("═" * 80)

        return "\n".join(report)

    def _display_unified_report(self, report):
        """Display unified report in Analysis Summary tab and populate other tabs"""
        # Clear existing parsed results tree
        for item in self.tree_results.get_children():
            self.tree_results.delete(item)

        # Check if Summary tab already exists
        tab_names = [self.tabs_results.tab(i, "text") for i in range(self.tabs_results.index("end"))]

        if "Analysis Summary" not in tab_names:
            # Create new Summary tab
            summary_tab = ttk.Frame(self.tabs_results)
            self.txt_summary = tk.Text(summary_tab, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word", font=("Consolas", 9))
            scroll_summary = ttk.Scrollbar(summary_tab, command=self.txt_summary.yview)
            self.txt_summary.configure(yscrollcommand=scroll_summary.set)
            self.txt_summary.pack(side="left", fill="both", expand=True)
            scroll_summary.pack(side="right", fill="y")
            self.tabs_results.insert(1, summary_tab, text="Analysis Summary")  # Insert after Raw Output

        # Display full report in Analysis Summary tab
        self.txt_summary.delete("1.0", "end")
        self.txt_summary.insert("1.0", report)

        # Extract and populate Next Steps tab
        self._populate_nextsteps_from_report(report)

        # Populate Parsed Results with key findings
        self._populate_parsed_results_from_report(report)

        # Switch to Summary tab
        self.tabs_results.select(1)

    def _populate_nextsteps_from_report(self, report):
        """Extract recommendations from report and display in Next Steps tab"""
        self.txt_nextsteps.delete("1.0", "end")

        # Extract the recommendations section
        lines = report.split('\n')
        in_recommendations = False
        recommendations = []

        for line in lines:
            if '🎯 RECOMMENDED NEXT STEPS' in line:
                in_recommendations = True
                continue
            elif in_recommendations:
                if line.startswith('═'):
                    # End of recommendations section
                    if recommendations:  # Don't stop if it's the opening separator
                        break
                else:
                    recommendations.append(line)

        # Display in Next Steps tab
        if recommendations:
            self.txt_nextsteps.insert("end", "═" * 80 + "\n")
            self.txt_nextsteps.insert("end", "                    RECOMMENDED NEXT STEPS\n")
            self.txt_nextsteps.insert("end", "═" * 80 + "\n\n")
            self.txt_nextsteps.insert("end", '\n'.join(recommendations))
        else:
            self.txt_nextsteps.insert("end", "No specific recommendations at this time.\n\n")
            self.txt_nextsteps.insert("end", "The system appears to be operating normally based on the analysis.\n")

    def _populate_parsed_results_from_report(self, report):
        """Populate Parsed Results tab with process list from extracted facts"""
        # Populate the TreeView with processes from current_facts
        if hasattr(self, 'current_facts') and self.current_facts and isinstance(self.current_facts, dict):
            processes = self.current_facts.get('processes', [])

            # Deduplicate by PID (keep first occurrence of each unique PID)
            seen_pids = set()
            unique_processes = []
            for proc in processes:
                pid = proc.get('pid')
                # Filter out invalid PIDs (must be int > 0 and not already seen)
                if isinstance(pid, int) and pid > 0 and pid not in seen_pids:
                    seen_pids.add(pid)
                    unique_processes.append(proc)

            # Sort by PID
            processes_sorted = sorted(unique_processes, key=lambda p: p.get('pid', 0))

            # Populate tree with unique processes only
            for proc in processes_sorted:
                pid = proc.get('pid', 'N/A')
                name = proc.get('name', 'Unknown')
                ppid = proc.get('ppid', 'N/A')
                threads = proc.get('threads', 'N/A')
                handles = proc.get('handles', 'N/A')
                create_time = proc.get('create_time', 'N/A')

                # Details column: show create time if available
                details = f"Created: {create_time}" if create_time != 'N/A' else 'N/A'

                self.tree_results.insert("", "end", values=(pid, name, ppid, threads, handles, details))

    def _stop_process(self):
        """Stop running process"""
        if self.current_process:
            self.current_process.terminate()
            self.txt_raw.insert("end", "\n[Process stopped]\n")
            self.current_process = None

        # Also stop auto-analyze if running
        if self.auto_analyze_running:
            self.auto_analyze_running = False
            self.auto_analyze_progress.set("Analysis stopped by user")
            self.txt_raw.insert("end", "\n[Auto-analysis stopped]\n")

    def _initialize_rag(self):
        """Load Volatility knowledge base for Ask Syd"""
        try:
            self.log_to_asksyd("[LOADING] Loading Volatility knowledge...")

            # 1. Load embedding model using safe loader
            try:
                self.embed_model = load_embedding_model("all-MiniLM-L6-v2")
                self.log_to_asksyd("[OK] Embedding model loaded on cpu")
            except Exception as e:
                # Fallback if safe loader fails - disable RAG
                self.log_to_asksyd("[WARNING] Ask Syd knowledge base could not load. Ensure 'hf_home' folder is present.")
                self.log_to_asksyd("[INFO] Volatility analysis still works.")
                self.rag_ready = False
                return

            # 2. Load Volatility FAISS index
            import faiss
            import pickle
            from pathlib import Path

            faiss_path = BASE_PATH / "rag_engine" / "embeddings" / "customers" / "customer_syd_volatility_knowledge_Volatility3.faiss"
            pkl_path = BASE_PATH / "rag_engine" / "embeddings" / "customers" / "customer_syd_volatility_knowledge_Volatility3.pkl"

            self.faiss_index = faiss.read_index(str(faiss_path))
            with open(pkl_path, 'rb') as f:
                self.chunks = pickle.load(f)
            self.log_to_asksyd(f"[OK] Loaded {len(self.chunks)} Volatility knowledge chunks")

            # 3. Get shared LLM (single instance for all tools)
            self.llm = get_shared_llm()
            self.log_to_asksyd("[OK] Using shared LLM (Qwen 2.5 14B)")

            # 4. Initialize Volatility fact extractor (mirrors Nmap architecture)
            from volatility_fact_extractor import VolatilityFactExtractor
            self.fact_extractor = VolatilityFactExtractor()
            self.log_to_asksyd("[OK] Volatility fact extractor ready (comprehensive pattern extraction)")

            self.rag_ready = True
            self.log_to_asksyd("[SUCCESS] Ask Syd ready! Type your Volatility question.")

        except Exception as e:
            self.log_to_asksyd("[WARNING] Ask Syd knowledge base could not load. Ensure 'hf_home' folder is present.")
            import traceback
            traceback.print_exc()

    def _clear_chat_and_output(self):
        """Clear all chat and output screens for Volatility"""
        # Clear Ask Syd chat
        self.txt_chat.delete('1.0', tk.END)
        # Clear input field
        self.entry_question.delete('1.0', tk.END)
        # Clear raw output
        self.txt_raw.delete('1.0', tk.END)
        # Clear parsed results tree
        for item in self.tree_results.get_children():
            self.tree_results.delete(item)
        # Clear log
        self.txt_log.delete('1.0', tk.END)
        # Log the clear action
        self.log_to_asksyd("[INFO] Chat and output cleared")

    def _send_to_syd(self):
        """Handle Send button - query RAG system"""
        if not self.rag_ready:
            from tkinter import messagebox
            messagebox.showwarning("Ask Syd", "Still loading knowledge base, please wait...")
            return

        question = self.entry_question.get("1.0", tk.END).strip()
        if not question:
            return

        self.entry_question.delete("1.0", tk.END)
        self.append_chat_message("You", question)

        # Show "Syd is thinking..." indicator
        self.show_thinking_indicator()

        def query_rag():
            try:
                # === STAGE A: USE PRE-COMPUTED FACTS OR EXTRACT FROM RAW OUTPUT ===
                # CRITICAL FIX: Check for pre-computed facts FIRST (from auto-analyze)
                # Auto-analyze stores facts in self.current_facts and self.current_facts_text
                # but doesn't write full plugin output to txt_raw (only progress messages)

                facts = None
                facts_text = None

                # Check if we have pre-computed facts from auto-analyze
                if hasattr(self, 'current_facts') and self.current_facts:
                    # Count items in pre-computed facts to verify it's not empty
                    fact_count = (len(self.current_facts.get('processes', [])) +
                                 len(self.current_facts.get('network_connections', [])) +
                                 len(self.current_facts.get('command_lines', [])) +
                                 len(self.current_facts.get('malfind_results', [])))

                    if fact_count > 0:
                        # Use pre-computed facts from auto-analyze
                        facts = self.current_facts
                        if hasattr(self, 'current_facts_text') and self.current_facts_text:
                            facts_text = self.current_facts_text
                        else:
                            facts_text = self.fact_extractor.facts_to_text(facts)

                # Fallback: Extract facts from auto_analyze_results if available
                if facts is None and hasattr(self, 'auto_analyze_results') and self.auto_analyze_results:
                    try:
                        if not hasattr(self, 'fact_extractor'):
                            from volatility_fact_extractor import VolatilityFactExtractor
                            self.fact_extractor = VolatilityFactExtractor()

                        # Extract per-plugin to avoid cross-contamination
                        facts = {
                            "plugin_type": "multiple",
                            "processes": [], "network_connections": [], "command_lines": [],
                            "dll_list": [], "malfind_results": [], "registry_keys": [],
                            "file_handles": [], "metadata": {},
                            "all_pids": [], "all_process_names": [], "all_ips": [], "all_ports": []
                        }

                        for plugin, output in self.auto_analyze_results.items():
                            try:
                                clean_output = "\n".join(
                                    line for line in output.split("\n")
                                    if not line.strip().startswith("Progress:")
                                    and "Volatility 3 Framework" not in line
                                )
                                if not clean_output.strip():
                                    continue
                                plugin_facts = self.fact_extractor.extract_facts(clean_output)
                                for key in ["processes", "network_connections", "command_lines", "dll_list",
                                           "malfind_results", "registry_keys", "file_handles"]:
                                    if key in plugin_facts and plugin_facts[key]:
                                        facts[key].extend(plugin_facts[key])
                                for key in ["all_pids", "all_process_names", "all_ips", "all_ports"]:
                                    if key in plugin_facts and plugin_facts[key]:
                                        facts[key] = list(set(facts[key] + plugin_facts[key]))
                            except Exception:
                                pass

                        # Supplement with grid-format parsing (malfind, netscan)
                        facts = self._supplement_facts_from_grid_output(facts)

                        fact_count = (len(facts.get('processes', [])) +
                                     len(facts.get('network_connections', [])) +
                                     len(facts.get('command_lines', [])) +
                                     len(facts.get('malfind_results', [])))

                        if fact_count > 0:
                            facts_text = self.fact_extractor.facts_to_text(facts)
                            self.current_facts = facts
                            self.current_facts_text = facts_text
                        else:
                            facts = None  # Reset so we fall through to next fallback
                    except Exception as e:
                        facts = None

                # Fall back to parsing txt_raw if no pre-computed facts
                if facts is None:
                    # Thread-safe read from Tkinter widget
                    _output_holder = [None]
                    _event = threading.Event()
                    def _read_output():
                        _output_holder[0] = self.txt_raw.get("1.0", tk.END).strip()
                        _event.set()
                    self.after(0, _read_output)
                    _event.wait(timeout=5)
                    current_output = _output_holder[0] or ""

                    # Check if we have Volatility output or if this is a general question
                    if not current_output or len(current_output) < 50:
                        # No Volatility data - answer general questions using knowledge base only
                        import faiss
                        query_vec = self.embed_model.encode([question]).astype('float32')
                        faiss.normalize_L2(query_vec)
                        distances, indices = self.faiss_index.search(query_vec, 5)

                        contexts = []
                        for idx in indices[0]:
                            if idx < len(self.chunks):
                                chunk = self.chunks[idx]
                                text = chunk.get('content', str(chunk))
                                contexts.append(text)
                        context_text = "\n\n".join(contexts)

                        # Build general knowledge prompt
                        system_prompt = f"""You are Syd, an expert memory forensics analyst specializing in Volatility 3, incident response, and exploit analysis.

The user has asked a general question without providing memory dump data. Answer their question using your knowledge of Volatility, memory forensics, malware analysis, and exploitation techniques.

KNOWLEDGE BASE:
{context_text}

RESPONSE GUIDELINES:
- Provide clear, practical explanations
- Include examples when helpful
- Mention relevant Volatility plugins and techniques
- If asked about exploits or malware, provide guidance on analysis, reverse engineering, and proof-of-concept development for authorized security testing
- If asked about CVEs, explain the vulnerability and how it manifests in memory
- Keep answers concise but informative
- If the question requires memory dump data to answer, politely explain that and ask them to provide Volatility output"""

                        user_message = f"Question: {question}"

                        response = self.llm.create_chat_completion(
                            messages=[
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_message}
                            ],
                            max_tokens=1536,
                            temperature=0.2,
                            top_p=0.9,
                            stop=["Question:", "Q:"]
                        )
                        answer = response['choices'][0]['message']['content'].strip()
                        answer = tag_unverified_cves(answer)

                        # Remove thinking indicator and show answer
                        self.after(0, lambda: self.remove_thinking_indicator())
                        self.after(0, lambda: self.append_chat_message("Syd", answer))
                        return

                    # CRITICAL: Use pre-computed facts from auto-analyze if available
                    # Auto-analyze stores complete facts in self.current_facts_text
                    # Extracting from txt_raw fails because it only has summary, not raw plugin output
                    if hasattr(self, 'current_facts_text') and self.current_facts_text:
                        facts_text = self.current_facts_text
                        facts = self.current_facts if hasattr(self, 'current_facts') else {}
                        print(f"[DEBUG] Using pre-computed facts from auto-analyze")
                    else:
                        # Fallback: Extract from txt_raw (for manual plugin runs)
                        facts = self.fact_extractor.extract_facts(current_output)
                        facts_text = self.fact_extractor.facts_to_text(facts)
                        self.current_facts = facts
                        print(f"[DEBUG] Extracting facts from txt_raw")

                # === STAGE B: GET KNOWLEDGE BASE CONTEXT ===
                # Get knowledge base context (for explaining concepts, not facts)
                import faiss
                query_vec = self.embed_model.encode([question]).astype('float32')
                faiss.normalize_L2(query_vec)
                distances, indices = self.faiss_index.search(query_vec, 3)

                contexts = []
                for idx in indices[0]:
                    if idx < len(self.chunks):
                        chunk = self.chunks[idx]
                        text = chunk.get('content', str(chunk))
                        contexts.append(text)
                context_text = "\n\n".join(contexts)

                # Truncate facts and context to fit within context window
                pre_trunc_len = len(facts_text)
                facts_text, context_text = truncate_for_context_window(
                    self.llm, facts_text, context_text,
                    max_tokens=1536, static_prompt_chars=2000
                )
                post_trunc_len = len(facts_text)
                print(f"[DEBUG] Volatility facts: {pre_trunc_len} chars -> {post_trunc_len} chars after truncation")
                if pre_trunc_len != post_trunc_len:
                    print(f"[DEBUG] WARNING: Facts were truncated by {pre_trunc_len - post_trunc_len} chars!")
                    # Check if key sections survived truncation
                    if "listening on which ports" in facts_text:
                        print(f"[DEBUG] ✓ Listening ports section survived truncation")
                    else:
                        print(f"[DEBUG] ✗ Listening ports section was TRUNCATED!")
                    if "code injection" in facts_text:
                        print(f"[DEBUG] ✓ Code injection section survived truncation")
                    else:
                        print(f"[DEBUG] ✗ Code injection section was TRUNCATED!")

                # === STAGE C: BUILD FACT-BASED PROMPT (mirrors Nmap/BloodHound architecture) ===
                system_prompt = f"""You are Syd, an expert memory forensics analyst analyzing Volatility 3 output.

ANSWERING STRATEGY (3-Tier Approach):

1. SPECIFIC MEMORY DUMP DATA (Facts-First - NEVER Invent):
   - For PIDs, process names, network connections, command lines: Use ONLY the facts below
   - NEVER invent: PIDs, process names, IP addresses, ports, memory addresses
   - If not in facts, say "Not present in this memory dump"
   - When asked for "specific" values (addresses, IPs, ports), extract EXACT values from facts
   - Example: If asked for memory addresses, quote the exact hex addresses like "0x0000021b7c000000"

2. INFERENCE FROM EVIDENCE (Connect the Dots):
   - Process relationships: Parent/child process trees indicate behavior
   - Network connections: Unusual IPs or ports = C2 communication
   - Command lines: Suspicious arguments = malware activity
   - Memory protection: PAGE_EXECUTE_READWRITE = code injection
   - Use phrases like: "Based on the findings..." or "This indicates..."
   - NETWORK DIRECTION: Local IP is the COMPROMISED machine, Remote IP is the TARGET/destination

3. GENERAL FORENSICS KNOWLEDGE (Explain Concepts):
   - Definitions: What malfind is, how process injection works
   - Analysis techniques: How to investigate suspicious processes
   - Use phrases like: "In memory forensics..." or "This technique works by..."

CRITICAL RULES:
- When user asks "List X" or "Give me X only" → Provide ONLY the requested data, no explanations
- When user asks for "specific" or "exact" values → Extract precise values from facts (addresses, IPs, PIDs)
- When user asks "Are any connecting to..." → Only confirm if you have EVIDENCE, don't speculate

CRITICAL RULES:
   - If the user asks about a specific CVE by number, you may discuss it - explain the vulnerability and exploitation approach.
   - Do NOT invent additional CVE numbers on your own. If you want to mention a vulnerability class, describe it by name without guessing a CVE number.
   - When discussing exploits, focus on the TECHNIQUE rather than guessing CVE numbers.

FACTS FROM THIS MEMORY DUMP:
{facts_text}

KNOWLEDGE BASE (for general Volatility/forensics concepts):
{context_text}

RESPONSE FORMAT:
- Start with facts from the memory dump
- Add inferences based on evidence
- Include general knowledge if helpful
- Always distinguish: Facts vs Inference vs General knowledge"""

                user_message = f"Question: {question}\n\nAnswer based on the facts above:"

                # === STAGE D: GENERATE WITH LLM ===
                response = self.llm.create_chat_completion(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ],
                    max_tokens=1536,
                    temperature=0.1,
                    top_p=0.9,
                    stop=["Question:", "Q:", "\n\n\n"]
                )
                answer = response['choices'][0]['message']['content'].strip()
                answer = tag_unverified_cves(answer)

                # Aggressive repetition detection and truncation (same as BloodHound)
                lines = answer.split('\n')
                seen = {}
                clean_lines = []
                max_lines = 60

                for i, line in enumerate(lines):
                    if i >= max_lines:
                        break

                    line_normalized = ''.join([c for c in line if not c.isdigit()]).strip()[:60]

                    if len(line_normalized) < 10:
                        clean_lines.append(line)
                        continue

                    if line_normalized in seen:
                        seen[line_normalized] += 1
                        if seen[line_normalized] >= 2:
                            break
                    else:
                        seen[line_normalized] = 1

                    clean_lines.append(line)

                answer = '\n'.join(clean_lines)

                # === STAGE E: VALIDATION LAYER (mirrors Nmap/BloodHound architecture) ===
                # Validate answer against extracted facts to prevent hallucinations
                validation_result = self.fact_extractor.validate_answer(answer, facts)

                if not validation_result['valid']:
                    # Warn about potential hallucination but show full answer
                    warning = f"[WARNING - POSSIBLE HALLUCINATION]\n\n"
                    warning += f"Syd's answer may contain information not confirmed in the memory dump:\n"
                    for violation in validation_result['violations']:
                        warning += f"  - {violation}\n"
                    warning += f"\nPlease verify the following answer against your analysis results:\n"
                    warning += f"{'=' * 50}\n\n"
                    answer = warning + answer

                # Remove thinking indicator and show answer
                self.after(0, lambda: self.remove_thinking_indicator())
                self.after(0, lambda: self.append_chat_message("Syd", answer))

            except Exception as e:
                error_msg = f"Error processing question: {str(e)}"
                self.after(0, lambda: self.remove_thinking_indicator())
                self.after(0, lambda: self.append_chat_message("System", error_msg))
                import traceback
                traceback.print_exc()

        import threading
        threading.Thread(target=query_rag, daemon=True).start()

    def _upload_data(self):
        """Handle Upload button - upload memory dumps or results to chat"""
        from tkinter import filedialog, messagebox
        import os

        filepath = filedialog.askopenfilename(
            title="Select file to upload",
            filetypes=[("Memory Dumps", "*.mem *.raw *.dmp *.vmem"), ("Text files", "*.txt"), ("All files", "*.*")]
        )

        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                self.txt_chat.insert(tk.END, f"\n[UPLOADED: {os.path.basename(filepath)}]\n")
                self.txt_chat.insert(tk.END, content[:5000])  # Limit to 5000 chars
                if len(content) > 5000:
                    self.txt_chat.insert(tk.END, "\n\n[... truncated ...]")
                self.txt_chat.see(tk.END)

            except Exception as e:
                messagebox.showerror("Upload Error", str(e))

    def log_to_asksyd(self, message):
        """Log messages to Ask Syd log panel (thread-safe)"""
        def _update():
            self.txt_log.insert(tk.END, f"{message}\n")
            self.txt_log.see(tk.END)

        # Schedule GUI update on main thread
        try:
            self.after(0, _update)
        except:
            pass

    def show_thinking_indicator(self):
        """Show 'Syd is thinking...' with animated dots"""
        # Store the starting position of the thinking message
        self.thinking_start = self.txt_chat.index(tk.END)

        # Add the thinking message
        self.txt_chat.insert(tk.END, f"\n{'='*60}\n")
        self.txt_chat.insert(tk.END, "[Syd]\n")
        self.thinking_text_start = self.txt_chat.index(tk.END)
        self.txt_chat.insert(tk.END, "Thinking.\n")
        self.txt_chat.see(tk.END)

        # Start animation
        self.thinking_dots = 1
        self.thinking_active = True
        self.animate_thinking()

    def animate_thinking(self):
        """Animate the thinking dots"""
        if not self.thinking_active:
            return

        # Update dots
        self.thinking_dots = (self.thinking_dots % 3) + 1
        dots = "." * self.thinking_dots

        try:
            # Update the thinking text
            self.txt_chat.delete(self.thinking_text_start, f"{self.thinking_text_start} lineend")
            self.txt_chat.insert(self.thinking_text_start, f"Thinking{dots}")
            self.txt_chat.see(tk.END)
        except:
            pass  # If something goes wrong, just stop animating

        # Schedule next animation frame
        if self.thinking_active:
            self.after(500, self.animate_thinking)

    def remove_thinking_indicator(self):
        """Remove the 'Syd is thinking...' message"""
        self.thinking_active = False

        try:
            # Delete the thinking message
            if hasattr(self, 'thinking_start'):
                self.txt_chat.delete(self.thinking_start, tk.END)
        except:
            pass  # If something goes wrong, just continue

    def append_chat_message(self, sender, message):
        """Append a message to the chat display"""
        self.txt_chat.insert(tk.END, f"\n{'='*60}\n")
        self.txt_chat.insert(tk.END, f"[{sender}]\n")
        self.txt_chat.insert(tk.END, f"{message}\n")
        self.txt_chat.see(tk.END)

    def _create_context_menu(self, widget):
        """Add right-click copy/paste menu to Text widget"""
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="Cut", command=lambda: widget.event_generate("<<Cut>>"))
        menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
        menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_separator()
        menu.add_command(label="Select All", command=lambda: widget.tag_add("sel", "1.0", "end"))

        def show_menu(event):
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        widget.bind("<Button-3>", show_menu)  # Right-click

    def _copy_all_processes(self):
        """Copy all processes from Treeview to clipboard in TSV format"""
        try:
            items = self.tree_results.get_children()
            if not items:
                from tkinter import messagebox
                messagebox.showinfo("Copy All Processes", "No processes to copy.")
                return

            # Build TSV output
            output_lines = []
            output_lines.append("PID\tProcess\tPPID\tThreads\tHandles\tDetails")
            output_lines.append("-" * 80)

            for item in items:
                values = self.tree_results.item(item, "values")
                if values:
                    pid = values[0] if len(values) > 0 else ""
                    process = values[1] if len(values) > 1 else ""
                    ppid = values[2] if len(values) > 2 else ""
                    threads = values[3] if len(values) > 3 else ""
                    handles = values[4] if len(values) > 4 else ""
                    details = values[5] if len(values) > 5 else ""
                    output_lines.append(f"{pid}\t{process}\t{ppid}\t{threads}\t{handles}\t{details}")

            output_text = "\n".join(output_lines)

            # Copy to clipboard
            self.clipboard_clear()
            self.clipboard_append(output_text)
            self.clipboard_append("")  # Ensure it stays in clipboard

            from tkinter import messagebox
            messagebox.showinfo("Copy All Processes", f"Copied {len(items)} processes to clipboard.\n\nPaste into Excel for tab-separated columns.")

        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror("Copy Error", f"Failed to copy processes: {e}")


class StandardToolPage(ttk.Frame):
    """Standard tool page with Ask Syd panel - used by all tools"""

    # Tool path configurations - which tools need executable paths
    TOOL_PATHS = {
        # Red Team
        "Metasploit": {"cmd": "msfconsole", "test_arg": "--version"},
        "Sliver": {"cmd": "sliver-client", "test_arg": "version"},
        "CrackMapExec": {"cmd": "crackmapexec", "test_arg": "--version"},
        "Impacket": {"cmd": "impacket-smbclient", "test_arg": "-h"},
        "Responder": {"cmd": "responder", "test_arg": "-h"},
        "Hashcat": {"cmd": "hashcat", "test_arg": "--version"},
        "Feroxbuster": {"cmd": "feroxbuster", "test_arg": "--version"},
        "Curl/Ncat": {"cmd": "curl", "test_arg": "--version"},
        # Blue Team
        "Zeek": {"cmd": "zeek", "test_arg": "--version"},
        "YARA": {"cmd": "yara", "test_arg": "--version"},
        "Chainsaw": {"cmd": "chainsaw", "test_arg": "--version"},
        "Suricata": {"cmd": "suricata", "test_arg": "--version"},
        "TShark": {"cmd": "tshark", "test_arg": "--version"},
        "Autopsy/SleuthKit": {"cmd": "fls", "test_arg": "-V"},
    }

    def __init__(self, parent, tool_name):
        super().__init__(parent)

        self.tool_name = tool_name
        self.tool_path = tk.StringVar()
        self.has_path_config = tool_name in self.TOOL_PATHS

        # Layout: Two columns (Left: Tool, Right: Ask Syd Panel)
        main_paned = ttk.PanedWindow(self, orient="horizontal")
        main_paned.pack(fill="both", expand=True)

        left_frame = ttk.Frame(main_paned)
        right_frame = ttk.Frame(main_paned)
        main_paned.add(left_frame, weight=3)
        main_paned.add(right_frame, weight=2)
        right_frame.configure(width=500)

        # ========== LEFT COLUMN: Controls & Output ==========
        controls_frame = ttk.Frame(left_frame)
        controls_frame.pack(fill="x", padx=5, pady=5)

        ttk.Label(controls_frame, text=f"{tool_name}", style="Header.TLabel").pack(anchor="w", pady=(0,10))

        # Path configuration (if tool needs it)
        if self.has_path_config:
            path_frame = ttk.Frame(controls_frame)
            path_frame.pack(fill="x", pady=(0,8))
            ttk.Label(path_frame, text="Tool Path:").pack(side="left", padx=5)

            # Auto-detect default path
            default_path = self.TOOL_PATHS[tool_name]["cmd"]
            self.tool_path.set(default_path)

            path_entry = ttk.Entry(path_frame, textvariable=self.tool_path, width=35)
            path_entry.pack(side="left", fill="x", expand=True, padx=5)
            ttk.Button(path_frame, text="Browse", command=self._browse_path).pack(side="left", padx=2)
            ttk.Button(path_frame, text="Test", command=self._test_tool).pack(side="left")

        # Status label
        self.lbl_status = ttk.Label(controls_frame, text=f"{tool_name} ready", foreground=INK_SOFT)
        self.lbl_status.pack(side="left", padx=5, pady=5)

        # Tabbed output area
        results_frame = ttk.Frame(left_frame)
        results_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.tabs_output = ttk.Notebook(results_frame)
        self.tabs_output.pack(fill="both", expand=True)

        # Tab 1: Output
        tab_output = ttk.Frame(self.tabs_output)
        self.tabs_output.add(tab_output, text="Output")

        self.txt_output = tk.Text(tab_output, bg=BG_DARK, fg=INK, wrap="word", state="normal")
        output_scroll = ttk.Scrollbar(tab_output, orient="vertical", command=self.txt_output.yview)
        self.txt_output.configure(yscrollcommand=output_scroll.set)
        self.txt_output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

        # Tab 2: Results (parsed/formatted output)
        tab_results = ttk.Frame(self.tabs_output)
        self.tabs_output.add(tab_results, text="Results")

        self.txt_results = tk.Text(tab_results, bg=BG_DARK, fg=INK, wrap="word", state="normal")
        results_scroll = ttk.Scrollbar(tab_results, orient="vertical", command=self.txt_results.yview)
        self.txt_results.configure(yscrollcommand=results_scroll.set)
        self.txt_results.pack(side="left", fill="both", expand=True)
        results_scroll.pack(side="right", fill="y")

        # Tab 3: Paste/Input
        tab_paste = ttk.Frame(self.tabs_output)
        self.tabs_output.add(tab_paste, text="Paste/Input")

        paste_header = ttk.Frame(tab_paste)
        paste_header.pack(fill="x", padx=5, pady=5)
        ttk.Label(paste_header, text=f"Paste {tool_name} output or input commands:", style="Header.TLabel").pack(side="left")

        self.txt_paste = tk.Text(tab_paste, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word")
        paste_scroll = ttk.Scrollbar(tab_paste, orient="vertical", command=self.txt_paste.yview)
        self.txt_paste.configure(yscrollcommand=paste_scroll.set)
        self.txt_paste.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        paste_scroll.pack(side="right", fill="y")

        # ========== RIGHT COLUMN (Ask Syd Panel) ==========
        # Header bar
        header = ttk.Frame(right_frame)
        header.pack(fill="x", padx=5, pady=5)

        title_row = ttk.Frame(header)
        title_row.pack(fill="x")
        ttk.Label(title_row, text=f"Ask Syd - {tool_name} Expert", style="Header.TLabel").pack(side="left")
        badge = ttk.Label(title_row, text="Fresh Context", background=ACCENT, foreground="#fff", padding=(5,2))
        badge.pack(side="left", padx=10)

        controls_row = ttk.Frame(header)
        controls_row.pack(fill="x", pady=(5,0))
        ttk.Label(controls_row, text="Tool:").pack(side="left", padx=5)
        self.cmb_tool = ttk.Combobox(controls_row, values=[tool_name], state="readonly", width=15)
        self.cmb_tool.current(0)
        self.cmb_tool.pack(side="left", padx=5)

        source_row = ttk.Frame(header)
        source_row.pack(fill="x", pady=(5,0))
        ttk.Label(source_row, text="Source:").pack(side="left", padx=5)
        self.var_source = tk.StringVar(value="Syd")
        ttk.Radiobutton(source_row, text="Syd", variable=self.var_source, value="Syd").pack(side="left", padx=5)
        ttk.Radiobutton(source_row, text="Customer", variable=self.var_source, value="Customer").pack(side="left", padx=5)

        # Main chat region
        chat_frame = ttk.Frame(right_frame)
        chat_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.txt_chat = tk.Text(chat_frame, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word", height=20)
        scroll_chat = ttk.Scrollbar(chat_frame, command=self.txt_chat.yview)
        self.txt_chat.configure(yscrollcommand=scroll_chat.set)
        self.txt_chat.pack(side="left", fill="both", expand=True)
        scroll_chat.pack(side="right", fill="y")

        # Lower log panel
        log_frame = ttk.Frame(right_frame)
        log_frame.pack(fill="both", expand=False, padx=5, pady=5)

        self.txt_log = tk.Text(log_frame, bg=BG_DARK, fg=INK_SOFT, insertbackground=INK, wrap="word", height=6)
        scroll_log = ttk.Scrollbar(log_frame, command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=scroll_log.set)
        self.txt_log.pack(side="left", fill="both", expand=True)
        scroll_log.pack(side="right", fill="y")

        # Input field for questions - multiline text widget
        input_frame = ttk.Frame(right_frame)
        input_frame.pack(fill="both", expand=False, padx=5, pady=(5,0))

        self.entry_question = tk.Text(input_frame, height=3, bg=BG_DARK, fg=INK,
                                     insertbackground=INK, wrap="word", font=('Consolas', 10))
        self.entry_question.pack(fill="both", expand=True)
        self.entry_question.bind('<Control-Return>', lambda e: self._send_to_syd())

        # Bottom buttons
        bottom_btns = ttk.Frame(right_frame)
        bottom_btns.pack(fill="x", padx=5, pady=5)
        ttk.Button(bottom_btns, text="Send (Ctrl+Enter)", command=self._send_to_syd).pack(side="left", padx=5)
        ttk.Button(bottom_btns, text="Upload data...", command=self._upload_data).pack(side="left", padx=5)

        # Log initial message
        self.log_to_asksyd(f"[INFO] {tool_name} ready")
        if self.has_path_config:
            self.log_to_asksyd(f"[INFO] Click 'Test' to verify {tool_name} installation")
        else:
            self.log_to_asksyd(f"[INFO] {tool_name} is an internal tool - no external dependencies")

    def _browse_path(self):
        """Browse for tool executable"""
        filename = filedialog.askopenfilename(
            title=f"Select {self.tool_name} executable",
            filetypes=[("Executables", "*.exe *.bat *.sh"), ("All Files", "*.*")]
        )
        if filename:
            self.tool_path.set(filename)
            self.log_to_asksyd(f"Path set to: {filename}")

    def _test_tool(self):
        """Test tool installation"""
        if not self.has_path_config:
            return

        tool_cmd = self.tool_path.get().strip()
        if not tool_cmd:
            messagebox.showwarning("No Path", f"Please set the {self.tool_name} path first")
            return

        try:
            test_arg = self.TOOL_PATHS[self.tool_name]["test_arg"]
            result = subprocess.run(
                [tool_cmd, test_arg],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = result.stdout + result.stderr

            if result.returncode == 0 or len(output) > 0:
                self.log_to_asksyd(f"[OK] {self.tool_name} test successful\n\n{output[:200]}")
                messagebox.showinfo("Test Successful", f"{self.tool_name} is working correctly!")
            else:
                self.log_to_asksyd(f"[ERROR] {self.tool_name} test failed\n\n{output}")
                messagebox.showerror("Test Failed", f"{self.tool_name} test failed.\n\n{output[:300]}")

        except FileNotFoundError:
            msg = f"{self.tool_name} not found. Please install {self.tool_name} or set the path manually."
            self.log_to_asksyd(f"[ERROR] {msg}")
            messagebox.showerror(f"{self.tool_name} Not Found", msg)
        except Exception as e:
            self.log_to_asksyd(f"[ERROR] Error: {str(e)}")
            messagebox.showerror("Test Error", str(e))

    def log_to_asksyd(self, message):
        """Log messages to Ask Syd log panel (thread-safe)"""
        def _update():
            self.txt_log.insert(tk.END, f"{message}\n")
            self.txt_log.see(tk.END)

        # Schedule GUI update on main thread
        try:
            self.after(0, _update)
        except:
            pass

    def _send_to_syd(self):
        """Send question to Ask Syd (placeholder - no RAG for most tools yet)"""
        question = self.entry_question.get("1.0", "end").strip()

        if not question:
            return

        # Display user question
        self.append_chat_message("YOU", question)
        self.entry_question.delete("1.0", "end")

        # Placeholder response - no RAG available yet
        response = f"""[INFO] {self.tool_name} RAG is not yet implemented.

This tool is ready for your use. Check the Output and Results tabs for tool execution results.

For {self.tool_name} documentation and help:
- Official documentation
- Community forums
- HackTricks: https://book.hacktricks.xyz/"""

        self.append_chat_message("SYD", response)

    def _upload_data(self):
        """Upload a file to the chat (for context)"""
        filepath = filedialog.askopenfilename(
            title="Select file to upload",
            filetypes=[("Text files", "*.txt"), ("Log files", "*.log"), ("All files", "*.*")]
        )

        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                self.txt_chat.insert(tk.END, f"\n[UPLOADED: {os.path.basename(filepath)}]\n")
                self.txt_chat.insert(tk.END, content[:5000])  # Limit to 5000 chars
                if len(content) > 5000:
                    self.txt_chat.insert(tk.END, "\n\n[... truncated ...]")
                self.txt_chat.see(tk.END)

            except Exception as e:
                messagebox.showerror("Upload Error", str(e))

    def append_chat_message(self, sender, message):
        """Append a message to the chat display"""
        self.txt_chat.insert(tk.END, f"\n{'='*60}\n")
        self.txt_chat.insert(tk.END, f"[{sender}]\n")
        self.txt_chat.insert(tk.END, f"{message}\n")
        self.txt_chat.see(tk.END)


class GenericToolPage(StandardToolPage):
    """Alias for backward compatibility"""
    pass

class BloodHoundPage(ttk.Frame):
    """BloodHound Active Directory Analysis Interface"""

    def __init__(self, parent):
        super().__init__(parent)

        # State
        self.json_path = tk.StringVar()
        self.current_vulnerabilities = None

        # RAG components for BloodHound
        self.embed_model = None
        self.llm = None
        self.faiss_index = None
        self.chunks = None
        self.rag_ready = False

        # Layout: Two columns (Left: Tool, Right: Ask Syd Panel)
        main_paned = ttk.PanedWindow(self, orient="horizontal")
        main_paned.pack(fill="both", expand=True)

        left_frame = ttk.Frame(main_paned)
        right_frame = ttk.Frame(main_paned)
        main_paned.add(left_frame, weight=3)
        main_paned.add(right_frame, weight=2)
        right_frame.configure(width=500)

        # ========== LEFT COLUMN: Controls & Results ==========
        controls_frame = ttk.Frame(left_frame)
        controls_frame.pack(fill="x", padx=5, pady=5)

        ttk.Label(controls_frame, text="BloodHound - AD Analysis", style="Header.TLabel").pack(anchor="w", pady=(0,10))

        # File selector
        file_frame = ttk.Frame(controls_frame)
        file_frame.pack(fill="x", pady=(0,8))
        ttk.Label(file_frame, text="JSON/ZIP File:").pack(side="left", padx=5)
        file_entry = ttk.Entry(file_frame, textvariable=self.json_path, width=35)
        file_entry.pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(file_frame, text="Browse", command=self._browse_file).pack(side="left", padx=2)
        ttk.Button(file_frame, text="Analyze", command=self._analyze_file).pack(side="left")

        # Status label
        self.lbl_status = ttk.Label(controls_frame, text="BloodHound ready", foreground=INK_SOFT)
        self.lbl_status.pack(side="left", padx=5, pady=5)

        # Tabbed results area
        results_frame = ttk.Frame(left_frame)
        results_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.tabs_results = ttk.Notebook(results_frame)
        self.tabs_results.pack(fill="both", expand=True)

        # Tab 1: Raw JSON
        tab_raw = ttk.Frame(self.tabs_results)
        self.tabs_results.add(tab_raw, text="Raw JSON")

        self.txt_raw = tk.Text(tab_raw, bg=BG_DARK, fg=INK, wrap="word", state="normal")
        raw_scroll = ttk.Scrollbar(tab_raw, orient="vertical", command=self.txt_raw.yview)
        self.txt_raw.configure(yscrollcommand=raw_scroll.set)
        self.txt_raw.pack(side="left", fill="both", expand=True)
        raw_scroll.pack(side="right", fill="y")

        # Tab 2: Attack Paths (Treeview)
        tab_paths = ttk.Frame(self.tabs_results)
        self.tabs_results.add(tab_paths, text="Attack Paths")

        # Add "Copy All" button at top
        paths_header = ttk.Frame(tab_paths)
        paths_header.pack(fill="x", padx=5, pady=5)
        ttk.Button(paths_header, text="Copy All Attack Paths", command=self._copy_all_attack_paths).pack(side="right")

        self.tree_paths = ttk.Treeview(tab_paths, columns=("Source", "Permission", "Target", "Risk"), show="tree headings")
        self.tree_paths.heading("#0", text="ID")
        self.tree_paths.heading("Source", text="Source")
        self.tree_paths.heading("Permission", text="Permission")
        self.tree_paths.heading("Target", text="Target")
        self.tree_paths.heading("Risk", text="Risk")
        self.tree_paths.column("#0", width=50)
        self.tree_paths.column("Source", width=150)
        self.tree_paths.column("Permission", width=150)
        self.tree_paths.column("Target", width=150)
        self.tree_paths.column("Risk", width=80)

        paths_scroll = ttk.Scrollbar(tab_paths, orient="vertical", command=self.tree_paths.yview)
        self.tree_paths.configure(yscrollcommand=paths_scroll.set)
        self.tree_paths.pack(side="left", fill="both", expand=True)
        paths_scroll.pack(side="right", fill="y")

        # Tab 3: Vulnerabilities (Treeview)
        tab_vulns = ttk.Frame(self.tabs_results)
        self.tabs_results.add(tab_vulns, text="Vulnerabilities")

        # Add "Copy All" button at top
        vulns_header = ttk.Frame(tab_vulns)
        vulns_header.pack(fill="x", padx=5, pady=5)
        ttk.Button(vulns_header, text="Copy All Vulnerabilities", command=self._copy_all_vulnerabilities).pack(side="right")

        self.tree_vulns = ttk.Treeview(tab_vulns, columns=("Type", "Account", "Details"), show="tree headings")
        self.tree_vulns.heading("#0", text="ID")
        self.tree_vulns.heading("Type", text="Type")
        self.tree_vulns.heading("Account", text="Account")
        self.tree_vulns.heading("Details", text="Details")
        self.tree_vulns.column("#0", width=50)
        self.tree_vulns.column("Type", width=150)
        self.tree_vulns.column("Account", width=200)
        self.tree_vulns.column("Details", width=250)

        vulns_scroll = ttk.Scrollbar(tab_vulns, orient="vertical", command=self.tree_vulns.yview)
        self.tree_vulns.configure(yscrollcommand=vulns_scroll.set)
        self.tree_vulns.pack(side="left", fill="both", expand=True)
        vulns_scroll.pack(side="right", fill="y")

        # Tab 4: Analysis Report
        self.tab_report = ttk.Frame(self.tabs_results)
        self.tabs_results.add(self.tab_report, text="Analysis Report")

        self.txt_report = tk.Text(self.tab_report, bg=BG_DARK, fg=INK, wrap="word", state="normal")
        report_scroll = ttk.Scrollbar(self.tab_report, orient="vertical", command=self.txt_report.yview)
        self.txt_report.configure(yscrollcommand=report_scroll.set)
        self.txt_report.pack(side="left", fill="both", expand=True)
        report_scroll.pack(side="right", fill="y")

        # Tab 5: Paste Results
        tab_paste = ttk.Frame(self.tabs_results)
        self.tabs_results.add(tab_paste, text="Paste Results")

        paste_header = ttk.Frame(tab_paste)
        paste_header.pack(fill="x", padx=5, pady=5)
        ttk.Label(paste_header, text="Paste BloodHound JSON or Cypher output:", style="Header.TLabel").pack(side="left")
        ttk.Button(paste_header, text="Analyze Pasted", command=self._analyze_paste).pack(side="right", padx=5)

        self.txt_paste = tk.Text(tab_paste, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word")
        paste_scroll = ttk.Scrollbar(tab_paste, orient="vertical", command=self.txt_paste.yview)
        self.txt_paste.configure(yscrollcommand=paste_scroll.set)
        self.txt_paste.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        paste_scroll.pack(side="right", fill="y")

        # ========== RIGHT COLUMN (Ask Syd Panel) ==========
        # Header bar
        header = ttk.Frame(right_frame)
        header.pack(fill="x", padx=5, pady=5)

        title_row = ttk.Frame(header)
        title_row.pack(fill="x")
        ttk.Label(title_row, text="Ask Syd - BloodHound Expert", style="Header.TLabel").pack(side="left")
        badge = ttk.Label(title_row, text="Fresh Context", background=ACCENT, foreground="#fff", padding=(5,2))
        badge.pack(side="left", padx=10)

        controls_row = ttk.Frame(header)
        controls_row.pack(fill="x", pady=(5,0))
        ttk.Label(controls_row, text="Tool:").pack(side="left", padx=5)
        self.cmb_tool = ttk.Combobox(controls_row, values=["BloodHound"], state="readonly", width=12)
        self.cmb_tool.current(0)
        self.cmb_tool.pack(side="left", padx=5)

        source_row = ttk.Frame(header)
        source_row.pack(fill="x", pady=(5,0))
        ttk.Label(source_row, text="Source:").pack(side="left", padx=5)
        self.var_source = tk.StringVar(value="Syd")
        ttk.Radiobutton(source_row, text="Syd", variable=self.var_source, value="Syd").pack(side="left", padx=5)
        ttk.Radiobutton(source_row, text="Customer", variable=self.var_source, value="Customer").pack(side="left", padx=5)

        # Main chat region
        chat_frame = ttk.Frame(right_frame)
        chat_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.txt_chat = tk.Text(chat_frame, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word", height=20)
        scroll_chat = ttk.Scrollbar(chat_frame, command=self.txt_chat.yview)
        self.txt_chat.configure(yscrollcommand=scroll_chat.set)
        self.txt_chat.pack(side="left", fill="both", expand=True)
        scroll_chat.pack(side="right", fill="y")

        # Lower log panel
        log_frame = ttk.Frame(right_frame)
        log_frame.pack(fill="both", expand=False, padx=5, pady=5)

        self.txt_log = tk.Text(log_frame, bg=BG_DARK, fg=INK_SOFT, insertbackground=INK, wrap="word", height=6)
        scroll_log = ttk.Scrollbar(log_frame, command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=scroll_log.set)
        self.txt_log.pack(side="left", fill="both", expand=True)
        scroll_log.pack(side="right", fill="y")

        # Input field for questions - multiline text widget
        input_frame = ttk.Frame(right_frame)
        input_frame.pack(fill="both", expand=False, padx=5, pady=(5,0))

        self.entry_question = tk.Text(input_frame, height=3, bg=BG_DARK, fg=INK,
                                     insertbackground=INK, wrap="word", font=('Consolas', 10))
        self.entry_question.pack(fill="both", expand=True)
        self.entry_question.bind('<Control-Return>', lambda e: self._send_to_syd())

        # Bottom buttons
        bottom_btns = ttk.Frame(right_frame)
        bottom_btns.pack(fill="x", padx=5, pady=5)
        ttk.Button(bottom_btns, text="Send (Ctrl+Enter)", command=self._send_to_syd).pack(side="left", padx=5)
        ttk.Button(bottom_btns, text="Clear Chat", command=self._clear_chat_and_output).pack(side="left", padx=5)
        ttk.Button(bottom_btns, text="Upload data...", command=self._upload_data).pack(side="left", padx=5)

        # Add right-click context menus for copy/paste
        self._create_context_menu(self.txt_raw)
        self._create_context_menu(self.txt_report)
        self._create_context_menu(self.txt_paste)
        self._create_context_menu(self.txt_chat)
        self._create_context_menu(self.txt_log)
        self._create_context_menu(self.entry_question)

        # Log initial message
        self.log_to_asksyd("[INFO] BloodHound analyzer ready")
        self.log_to_asksyd("[INFO] Load a JSON/ZIP file or paste BloodHound output to analyze")

        # Initialize RAG in background
        import threading
        threading.Thread(target=self._initialize_rag, daemon=True).start()

    def _initialize_rag(self):
        """Initialize BloodHound RAG system: Load FAISS + LLM"""
        try:
            self.log_to_asksyd("[LOADING] Loading BloodHound knowledge base...")

            # 1. Load embedding model using safe loader
            self.embed_model = load_embedding_model("all-MiniLM-L6-v2")
            self.log_to_asksyd("[OK] Embedding model loaded on cpu")

            # 2. Load BloodHound FAISS index
            faiss_path = BASE_PATH / "rag_engine" / "embeddings" / "customers" / "customer_syd_bloodhound_knowledge_BloodHound.faiss"
            pkl_path = BASE_PATH / "rag_engine" / "embeddings" / "customers" / "customer_syd_bloodhound_knowledge_BloodHound.pkl"

            if not faiss_path.exists() or not pkl_path.exists():
                self.log_to_asksyd("[ERROR] BloodHound knowledge files not found!")
                self.log_to_asksyd("[INFO] Run: python chunk_and_embed_bloodhound.py")
                return

            self.faiss_index = faiss.read_index(str(faiss_path))
            with open(pkl_path, 'rb') as f:
                self.chunks = pickle.load(f)
            self.log_to_asksyd(f"[OK] Loaded {len(self.chunks)} BloodHound knowledge chunks from database")

            # 3. Get shared LLM (single instance for all tools)
            self.llm = get_shared_llm()
            self.log_to_asksyd("[OK] Using shared LLM (Qwen 2.5 14B)")

            # 4. Initialize BloodHound fact extractor (mirrors Nmap architecture)
            from bloodhound_fact_extractor import BloodHoundFactExtractor
            self.fact_extractor = BloodHoundFactExtractor()
            self.log_to_asksyd("[OK] BloodHound fact extractor ready (comprehensive pattern extraction)")

            self.rag_ready = True
            self.log_to_asksyd("[SUCCESS] Ask Syd ready! Ask me about BloodHound, AD attacks, Cypher queries, etc.")

        except Exception as e:
            self.log_to_asksyd("[WARNING] Ask Syd knowledge base could not load. Ensure 'hf_home' folder is present.")
            import traceback
            traceback.print_exc()

    def _browse_file(self):
        """Browse for BloodHound JSON or ZIP file"""
        filename = filedialog.askopenfilename(
            title="Select BloodHound Export",
            filetypes=[
                ("BloodHound Files", "*.json *.zip"),
                ("JSON files", "*.json"),
                ("ZIP files", "*.zip"),
                ("All files", "*.*")
            ]
        )

        if filename:
            self.json_path.set(filename)

    def _analyze_file(self):
        """Analyze BloodHound file (JSON or ZIP)"""
        filepath = self.json_path.get().strip()

        if not filepath:
            from tkinter import messagebox
            messagebox.showwarning("No File", "Please select a BloodHound JSON or ZIP file")
            return

        # Check file size
        import os
        from tkinter import messagebox
        file_size_mb = os.path.getsize(filepath) / (1024 * 1024)

        if file_size_mb > 100:
            result = messagebox.askyesno(
                "Large File Warning",
                f"This file is {file_size_mb:.1f}MB.\n\n"
                "Files over 100MB may cause performance issues or GUI freezing.\n\n"
                "Recommended: Use smaller BloodHound exports or analyze specific JSON files.\n\n"
                "Continue anyway?"
            )
            if not result:
                return
        elif file_size_mb > 50:
            messagebox.showinfo(
                "Performance Notice",
                f"This file is {file_size_mb:.1f}MB.\n\n"
                "Analysis may take 10-30 seconds. Please be patient."
            )

        self.lbl_status.configure(text="Analyzing...")
        self.txt_raw.delete("1.0", "end")
        self.tree_paths.delete(*self.tree_paths.get_children())
        self.tree_vulns.delete(*self.tree_vulns.get_children())
        self.txt_report.delete("1.0", "end")

        try:
            json_data = None

            if filepath.endswith('.zip'):
                # Analyze ZIP file
                from bloodhound_analyzer import analyze_bloodhound_zip
                import zipfile
                import json

                report, vulnerabilities = analyze_bloodhound_zip(filepath)

                self.txt_raw.insert("1.0", f"[ZIP FILE ANALYZED: {filepath}]\n\n")
                self.txt_raw.insert("end", "ZIP files contain multiple JSON files. See Analysis Report for full details.")

                # CRITICAL FIX: Extract JSON data from ZIP for fact extraction
                try:
                    combined_data = {'users': [], 'computers': [], 'groups': []}
                    with zipfile.ZipFile(filepath, 'r') as zf:
                        json_files = [f for f in zf.namelist() if f.endswith('.json')]
                        for json_file in json_files:
                            with zf.open(json_file) as f:
                                try:
                                    file_data = json.load(f)
                                    # Combine data from multiple JSON files
                                    if isinstance(file_data, dict) and 'data' in file_data:
                                        # Old format - need to classify objects
                                        if 'users' in json_file.lower():
                                            combined_data['users'].extend(file_data['data'])
                                        elif 'computers' in json_file.lower():
                                            combined_data['computers'].extend(file_data['data'])
                                        elif 'groups' in json_file.lower():
                                            combined_data['groups'].extend(file_data['data'])
                                except (json.JSONDecodeError, TypeError):
                                    continue

                    if combined_data['users'] or combined_data['computers'] or combined_data['groups']:
                        json_data = combined_data
                        self.log_to_asksyd(f"[OK] Loaded {len(combined_data['users'])} users, {len(combined_data['computers'])} computers, {len(combined_data['groups'])} groups from ZIP")
                except Exception as e:
                    self.log_to_asksyd(f"[WARNING] Could not extract JSON from ZIP: {e}")
                    json_data = None
            else:
                # Analyze JSON file
                with open(filepath, 'r', encoding='utf-8') as f:
                    json_content = f.read()

                self.txt_raw.insert("1.0", json_content)

                # Parse JSON for fact extraction
                import json
                json_data = json.loads(json_content)

                from bloodhound_analyzer import BloodHoundAnalyzer
                report, vulnerabilities = BloodHoundAnalyzer.analyze_bloodhound_output(json_content)

            # === NEW: Extract facts using fact extractor (mirrors Nmap architecture) ===
            if json_data and hasattr(self, 'fact_extractor'):
                try:
                    self.current_facts = self.fact_extractor.extract_facts(json_data)

                    # CRITICAL FIX: Add CVE data to facts (if available in vulnerabilities)
                    if vulnerabilities and 'cves' in vulnerabilities:
                        self.current_facts['cves'] = vulnerabilities['cves']
                    else:
                        self.current_facts['cves'] = {}

                    self.current_facts_text = self.fact_extractor.facts_to_text(self.current_facts)
                    cve_count = sum(len(cves) for cves in self.current_facts.get('cves', {}).values())
                    self.log_to_asksyd(f"[OK] Extracted {len(self.current_facts.get('all_users', []))} users, {len(self.current_facts.get('all_groups', []))} groups, {len(self.current_facts.get('attack_paths', []))} attack paths, {cve_count} CVEs")
                except Exception as e:
                    self.log_to_asksyd(f"[WARNING] Fact extraction failed: {e}")
                    self.current_facts = None
                    self.current_facts_text = None

            # Store vulnerabilities
            self.current_vulnerabilities = vulnerabilities

            # Display report
            self.txt_report.delete("1.0", "end")
            self.txt_report.insert("1.0", report)

            # Populate attack paths tree
            if vulnerabilities and 'attack_paths' in vulnerabilities:
                for idx, path in enumerate(vulnerabilities['attack_paths'], 1):
                    self.tree_paths.insert("", "end", text=str(idx), values=(
                        path.get('source', ''),
                        path.get('relationship', ''),
                        path.get('target', ''),
                        path.get('risk', '')
                    ))

            # Populate vulnerabilities tree
            if vulnerabilities and 'property_vulns' in vulnerabilities:
                for idx, vuln in enumerate(vulnerabilities['property_vulns'], 1):
                    self.tree_vulns.insert("", "end", text=str(idx), values=(
                        vuln.get('type', ''),
                        vuln.get('account', ''),
                        vuln.get('details', '')
                    ))

            # Switch to Analysis Report tab
            self.tabs_results.select(self.tab_report)

            self.lbl_status.configure(text="Analysis complete")
            self.log_to_asksyd("[SUCCESS] Analysis complete!")

        except Exception as e:
            import traceback
            error_msg = f"Error analyzing file:\n{str(e)}\n\n{traceback.format_exc()}"
            self.txt_report.delete("1.0", "end")
            self.txt_report.insert("1.0", error_msg)
            self.lbl_status.configure(text="Analysis failed")
            self.log_to_asksyd(f"[ERROR] {str(e)}")

    def _analyze_paste(self):
        """Analyze pasted BloodHound JSON"""
        pasted = self.txt_paste.get("1.0", "end").strip()

        if not pasted:
            from tkinter import messagebox
            messagebox.showwarning("No Input", "Please paste BloodHound JSON output first")
            return

        self.lbl_status.configure(text="Analyzing...")
        self.txt_raw.delete("1.0", "end")
        self.tree_paths.delete(*self.tree_paths.get_children())
        self.tree_vulns.delete(*self.tree_vulns.get_children())
        self.txt_report.delete("1.0", "end")

        try:
            # Display raw JSON
            self.txt_raw.insert("1.0", pasted)

            # Analyze with BloodHound analyzer first (it has robust JSON parsing)
            from bloodhound_analyzer import BloodHoundAnalyzer
            report, vulnerabilities = BloodHoundAnalyzer.analyze_bloodhound_output(pasted)

            # Parse JSON for fact extraction (use BloodHound's robust parser)
            json_data = BloodHoundAnalyzer._try_parse_json(pasted)

            # === NEW: Extract facts using fact extractor (mirrors Nmap architecture) ===
            if json_data and hasattr(self, 'fact_extractor'):
                try:
                    self.current_facts = self.fact_extractor.extract_facts(json_data)

                    # CRITICAL FIX: Add CVE data to facts (if available in vulnerabilities)
                    if vulnerabilities and 'cves' in vulnerabilities:
                        self.current_facts['cves'] = vulnerabilities['cves']
                    else:
                        self.current_facts['cves'] = {}

                    self.current_facts_text = self.fact_extractor.facts_to_text(self.current_facts)
                    cve_count = sum(len(cves) for cves in self.current_facts.get('cves', {}).values())
                    self.log_to_asksyd(f"[OK] Extracted {len(self.current_facts.get('all_users', []))} users, {len(self.current_facts.get('all_groups', []))} groups, {len(self.current_facts.get('attack_paths', []))} attack paths, {cve_count} CVEs")
                except Exception as e:
                    self.log_to_asksyd(f"[WARNING] Fact extraction failed: {e}")
                    self.current_facts = None
                    self.current_facts_text = None

            # Store vulnerabilities
            self.current_vulnerabilities = vulnerabilities

            # Display report
            self.txt_report.delete("1.0", "end")
            self.txt_report.insert("1.0", report)

            # Populate attack paths tree
            if vulnerabilities and 'attack_paths' in vulnerabilities:
                for idx, path in enumerate(vulnerabilities['attack_paths'], 1):
                    self.tree_paths.insert("", "end", text=str(idx), values=(
                        path.get('source', ''),
                        path.get('relationship', ''),
                        path.get('target', ''),
                        path.get('risk', '')
                    ))

            # Populate vulnerabilities tree
            if vulnerabilities and 'property_vulns' in vulnerabilities:
                for idx, vuln in enumerate(vulnerabilities['property_vulns'], 1):
                    self.tree_vulns.insert("", "end", text=str(idx), values=(
                        vuln.get('type', ''),
                        vuln.get('account', ''),
                        vuln.get('details', '')
                    ))

            # Switch to Analysis Report tab
            self.tabs_results.select(self.tab_report)

            self.lbl_status.configure(text="Analysis complete")
            self.log_to_asksyd("[SUCCESS] Analysis complete!")

        except Exception as e:
            import traceback
            error_msg = f"Error analyzing pasted content:\n{str(e)}\n\n{traceback.format_exc()}"
            self.txt_report.delete("1.0", "end")
            self.txt_report.insert("1.0", error_msg)
            self.lbl_status.configure(text="Analysis failed")
            self.log_to_asksyd(f"[ERROR] {str(e)}")

    def _clear_chat_and_output(self):
        """Clear all chat and output screens for BloodHound"""
        # Clear Ask Syd chat
        self.txt_chat.delete('1.0', tk.END)
        # Clear input field
        self.entry_question.delete('1.0', tk.END)
        # Clear raw output
        self.txt_raw.delete('1.0', tk.END)
        # Clear attack paths tree
        for item in self.tree_paths.get_children():
            self.tree_paths.delete(item)
        # Clear vulnerabilities tree
        for item in self.tree_vulns.get_children():
            self.tree_vulns.delete(item)
        # Clear report
        self.txt_report.delete('1.0', tk.END)
        # Clear log
        self.txt_log.delete('1.0', tk.END)
        # Clear loaded facts
        self.current_facts = None
        self.current_facts_text = None
        # Log the clear action
        self.log_to_asksyd("[INFO] Chat and output cleared")

    def log_to_asksyd(self, message):
        """Log messages to Ask Syd log panel (thread-safe)"""
        def _update():
            self.txt_log.insert(tk.END, f"{message}\n")
            self.txt_log.see(tk.END)

        # Schedule GUI update on main thread
        try:
            self.after(0, _update)
        except:
            pass

    # ========== Context Menu (Right-click) ==========
    def _create_context_menu(self, widget):
        """Add right-click copy/paste menu to Text widget"""
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="Cut", command=lambda: widget.event_generate("<<Cut>>"))
        menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
        menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_separator()
        menu.add_command(label="Select All", command=lambda: widget.tag_add("sel", "1.0", "end"))

        def show_menu(event):
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        widget.bind("<Button-3>", show_menu)  # Right-click

    # ========== Copy All Methods ==========
    def _copy_all_attack_paths(self):
        """Copy all attack paths to clipboard"""
        try:
            # Get all items from the Treeview
            items = self.tree_paths.get_children()
            if not items:
                messagebox.showinfo("Copy All Attack Paths", "No attack paths to copy.")
                return

            # Build tab-separated text output
            output_lines = []
            # Header
            output_lines.append("ID\tSource\tPermission\tTarget\tRisk")
            output_lines.append("-" * 80)

            # Data rows
            for item in items:
                item_id = self.tree_paths.item(item, "text")
                values = self.tree_paths.item(item, "values")
                if values:
                    source = values[0] if len(values) > 0 else ""
                    permission = values[1] if len(values) > 1 else ""
                    target = values[2] if len(values) > 2 else ""
                    risk = values[3] if len(values) > 3 else ""
                    output_lines.append(f"{item_id}\t{source}\t{permission}\t{target}\t{risk}")

            # Copy to clipboard
            output_text = "\n".join(output_lines)
            self.clipboard_clear()
            self.clipboard_append(output_text)
            self.clipboard_append("")  # Ensure it stays on clipboard

            messagebox.showinfo("Copy All Attack Paths", f"Copied {len(items)} attack paths to clipboard.")
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy attack paths: {e}")

    def _copy_all_vulnerabilities(self):
        """Copy all vulnerabilities to clipboard"""
        try:
            # Get all items from the Treeview
            items = self.tree_vulns.get_children()
            if not items:
                messagebox.showinfo("Copy All Vulnerabilities", "No vulnerabilities to copy.")
                return

            # Build tab-separated text output
            output_lines = []
            # Header
            output_lines.append("ID\tType\tAccount\tDetails")
            output_lines.append("-" * 80)

            # Data rows
            for item in items:
                item_id = self.tree_vulns.item(item, "text")
                values = self.tree_vulns.item(item, "values")
                if values:
                    vuln_type = values[0] if len(values) > 0 else ""
                    account = values[1] if len(values) > 1 else ""
                    details = values[2] if len(values) > 2 else ""
                    output_lines.append(f"{item_id}\t{vuln_type}\t{account}\t{details}")

            # Copy to clipboard
            output_text = "\n".join(output_lines)
            self.clipboard_clear()
            self.clipboard_append(output_text)
            self.clipboard_append("")  # Ensure it stays on clipboard

            messagebox.showinfo("Copy All Vulnerabilities", f"Copied {len(items)} vulnerabilities to clipboard.")
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy vulnerabilities: {e}")

    def _send_to_syd(self):
        """Handle Send button - query BloodHound RAG system"""
        if not self.rag_ready:
            messagebox.showwarning("Ask Syd", "Still loading knowledge base, please wait...")
            return

        question = self.entry_question.get("1.0", "end").strip()
        if not question:
            return

        self.entry_question.delete("1.0", "end")
        self.append_chat_message("YOU", question)

        # Show "Syd is thinking..." indicator
        self.show_thinking_indicator()

        def query_rag():
            try:
                # === STAGE A: CHECK FOR EXTRACTED FACTS (mirrors Nmap architecture) ===
                # Check if we have BloodHound data or if this is a general question
                if not hasattr(self, 'current_facts_text') or not self.current_facts_text:
                    # No BloodHound data - answer general questions using knowledge base only
                    query_vec = self.embed_model.encode([question]).astype('float32')
                    faiss.normalize_L2(query_vec)
                    distances, indices = self.faiss_index.search(query_vec, 5)

                    contexts = []
                    for idx in indices[0]:
                        if idx < len(self.chunks):
                            chunk = self.chunks[idx]
                            text = chunk.get('content', str(chunk))
                            contexts.append(text)
                    context_text = "\n\n".join(contexts)

                    # Build general knowledge prompt
                    system_prompt = f"""You are Syd, an expert penetration testing analyst specializing in BloodHound, Active Directory security, and AD exploitation.

The user has asked a general question without providing BloodHound data. Answer their question using your knowledge of BloodHound, Active Directory, attack paths, and exploitation techniques.

KNOWLEDGE BASE:
{context_text}

RESPONSE GUIDELINES:
- Provide clear, practical explanations
- Include examples when helpful
- Mention relevant BloodHound queries and techniques
- If asked about exploitation, provide AD attack commands (Rubeus, Mimikatz, Impacket, PowerView, SharpHound) for authorized penetration testing
- If asked about specific attack paths (DCSync, Kerberoasting, AS-REP roasting, etc.), provide exploitation steps and tooling
- Keep answers concise but informative
- If the question requires BloodHound data to answer, politely explain that and ask them to provide BloodHound JSON data"""

                    user_message = f"Question: {question}"

                    response = self.llm.create_chat_completion(
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_message}
                        ],
                        max_tokens=1536,
                        temperature=0.2,
                        top_p=0.9,
                        stop=["Question:", "Q:"]
                    )
                    answer = response['choices'][0]['message']['content'].strip()
                    answer = tag_unverified_cves(answer)

                    # Remove thinking indicator and show answer
                    self.after(0, lambda: self.remove_thinking_indicator())
                    self.after(0, lambda: self.append_chat_message("SYD", answer))
                    return

                # === STAGE B: GET KNOWLEDGE BASE CONTEXT ===
                # Embed question
                query_vec = self.embed_model.encode([question]).astype('float32')
                faiss.normalize_L2(query_vec)

                # Search FAISS for top 2 chunks (reduced from 3 to save context space)
                distances, indices = self.faiss_index.search(query_vec, 2)

                # Get chunk text
                contexts = []
                for idx in indices[0]:
                    if idx < len(self.chunks):
                        chunk = self.chunks[idx]
                        text = chunk.get('content', str(chunk))
                        contexts.append(text)

                context_text = "\n\n".join(contexts)

                # === STAGE C: BUILD FACT-BASED PROMPT (mirrors Nmap architecture) ===
                # Truncate facts and context to fit within context window
                facts_for_prompt, context_for_prompt = truncate_for_context_window(
                    self.llm, self.current_facts_text, context_text,
                    max_tokens=1536, static_prompt_chars=2500
                )

                system_prompt = f"""You are Syd, an expert penetration testing analyst analyzing BloodHound Active Directory data.

ANSWERING STRATEGY (3-Tier Approach):

1. SPECIFIC BLOODHOUND DATA (Facts-First - NEVER Invent):
   - For users, groups, computers, attack paths: Use ONLY the facts below
   - NEVER invent: usernames, group names, computer names, permissions, attack paths
   - If not in facts, say "Not present in this BloodHound scan"

2. INFERENCE FROM EVIDENCE (Connect the Dots):
   - Domain Admin sessions on workstations = credential theft risk
   - Kerberoastable service accounts = offline password cracking opportunity
   - GenericAll on high-value group = escalation path
   - Use phrases like: "Based on the findings..." or "This indicates..."

3. GENERAL AD SECURITY KNOWLEDGE (Explain Concepts):
   - Definitions: What Kerberoasting is, how DCSync works
   - Attack techniques: How to exploit findings
   - Use phrases like: "In Active Directory..." or "This attack works by..."

CRITICAL RULES (Professional Output Standards):

RULE 1 - COMMAND SYNTAX (Zero Tolerance):
- Use EXACT command syntax from facts - do NOT use your training data
- If facts show "hashcat -m 13100", use that EXACTLY (not -m 1800 or any other mode)
- If facts show specific Impacket syntax, copy it EXACTLY character-for-character
- Your training data may be outdated - facts are the source of truth
- Wrong commands = professional credibility destroyed

RULE 2 - NO SPECULATION (Evidence-Only Attack Plans):
- ONLY provide attack paths explicitly supported by BloodHound edges
- If facts say "Dangerous permissions: None found", you MUST answer:
  "No BloodHound-supported path from [user] to [target] exists in this dataset."
- NEVER chain together speculative steps without explicit edges:
  ❌ WRONG: "Kerberoast accounts, then exploit CVEs, then use WriteDacl..." (speculation)
  ✅ CORRECT: "No attack path found" OR cite explicit edges proving each hop
- Multi-hop paths require explicit evidence for EVERY hop
- CRITICAL: When user says "I cracked X's password - give me attack plan":
  - Check facts for X's permissions FIRST
  - If "Dangerous permissions: None found" → STOP, answer "No path exists"
  - Do NOT generate multi-step plans combining unrelated attacks
  - Being compromised ≠ having a path to Domain Admin

RULE 3 - TARGET MATCHING (Precision Required):
- BloodHound facts are TARGET-SPECIFIC - do not mix targets
- If user asks "Shadow Credentials on CASTELBLACK", only use facts mentioning CASTELBLACK
- If facts show "KEY ADMINS → HODOR" but question asks about WINTERFELL:
  Answer: "Not present in this BloodHound scan"
- NEVER apply facts about one principal/computer to questions about another

RULE 4 - EVIDENCE CITATION (Provability):
- For attack paths, cite edges: "source --[relationship]--> target"
- For permissions, show: "X has Y permission on Z (BloodHound edge)"
- For multi-hop paths, show ALL hops with evidence
- If you cannot cite an explicit edge, do not claim the relationship exists

RULE 5 - CVE/EXPLOIT ACCURACY:
- If the user asks about a specific CVE by number, you may discuss it - explain the vulnerability and exploitation approach.
- Do NOT invent additional CVE numbers on your own. Describe vulnerability classes by name without guessing CVE numbers.
- When discussing exploits, focus on the TECHNIQUE (e.g. Kerberoasting, DCSync) rather than guessing CVE numbers.

FACTS FROM THIS BLOODHOUND SCAN:
{facts_for_prompt}

KNOWLEDGE BASE (for general AD/BloodHound concepts):
{context_for_prompt}

RESPONSE FORMAT:
- Start with facts from the scan
- Add inferences based on evidence
- Include general knowledge if helpful
- Always distinguish: Facts vs Inference vs General knowledge"""

                user_message = f"Question: {question}\n\nAnswer based on the facts above:"

                # 5. Generate with LLM using chat completion (like Nmap)
                response = self.llm.create_chat_completion(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ],
                    max_tokens=1536,
                    temperature=0.1,
                    top_p=0.9,
                    stop=["Question:", "Q:", "\n\n\n"]
                )
                answer = response['choices'][0]['message']['content'].strip()
                answer = tag_unverified_cves(answer)

                # Aggressive repetition detection and truncation
                lines = answer.split('\n')
                seen = {}  # Track line patterns with counts
                section_headers = {}  # Track section headers specifically
                clean_lines = []
                max_lines = 60  # Hard limit on answer length (reduced from 80)
                broken_numbering_count = 0  # Detect broken numbering patterns

                for i, line in enumerate(lines):
                    if i >= max_lines:
                        break

                    line_stripped = line.strip()

                    # Detect broken numbering patterns like "2a)", "3b or 4c)", "2-3 HIGH-RISK:", etc.
                    # Also catch Q/A numbered patterns like "A1)", "Q2)"
                    if re.search(r'^\s*\d+[a-z]\)', line) or \
                       re.search(r'^\s*\d+-\d+\s', line) or \
                       re.search(r'^\s*\d+[a-z]\)\s*(or\s+\d+[a-z]\))', line) or \
                       re.search(r'^\s*[AQ]\d+\)', line):  # Catch "A1)", "Q2)", etc.
                        broken_numbering_count += 1
                        if broken_numbering_count >= 3:  # Stop if 3+ broken patterns (reduced from 4)
                            break

                    # Detect repeated section headers (all caps + special chars)
                    if len(line_stripped) > 5 and re.match(r'^[A-Z\s:=\-]{5,}$', line_stripped):
                        if line_stripped in section_headers:
                            section_headers[line_stripped] += 1
                            if section_headers[line_stripped] >= 2:  # Stop on 2nd occurrence of section header
                                break
                        else:
                            section_headers[line_stripped] = 1

                    # Normalize: remove numbers, strip whitespace
                    line_normalized = ''.join([c for c in line if not c.isdigit()]).strip()[:60]

                    # Skip empty or very short lines from counting
                    if len(line_normalized) < 10:
                        clean_lines.append(line)
                        continue

                    # Count how many times we've seen this pattern
                    if line_normalized in seen:
                        seen[line_normalized] += 1
                        # If we see the same pattern 2 times (reduced from 3), stop completely
                        if seen[line_normalized] >= 2:
                            break
                    else:
                        seen[line_normalized] = 1

                    clean_lines.append(line)

                answer = '\n'.join(clean_lines)

                # Post-processing: Remove incomplete last line
                # If answer ends with incomplete pattern like "4 ForceChangePassword Rights:" or "A1)", remove it
                lines_final = answer.split('\n')
                if lines_final:
                    last_line = lines_final[-1].strip()
                    # Detect incomplete patterns
                    incomplete_patterns = [
                        r'^\d+\s+\w+\s*:$',  # "4 ForceChangePassword Rights:"
                        r'^[AQ]\d+\)$',      # "A1)" or "Q2)" at end
                        r'^\d+[a-z]?\)?\s*:$',  # "2a):" or "3):"
                        r'^\s*-\s*$',        # Just a dash
                        r'^[A-Z\s]+:$',      # "Example:" or "For example:"
                    ]

                    is_incomplete = any(re.match(pattern, last_line) for pattern in incomplete_patterns)

                    # Also check if last line is very short and ends with colon
                    if len(last_line) < 50 and last_line.endswith(':'):
                        is_incomplete = True

                    if is_incomplete and len(lines_final) > 1:
                        # Remove the incomplete last line
                        answer = '\n'.join(lines_final[:-1])

                # === STAGE D: VALIDATION LAYER (mirrors Nmap architecture) ===
                # Validate answer against extracted facts to prevent hallucinations
                if hasattr(self, 'current_facts') and self.current_facts:
                    validation_result = self.fact_extractor.validate_answer(answer, self.current_facts)

                    if not validation_result['valid']:
                        # Warn about potential hallucination but show full answer
                        warning = f"[WARNING - POSSIBLE HALLUCINATION]\n\n"
                        warning += f"Syd's answer may contain information not confirmed in the BloodHound data:\n"
                        for violation in validation_result['violations']:
                            warning += f"  - {violation}\n"
                        warning += f"\nPlease verify the following answer against your analysis results:\n"
                        warning += f"{'=' * 50}\n\n"
                        answer = warning + answer

                # Remove thinking indicator and show answer
                self.after(0, lambda: self.remove_thinking_indicator())
                self.after(0, lambda: self.append_chat_message("SYD", answer))

            except Exception as e:
                error_msg = f"Error processing question: {str(e)}"
                self.log_to_asksyd(f"[ERROR] {error_msg}")
                self.after(0, lambda: self.remove_thinking_indicator())
                self.after(0, lambda: self.append_chat_message("SYSTEM", error_msg))

        import threading
        threading.Thread(target=query_rag, daemon=True).start()

    def _upload_data(self):
        """Upload a file to the chat (for context)"""
        filepath = filedialog.askopenfilename(
            title="Select file to upload",
            filetypes=[("JSON files", "*.json"), ("ZIP files", "*.zip"), ("Text files", "*.txt"), ("All files", "*.*")]
        )

        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                self.txt_chat.insert(tk.END, f"\n[UPLOADED: {os.path.basename(filepath)}]\n")
                self.txt_chat.insert(tk.END, content[:5000])  # Limit to 5000 chars
                if len(content) > 5000:
                    self.txt_chat.insert(tk.END, "\n\n[... truncated ...]")
                self.txt_chat.see(tk.END)

            except Exception as e:
                messagebox.showerror("Upload Error", str(e))

    def show_thinking_indicator(self):
        """Show 'Syd is thinking...' with animated dots"""
        # Store the starting position of the thinking message
        self.thinking_start = self.txt_chat.index(tk.END)

        # Add the thinking message
        self.txt_chat.insert(tk.END, f"\n{'='*60}\n")
        self.txt_chat.insert(tk.END, "[SYD]\n")
        self.thinking_text_start = self.txt_chat.index(tk.END)
        self.txt_chat.insert(tk.END, "Thinking.\n")
        self.txt_chat.see(tk.END)

        # Start animation
        self.thinking_dots = 1
        self.thinking_active = True
        self.animate_thinking()

    def animate_thinking(self):
        """Animate the thinking dots (. .. ... . .. ...)"""
        if not hasattr(self, 'thinking_active') or not self.thinking_active:
            return

        # Update dots
        dots = "." * self.thinking_dots
        self.thinking_dots = (self.thinking_dots % 3) + 1

        # Update the text
        try:
            self.txt_chat.delete(self.thinking_text_start, f"{self.thinking_text_start} lineend")
            self.txt_chat.insert(self.thinking_text_start, f"Thinking{dots}")
            self.txt_chat.see(tk.END)
        except:
            pass  # If something goes wrong, just stop animating

        # Schedule next animation (every 500ms)
        if self.thinking_active:
            self.after(500, self.animate_thinking)

    def remove_thinking_indicator(self):
        """Remove the 'Syd is thinking...' message"""
        self.thinking_active = False

        try:
            # Delete the thinking message
            if hasattr(self, 'thinking_start'):
                self.txt_chat.delete(self.thinking_start, tk.END)
        except:
            pass  # If something goes wrong, just continue

    def append_chat_message(self, sender, message):
        """Append a message to the chat display"""
        self.txt_chat.insert(tk.END, f"\n{'='*60}\n")
        self.txt_chat.insert(tk.END, f"[{sender}]\n")
        self.txt_chat.insert(tk.END, f"{message}\n")
        self.txt_chat.see(tk.END)


# ---------------------------- NXC/NetExec Page ----------------------------
class NXCPage(ttk.Frame):
    """NXC/NetExec Network Exploitation Interface - Production Quality"""

    # Known CVEs for NXC-detectable conditions
    _CONDITION_CVES = {
        'smb_v1':         ['CVE-2017-0144', 'CVE-2017-0145'],
        'zerologon':      ['CVE-2020-1472'],
        'petitpotam':     ['CVE-2021-36942'],
        'nopac':          ['CVE-2021-42278', 'CVE-2021-42287'],
        'printnightmare': ['CVE-2021-1675',  'CVE-2021-34527'],
    }

    def __init__(self, parent):
        super().__init__(parent)

        self.facts           = None
        self.facts_text      = None
        self.rag_ready       = False
        self.embed_model     = None
        self.llm             = None
        self.faiss_index     = None
        self.chunks          = None
        self._verified_cves  = set()
        self._thinking_start = None

        main_paned = ttk.PanedWindow(self, orient="horizontal")
        main_paned.pack(fill="both", expand=True)

        left_frame  = ttk.Frame(main_paned)
        right_frame = ttk.Frame(main_paned)
        main_paned.add(left_frame,  weight=3)
        main_paned.add(right_frame, weight=2)
        right_frame.configure(width=500)

        # ===== LEFT =====
        controls_frame = ttk.Frame(left_frame)
        controls_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(controls_frame, text="NXC/NetExec - Network Exploitation",
                  style="Header.TLabel").pack(anchor="w", pady=(0,6))

        btn_row = ttk.Frame(controls_frame)
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="Analyze Output", command=self._analyze,
                   style="Accent.TButton").pack(side="left", padx=(0,5))
        ttk.Button(btn_row, text="Clear All", command=self._clear_all).pack(side="left", padx=5)

        self.lbl_status = ttk.Label(controls_frame,
            text="NXC ready - paste terminal output and click Analyze",
            foreground=INK_SOFT)
        self.lbl_status.pack(anchor="w", pady=(4,0))

        # ── Run NXC Section ──────────────────────────────────────────────────
        run_frame = ttk.LabelFrame(left_frame, text="Run NXC/NetExec")
        run_frame.pack(fill="x", padx=5, pady=(0,4))

        # Row 1: target + preset + run/stop
        row1 = ttk.Frame(run_frame)
        row1.pack(fill="x", padx=4, pady=(4,2))
        ttk.Label(row1, text="Target:").pack(side="left")
        self.entry_nxc_target = ttk.Entry(row1, width=22)
        self.entry_nxc_target.pack(side="left", padx=(2,8))
        self.entry_nxc_target.insert(0, "192.168.1.0/24")

        ttk.Label(row1, text="Mode:").pack(side="left")
        self.nxc_mode = tk.StringVar(value="Host Discovery")
        mode_cb = ttk.Combobox(row1, textvariable=self.nxc_mode, width=18, state="readonly",
            values=["Host Discovery","Password Spray","Hash Spray (PTH)",
                    "Enum Shares","Enum Users","SAM Dump","NTDS Dump (DC)",
                    "Kerberoasting","AS-REP Roasting","Custom Command"])
        mode_cb.pack(side="left", padx=(2,8))
        mode_cb.bind("<<ComboboxSelected>>", self._nxc_update_cmd_preview)

        self.btn_run_nxc  = ttk.Button(row1, text="Run", command=self._run_nxc,
                                        style="Accent.TButton")
        self.btn_run_nxc.pack(side="left", padx=2)
        self.btn_stop_nxc = ttk.Button(row1, text="Stop", command=self._stop_nxc, state="disabled")
        self.btn_stop_nxc.pack(side="left", padx=2)

        # Row 2: credentials + command preview
        row2 = ttk.Frame(run_frame)
        row2.pack(fill="x", padx=4, pady=2)
        ttk.Label(row2, text="User:").pack(side="left")
        self.entry_nxc_user = ttk.Entry(row2, width=14)
        self.entry_nxc_user.pack(side="left", padx=(2,6))
        ttk.Label(row2, text="Pass/Hash:").pack(side="left")
        self.entry_nxc_pass = ttk.Entry(row2, width=20)
        self.entry_nxc_pass.pack(side="left", padx=(2,6))
        ttk.Label(row2, text="Extra:").pack(side="left")
        self.entry_nxc_extra = ttk.Entry(row2, width=20)
        self.entry_nxc_extra.pack(side="left", padx=(2,6))

        # Row 3: command preview (editable for Custom mode)
        row3 = ttk.Frame(run_frame)
        row3.pack(fill="x", padx=4, pady=(0,2))
        ttk.Label(row3, text="Command:").pack(side="left")
        self.entry_nxc_cmd = ttk.Entry(row3, foreground="#aaaaaa")
        self.entry_nxc_cmd.pack(side="left", fill="x", expand=True, padx=(2,6))
        ttk.Button(row3, text="Use Output →", command=self._use_nxc_output).pack(side="right")

        # Row 4: live output
        out_frame = ttk.Frame(run_frame)
        out_frame.pack(fill="x", padx=4, pady=(0,4))
        self.txt_nxc_out = tk.Text(out_frame, height=7, bg=BG_DARK, fg="#00ff41",
                                    insertbackground=INK, font=("Consolas", 8), wrap="none")
        sb = ttk.Scrollbar(out_frame, command=self.txt_nxc_out.yview)
        self.txt_nxc_out.configure(yscrollcommand=sb.set)
        self.txt_nxc_out.pack(side="left", fill="x", expand=True)
        sb.pack(side="right", fill="y")

        self._nxc_process  = None
        self._nxc_out_buf  = []
        self._nxc_update_cmd_preview()

        results_frame = ttk.Frame(left_frame)
        results_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.tabs = ttk.Notebook(results_frame)
        self.tabs.pack(fill="both", expand=True)

        # Tab 1: Paste Results
        paste_tab = ttk.Frame(self.tabs)
        self.tabs.add(paste_tab, text="Paste Results")
        paste_hdr = ttk.Frame(paste_tab)
        paste_hdr.pack(fill="x", padx=5, pady=(4,2))
        ttk.Label(paste_hdr,
            text="Paste raw NXC/NetExec terminal output, then click Analyze Output",
            foreground=INK_SOFT).pack(side="left")
        ttk.Button(paste_hdr, text="Clear",
            command=lambda: self.txt_paste.delete("1.0","end")).pack(side="right")
        paste_inner = ttk.Frame(paste_tab)
        paste_inner.pack(fill="both", expand=True)
        self.txt_paste = tk.Text(paste_inner, bg=BG_DARK, fg=INK, insertbackground=INK,
                                  wrap="word", font=("Consolas", 9))
        s = ttk.Scrollbar(paste_inner, command=self.txt_paste.yview)
        self.txt_paste.configure(yscrollcommand=s.set)
        self.txt_paste.pack(side="left", fill="both", expand=True)
        s.pack(side="right", fill="y")

        # Tab 2: Credentials Found
        creds_tab = ttk.Frame(self.tabs)
        self.tabs.add(creds_tab, text="Credentials Found")
        creds_hdr = ttk.Frame(creds_tab)
        creds_hdr.pack(fill="x", padx=5, pady=(4,2))
        ttk.Button(creds_hdr, text="Copy All Credentials",
                   command=self._copy_all_creds).pack(side="right")
        creds_inner = ttk.Frame(creds_tab)
        creds_inner.pack(fill="both", expand=True)
        self.txt_creds = tk.Text(creds_inner, bg=BG_DARK, fg=INK, insertbackground=INK,
                                  wrap="word", font=("Consolas", 9))
        s = ttk.Scrollbar(creds_inner, command=self.txt_creds.yview)
        self.txt_creds.configure(yscrollcommand=s.set)
        self.txt_creds.pack(side="left", fill="both", expand=True)
        s.pack(side="right", fill="y")

        # Tab 3: Hosts & Access
        hosts_tab = ttk.Frame(self.tabs)
        self.tabs.add(hosts_tab, text="Hosts & Access")
        hosts_hdr = ttk.Frame(hosts_tab)
        hosts_hdr.pack(fill="x", padx=5, pady=(4,2))
        ttk.Button(hosts_hdr, text="Copy All Hosts",
                   command=self._copy_all_hosts).pack(side="right")
        hosts_inner = ttk.Frame(hosts_tab)
        hosts_inner.pack(fill="both", expand=True)
        self.txt_hosts = tk.Text(hosts_inner, bg=BG_DARK, fg=INK, insertbackground=INK,
                                  wrap="word", font=("Consolas", 9))
        s = ttk.Scrollbar(hosts_inner, command=self.txt_hosts.yview)
        self.txt_hosts.configure(yscrollcommand=s.set)
        self.txt_hosts.pack(side="left", fill="both", expand=True)
        s.pack(side="right", fill="y")

        # Tab 4: Vulnerabilities & CVEs
        vulns_tab = ttk.Frame(self.tabs)
        self.tabs.add(vulns_tab, text="Vulnerabilities")
        vulns_hdr = ttk.Frame(vulns_tab)
        vulns_hdr.pack(fill="x", padx=5, pady=(4,2))
        ttk.Button(vulns_hdr, text="Copy All Vulnerabilities",
                   command=self._copy_all_vulns).pack(side="right")
        vulns_inner = ttk.Frame(vulns_tab)
        vulns_inner.pack(fill="both", expand=True)
        self.txt_vulns = tk.Text(vulns_inner, bg=BG_DARK, fg=INK, insertbackground=INK,
                                  wrap="word", font=("Consolas", 9))
        s = ttk.Scrollbar(vulns_inner, command=self.txt_vulns.yview)
        self.txt_vulns.configure(yscrollcommand=s.set)
        self.txt_vulns.pack(side="left", fill="both", expand=True)
        s.pack(side="right", fill="y")

        # Tab 5: Next Steps
        next_tab = ttk.Frame(self.tabs)
        self.tabs.add(next_tab, text="Next Steps")
        next_hdr = ttk.Frame(next_tab)
        next_hdr.pack(fill="x", padx=5, pady=(4,2))
        ttk.Button(next_hdr, text="Copy Next Steps",
                   command=self._copy_next_steps).pack(side="right")
        next_inner = ttk.Frame(next_tab)
        next_inner.pack(fill="both", expand=True)
        self.txt_next = tk.Text(next_inner, bg=BG_DARK, fg=INK, insertbackground=INK,
                                 wrap="word", font=("Consolas", 9))
        s = ttk.Scrollbar(next_inner, command=self.txt_next.yview)
        self.txt_next.configure(yscrollcommand=s.set)
        self.txt_next.pack(side="left", fill="both", expand=True)
        s.pack(side="right", fill="y")

        # ===== RIGHT: Ask Syd =====
        hdr = ttk.Frame(right_frame)
        hdr.pack(fill="x", padx=5, pady=5)
        title_row = ttk.Frame(hdr)
        title_row.pack(fill="x")
        ttk.Label(title_row, text="Ask Syd - NXC/NetExec Expert",
                  style="Header.TLabel").pack(side="left")
        ttk.Label(title_row, text="Red Team",
                  background="#dc2626", foreground="#fff", padding=(5,2)).pack(side="left", padx=10)

        chat_frame = ttk.Frame(right_frame)
        chat_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.txt_chat = tk.Text(chat_frame, bg=BG_DARK, fg=INK, insertbackground=INK,
                                 wrap="word", height=20)
        s = ttk.Scrollbar(chat_frame, command=self.txt_chat.yview)
        self.txt_chat.configure(yscrollcommand=s.set)
        self.txt_chat.pack(side="left", fill="both", expand=True)
        s.pack(side="right", fill="y")

        log_frame = ttk.Frame(right_frame)
        log_frame.pack(fill="x", padx=5, pady=(0,2))
        self.txt_log = tk.Text(log_frame, bg=BG_DARK, fg=INK_SOFT, insertbackground=INK,
                                wrap="word", height=5)
        s = ttk.Scrollbar(log_frame, command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=s.set)
        self.txt_log.pack(side="left", fill="both", expand=True)
        s.pack(side="right", fill="y")

        input_frame = ttk.Frame(right_frame)
        input_frame.pack(fill="x", padx=5, pady=5)
        self.entry_question = tk.Text(input_frame, height=3, bg=BG_DARK, fg=INK,
                                       insertbackground=INK, wrap="word",
                                       font=("Segoe UI", 10))
        self.entry_question.pack(side="left", fill="x", expand=True, padx=(0,5))
        self.entry_question.bind("<Return>",       self._on_enter_key)
        self.entry_question.bind("<Shift-Return>", lambda e: None)
        ttk.Button(input_frame, text="Ask",
                   command=self._send_to_syd, style="Accent.TButton").pack(side="right")

        for w in [self.txt_paste, self.txt_creds, self.txt_hosts, self.txt_vulns,
                  self.txt_next, self.txt_chat, self.txt_log, self.entry_question]:
            self._create_context_menu(w)

        self.log_to_asksyd("[INFO] NXC/NetExec analyzer ready")
        self.log_to_asksyd("[INFO] Paste NXC output and click Analyze Output")

        import threading
        threading.Thread(target=self._init_rag, daemon=True).start()

    # ------------------------------------------------------------------
    # RAG initialisation
    # ------------------------------------------------------------------

    def _init_rag(self):
        try:
            self.log_to_asksyd("[LOADING] Loading NXC knowledge base...")
            self.embed_model = load_embedding_model("all-MiniLM-L6-v2")
            self.log_to_asksyd("[OK] Embedding model loaded")

            faiss_path = BASE_PATH / "rag_engine" / "embeddings" / "customers" / "customer_syd_nxc_knowledge.faiss"
            pkl_path   = BASE_PATH / "rag_engine" / "embeddings" / "customers" / "customer_syd_nxc_knowledge.pkl"

            if not faiss_path.exists() or not pkl_path.exists():
                self.log_to_asksyd("[ERROR] NXC knowledge files not found - run: python chunk_and_embed_nxc.py")
                return

            self.faiss_index = faiss.read_index(str(faiss_path))
            with open(pkl_path, 'rb') as f:
                self.chunks = pickle.load(f)
            self.log_to_asksyd(f"[OK] Loaded {len(self.chunks)} NXC knowledge chunks")

            self.llm = get_shared_llm()
            self.log_to_asksyd("[OK] Using shared LLM (Qwen 2.5 14B)")

            self.rag_ready = True
            self.log_to_asksyd("[SUCCESS] Ask Syd ready! Ask about NXC, lateral movement, credential attacks, OPSEC...")

        except Exception as e:
            self.log_to_asksyd("[WARNING] Ask Syd knowledge base could not load. Ensure 'hf_home' folder is present.")
            import traceback
            traceback.print_exc()

    # ------------------------------------------------------------------
    # Analysis pipeline
    # ------------------------------------------------------------------

    def _analyze(self):
        raw = self.txt_paste.get("1.0", "end").strip()
        if not raw:
            messagebox.showwarning("No Output", "Paste NXC output first")
            return

        self.lbl_status.configure(text="Analyzing...")
        self._clear_results()
        self._verified_cves = set()

        try:
            from nxc_fact_extractor import NXCFactExtractor
            extractor       = NXCFactExtractor()
            self.facts      = extractor.extract(raw)
            self.facts_text = extractor.facts_to_text(self.facts)

            self._map_cves()
            self._display_credentials()
            self._display_hosts()
            self._display_vulnerabilities()
            self._display_next_steps()

            success_count = len([c for c in self.facts.credentials if c.status == "SUCCESS"])
            if success_count:
                self.tabs.select(1)

            self.lbl_status.configure(
                text=f"Done - {len(self.facts.hosts)} hosts | {success_count} valid creds | "
                     f"{len(self.facts.pwned_hosts)} Pwn3d! | {len(self._verified_cves)} CVEs"
            )
            self.log_to_asksyd(
                f"[OK] Analysis complete: {len(self.facts.hosts)} hosts | "
                f"{success_count} creds | {len(self.facts.pwned_hosts)} Pwn3d! | "
                f"{len(self._verified_cves)} CVEs"
            )

        except Exception as e:
            self.lbl_status.configure(text="Analysis failed")
            self.log_to_asksyd(f"[ERROR] {e}")
            import traceback
            traceback.print_exc()

    def _map_cves(self):
        """Map detected conditions to confirmed CVEs."""
        if not self.facts:
            return
        if any(h.smb_v1 for h in self.facts.hosts):
            self._verified_cves.update(self._CONDITION_CVES['smb_v1'])
        raw_lower = self.facts.raw_output.lower()
        for condition, cves in self._CONDITION_CVES.items():
            if condition in raw_lower:
                self._verified_cves.update(cves)

    # ------------------------------------------------------------------
    # NXC Run methods
    # ------------------------------------------------------------------

    def _nxc_update_cmd_preview(self, event=None):
        """Rebuild the command preview entry based on current mode/fields."""
        mode   = self.nxc_mode.get()
        target = self.entry_nxc_target.get().strip() or "<target>"
        user   = self.entry_nxc_user.get().strip()
        passwd = self.entry_nxc_pass.get().strip()
        extra  = self.entry_nxc_extra.get().strip()

        # Decide -p or -H flag
        def cred_flags():
            if not user and not passwd:
                return ""
            u = f"-u {user}" if user else ""
            if passwd and len(passwd) == 32 and all(c in "0123456789abcdefABCDEF" for c in passwd):
                p = f"-H {passwd}"
            else:
                p = f"-p '{passwd}'" if passwd else ""
            return f" {u} {p}".rstrip()

        templates = {
            "Host Discovery":    f"nxc smb {target}",
            "Password Spray":    f"nxc smb {target}{cred_flags()} --continue-on-success",
            "Hash Spray (PTH)":  f"nxc smb {target}{cred_flags()} --continue-on-success",
            "Enum Shares":       f"nxc smb {target}{cred_flags()} --shares",
            "Enum Users":        f"nxc smb {target}{cred_flags()} --users",
            "SAM Dump":          f"nxc smb {target}{cred_flags()} --sam",
            "NTDS Dump (DC)":    f"nxc smb {target}{cred_flags()} --ntds",
            "Kerberoasting":     f"nxc ldap {target}{cred_flags()} --kerberoasting hashes.txt",
            "AS-REP Roasting":   f"nxc ldap {target}{cred_flags()} --asreproast hashes.txt",
            "Custom Command":    self.entry_nxc_cmd.get() or f"nxc smb {target}",
        }
        cmd = templates.get(mode, f"nxc smb {target}")
        if extra:
            cmd += f" {extra}"

        self.entry_nxc_cmd.delete(0, "end")
        self.entry_nxc_cmd.insert(0, cmd)
        # Grey out preview for non-custom, editable for Custom Command
        self.entry_nxc_cmd.configure(
            state="normal" if mode == "Custom Command" else "readonly"
        )

    def _run_nxc(self):
        """Start NXC scan in a background thread."""
        import shutil, threading

        # Determine NXC executable
        nxc_exe = shutil.which("nxc") or shutil.which("netexec") or shutil.which("nxc.exe")
        if not nxc_exe:
            self._nxc_append_output("[ERROR] NXC/NetExec not found in PATH.\n"
                                    "[ERROR] Install with: pip install netexec\n")
            return

        # Build command list
        self._nxc_update_cmd_preview()
        mode = self.nxc_mode.get()
        if mode == "Custom Command":
            raw = self.entry_nxc_cmd.get().strip()
        else:
            raw = self.entry_nxc_cmd.get().strip()

        if not raw:
            self._nxc_append_output("[ERROR] No command to run.\n")
            return

        # Replace leading 'nxc' or 'netexec' token with discovered exe
        parts = raw.split()
        if parts and parts[0].lower() in ("nxc", "netexec"):
            parts[0] = nxc_exe
        cmd = parts

        # Update UI
        self.txt_nxc_out.configure(state="normal")
        self.txt_nxc_out.delete("1.0", "end")
        self._nxc_append_output(f"[RUN] {' '.join(cmd)}\n\n")
        self.btn_run_nxc.configure(state="disabled")
        self.btn_stop_nxc.configure(state="normal")
        self.lbl_status.configure(text="Running NXC scan...")

        t = threading.Thread(target=self._nxc_run_thread, args=(cmd,), daemon=True)
        t.start()

    def _stop_nxc(self):
        """Kill the running NXC process."""
        if self._nxc_process:
            try:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(self._nxc_process.pid)],
                        capture_output=True
                    )
                else:
                    self._nxc_process.kill()
                self._nxc_append_output("\n[STOPPED BY USER]\n")
            except Exception as e:
                self._nxc_append_output(f"\n[ERROR] Could not stop: {e}\n")
            finally:
                self._nxc_process = None
                self.after(0, self.btn_run_nxc.configure,  {"state": "normal"})
                self.after(0, self.btn_stop_nxc.configure, {"state": "disabled"})
                self.after(0, self.lbl_status.configure, {"text": "Stopped"})

    def _nxc_run_thread(self, cmd):
        """Background thread: run NXC, stream output, restore buttons on finish."""
        try:
            self._nxc_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            for line in iter(self._nxc_process.stdout.readline, ""):
                if line:
                    self._nxc_append_output(line)
            self._nxc_process.wait()
            rc = self._nxc_process.returncode
            if rc == 0:
                self._nxc_append_output("\n[COMPLETE] Scan finished successfully.\n")
                self._nxc_append_output("[TIP] Click 'Use Output →' to load into analyzer.\n")
            else:
                self._nxc_append_output(f"\n[DONE] Exit code {rc}\n")
        except FileNotFoundError:
            self._nxc_append_output(f"\n[ERROR] Executable not found: {cmd[0]}\n")
        except Exception as e:
            self._nxc_append_output(f"\n[ERROR] {type(e).__name__}: {e}\n")
        finally:
            self._nxc_process = None
            self.after(0, self.btn_run_nxc.configure,  {"state": "normal"})
            self.after(0, self.btn_stop_nxc.configure, {"state": "disabled"})
            self.after(0, self.lbl_status.configure, {"text": "Ready"})

    def _nxc_append_output(self, text):
        """Append text to the NXC live-output widget (thread-safe)."""
        def _do():
            self.txt_nxc_out.configure(state="normal")
            self.txt_nxc_out.insert("end", text)
            self.txt_nxc_out.see("end")
        self.after(0, _do)

    def _use_nxc_output(self):
        """Copy NXC live output into the Paste Results tab and auto-analyze."""
        content = self.txt_nxc_out.get("1.0", "end").strip()
        if not content:
            self._nxc_append_output("[INFO] No output to use yet — run a scan first.\n")
            return
        # Switch to Paste Results tab (index 0) and populate
        self.tabs.select(0)
        self.txt_paste.delete("1.0", "end")
        self.txt_paste.insert("1.0", content)
        # Trigger analysis automatically
        self.after(100, self._analyze)

    # ------------------------------------------------------------------
    # Display methods
    # ------------------------------------------------------------------

    def _display_credentials(self):
        self.txt_creds.delete("1.0", "end")
        f = self.facts

        success = [c for c in f.credentials if c.status == "SUCCESS"]
        locked  = [c for c in f.credentials if c.status == "LOCKED"]
        fails   = len([c for c in f.credentials if c.status == "FAIL"])

        def w(t): self.txt_creds.insert("end", t)

        w("=" * 65 + "\n")
        w("VALID CREDENTIALS\n")
        w("=" * 65 + "\n\n")

        if success:
            for c in success:
                sec = f"[HASH:{c.secret[:16]}...]" if c.is_hash else c.secret
                pth = "  [PTH-ready]" if c.is_hash else ""
                pwn = "  <<< Pwn3d! LOCAL ADMIN >>>" if c.pwned else ""
                w(f"  {c.domain}\\{c.username}:{sec}  @  {c.host_ip} ({c.hostname}){pth}{pwn}\n")
        else:
            w("  No valid credentials found in this output\n")

        if locked:
            w("\n" + "=" * 65 + "\n")
            w("WARNING: ACCOUNT LOCKOUTS TRIGGERED\n")
            w("=" * 65 + "\n")
            for c in locked:
                w(f"  {c.domain}\\{c.username}  LOCKED on {c.host_ip} ({c.hostname})\n")
            w("\n  ACTION: Stop spraying immediately. Notify client if appropriate.\n")

        if f.hash_dump:
            w("\n" + "=" * 65 + "\n")
            w(f"DUMPED HASHES  ({len(f.hash_dump)} total)\n")
            w("=" * 65 + "\n")
            for h in f.hash_dump[:50]:
                w(f"  {h}\n")
            if len(f.hash_dump) > 50:
                w(f"  ... and {len(f.hash_dump) - 50} more\n")

        w(f"\n{'─'*65}\n")
        w(f"Summary: {len(success)} valid | {fails} failed | {len(locked)} locked\n")

    def _display_hosts(self):
        self.txt_hosts.delete("1.0", "end")
        f = self.facts

        def w(t): self.txt_hosts.insert("end", t)

        w("=" * 65 + "\n")
        w("DISCOVERED HOSTS\n")
        w("=" * 65 + "\n\n")

        if f.hosts:
            for h in f.hosts:
                signing = "SIGNING ON" if h.signing else "SIGNING OFF  !! relay possible !!"
                admin   = "  <<< ADMIN ACCESS >>>" if h.admin_access else ""
                smb1    = "  [SMBv1 - EternalBlue risk!]" if h.smb_v1 else ""
                w(f"  {h.ip:16s}  {h.hostname:20s}  {h.os or 'Unknown OS'}\n")
                w(f"    Domain: {h.domain or 'Unknown':30s}  SMB {signing}{admin}{smb1}\n\n")
        else:
            w("  No host discovery output found in pasted data\n")

        if f.shares:
            w("=" * 65 + "\n")
            w("ENUMERATED SHARES\n")
            w("=" * 65 + "\n")
            for s in f.shares:
                remark = f"  ({s.remark})" if s.remark else ""
                w(f"  \\\\{s.hostname}\\{s.share_name:25s}  [{s.permissions}]{remark}\n")
            w("\n")

        if f.users:
            w("=" * 65 + "\n")
            w("ENUMERATED USERS\n")
            w("=" * 65 + "\n")
            for u in f.users:
                w(f"  {u.username:35s}  RID:{u.rid:6s}  on {u.host_ip} ({u.hostname})\n")

    def _display_vulnerabilities(self):
        self.txt_vulns.delete("1.0", "end")
        f = self.facts

        def w(t): self.txt_vulns.insert("end", t)

        w("=" * 65 + "\n")
        w("VULNERABILITIES & CVE CROSS-REFERENCE\n")
        w("=" * 65 + "\n\n")

        found_any = False

        smb1_hosts = [h for h in f.hosts if h.smb_v1]
        if smb1_hosts:
            found_any = True
            w("CRITICAL - SMBv1 ENABLED\n")
            w("CVEs: CVE-2017-0144 (EternalBlue), CVE-2017-0145 (EternalRomance)\n")
            w("Risk: Unauthenticated RCE, WannaCry/NotPetya propagation vector\n")
            for h in smb1_hosts:
                w(f"  Affected: {h.ip} ({h.hostname})\n")
            w("\n")

        no_sign = [h for h in f.hosts if not h.signing]
        if no_sign:
            found_any = True
            w("HIGH - SMB SIGNING DISABLED\n")
            w("Risk: NTLM relay attacks (ntlmrelayx + Responder/PetitPotam)\n")
            for h in no_sign:
                w(f"  Affected: {h.ip} ({h.hostname})\n")
            w("\n")

        if f.pwned_hosts:
            found_any = True
            w("HIGH - LOCAL ADMIN ACCESS CONFIRMED (Pwn3d!)\n")
            w("Risk: Credential dumping, lateral movement, persistence\n")
            for ip in f.pwned_hosts:
                h = next((x for x in f.hosts if x.ip == ip), None)
                w(f"  {ip} ({h.hostname if h else 'unknown'})\n")
            w("\n")

        locked = [c for c in f.credentials if c.status == "LOCKED"]
        if locked:
            found_any = True
            w("MEDIUM - ACCOUNT LOCKOUTS TRIGGERED\n")
            w("Risk: Detection likely triggered - STOP spraying\n")
            for c in locked:
                w(f"  {c.domain}\\{c.username} on {c.host_ip}\n")
            w("\n")

        raw_lower = f.raw_output.lower()
        if 'zerologon' in raw_lower and 'vulnerable' in raw_lower:
            found_any = True
            w("CRITICAL - ZEROLOGON DETECTED\n")
            w("CVE: CVE-2020-1472\n")
            w("Risk: Unauthenticated domain compromise\n\n")

        if 'nopac' in raw_lower and ('vulnerable' in raw_lower or 'exploitable' in raw_lower):
            found_any = True
            w("CRITICAL - NOPAC DETECTED\n")
            w("CVEs: CVE-2021-42278, CVE-2021-42287\n")
            w("Risk: Domain user -> Domain Admin\n\n")

        if 'petitpotam' in raw_lower and 'vulnerable' in raw_lower:
            found_any = True
            w("HIGH - PETITPOTAM DETECTED\n")
            w("CVE: CVE-2021-36942\n")
            w("Risk: Unauthenticated NTLM coercion from DC\n\n")

        if self._verified_cves:
            w("=" * 65 + "\n")
            w("CONFIRMED CVEs FROM THIS SCAN\n")
            w("=" * 65 + "\n")
            for cve in sorted(self._verified_cves):
                w(f"  {cve}\n")
            w("\nNote: CVEs above confirmed from detected conditions, not LLM-generated.\n")
            w("Any CVEs in Ask Syd answers not listed here are tagged [UNVERIFIED].\n")

        if not found_any:
            w("  No specific vulnerabilities detected in this output.\n")
            w("  Run targeted modules to check: zerologon, nopac, petitpotam\n")

    def _display_next_steps(self):
        self.txt_next.delete("1.0", "end")
        f     = self.facts
        lines = []

        lines.append("=" * 65)
        lines.append("RECOMMENDED NEXT STEPS")
        lines.append("=" * 65)
        lines.append("")

        if f.pwned_hosts:
            lines.append("PRIORITY 1 - ADMIN ACCESS: Dump credentials")
            lines.append("")
            for ip in f.pwned_hosts:
                h    = next((x for x in f.hosts if x.ip == ip), None)
                name = h.hostname if h else ip
                cred = next((c for c in f.credentials
                             if c.host_ip == ip and c.pwned), None)
                if cred:
                    sarg = f"-H {cred.secret}" if cred.is_hash else f"-p '{cred.secret}'"
                    lines.append(f"  # {ip} ({name})")
                    lines.append(f"  nxc smb {ip} -u '{cred.username}' {sarg} --sam")
                    lines.append(f"  nxc smb {ip} -u '{cred.username}' {sarg} --lsa")
                    lines.append(f"  nxc smb {ip} -u '{cred.username}' {sarg} --ntds  # DC only")
                    lines.append("")

        no_sign = [h for h in f.hosts if not h.signing]
        if no_sign:
            lines.append("PRIORITY 2 - RELAY ATTACK: SMB signing disabled")
            lines.append("")
            lines.append("  nxc smb <subnet>/24 --gen-relay-list targets_nosigning.txt")
            lines.append("  ntlmrelayx.py -tf targets_nosigning.txt -smb2support -socks")
            lines.append("  petitpotam.py <your_ip> <target_ip>")
            lines.append("")

        success = [c for c in f.credentials if c.status == "SUCCESS"]
        if success and len(f.hosts) > 1:
            lines.append("PRIORITY 3 - LATERAL MOVEMENT: Spread valid credentials")
            lines.append("")
            c    = success[0]
            sarg = f"-H {c.secret}" if c.is_hash else f"-p '{c.secret}'"
            all_ips = " ".join(h.ip for h in f.hosts)
            lines.append(f"  nxc smb {all_ips} -u '{c.username}' {sarg} --continue-on-success")
            lines.append(f"  nxc winrm {all_ips} -u '{c.username}' {sarg}")
            lines.append("")

        if f.hash_dump:
            lines.append("PRIORITY 4 - CRACK / PASS-THE-HASH")
            lines.append("")
            lines.append("  hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt")
            lines.append("  nxc smb <targets> -u Administrator -H <NThash> --continue-on-success")
            lines.append("")

        if f.hosts and not f.users and success:
            lines.append("FURTHER ENUMERATION")
            lines.append("")
            c    = success[0]
            sarg = f"-H {c.secret}" if c.is_hash else f"-p '{c.secret}'"
            lines.append(f"  nxc smb <targets> -u '{c.username}' {sarg} --users")
            lines.append(f"  nxc smb <targets> -u '{c.username}' {sarg} --shares")
            lines.append(f"  nxc ldap <DC> -u '{c.username}' {sarg} --kerberoasting kerberoast.txt")
            lines.append(f"  nxc ldap <DC> -u '{c.username}' {sarg} --asreproast asrep.txt")
            lines.append("")

        smb1 = [h for h in f.hosts if h.smb_v1]
        if smb1:
            lines.append("ADDITIONAL - SMBv1 ENABLED (EternalBlue risk)")
            lines.append("")
            for h in smb1:
                lines.append(f"  {h.ip} ({h.hostname})")
            lines.append("  Check: use Metasploit auxiliary/scanner/smb/smb_ms17_010")
            lines.append("")

        if not lines[3:]:
            lines.append("  No findings yet.")
            lines.append("  Paste NXC output and click Analyze Output.")

        self.txt_next.insert("end", "\n".join(lines))

    # ------------------------------------------------------------------
    # Anti-hallucination validator
    # ------------------------------------------------------------------

    def _validate_answer(self, answer: str) -> dict:
        if not self.facts:
            return {'valid': True, 'issues': []}

        issues    = []
        valid_ips = {h.ip for h in self.facts.hosts}

        # Derive subnet base addresses from scan hosts (e.g. 192.168.1.0 from 192.168.1.10)
        subnet_bases = set()
        for ip in valid_ips:
            parts = ip.rsplit('.', 1)
            if len(parts) == 2:
                subnet_bases.add(parts[0] + '.0')

        # Extract IPs from code blocks and inline code — these are examples, not scan claims
        exempt_from_code = set()
        for block in re.findall(r'```[\s\S]*?```', answer):
            exempt_from_code.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', block))
        for code in re.findall(r'`[^`\n]+`', answer):
            exempt_from_code.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', code))

        ip_pattern    = r'(?<!\d\.)\b(?:\d{1,3}\.){3}\d{1,3}\b(?!\.\d)'
        mentioned_ips = set(re.findall(ip_pattern, answer))
        always_exempt = {'0.0.0.0', '255.255.255.255', '127.0.0.1'}
        invented_ips  = mentioned_ips - valid_ips - always_exempt - subnet_bases - exempt_from_code
        if invented_ips:
            issues.append(f"Invented IPs not in scan: {', '.join(invented_ips)}")

        return {'valid': len(issues) == 0, 'issues': issues}

    # ------------------------------------------------------------------
    # Ask Syd
    # ------------------------------------------------------------------

    def _on_enter_key(self, event):
        if not (event.state & 0x1):
            self._send_to_syd()
            return "break"

    def _send_to_syd(self):
        if not self.rag_ready:
            messagebox.showwarning("Ask Syd", "Knowledge base still loading - please wait...")
            return

        question = self.entry_question.get("1.0", "end").strip()
        if not question:
            return

        self.entry_question.delete("1.0", "end")
        self.append_chat_message("YOU", question)
        self.show_thinking_indicator()

        import threading
        threading.Thread(target=self._query_rag, args=(question,), daemon=True).start()

    def _query_rag(self, question: str):
        try:
            # Stage A: RAG retrieval
            query_vec = self.embed_model.encode([question]).astype('float32')
            faiss.normalize_L2(query_vec)
            _, indices = self.faiss_index.search(query_vec, 3)
            context_text = "\n\n".join(
                self.chunks[i].get('content', '')
                for i in indices[0] if i < len(self.chunks)
            )

            # Stage B: Build prompt
            if not self.facts_text:
                # General knowledge mode
                system_prompt = f"""You are Syd, an expert penetration tester specialising in NXC/NetExec, Active Directory attacks, lateral movement, and credential attacks.

Answer the user's question using your expert knowledge and the knowledge base below.
Include exact NXC command syntax. Mention OPSEC considerations where relevant.
If the question requires scan data, ask them to paste NXC output and click Analyze.

EXACT NXC COMMAND SYNTAX — USE THESE FORMS ONLY:
  Password auth:     nxc smb <target> -u <user> -p '<password>'
  Hash/PTH auth:     nxc smb <target> -u <user> -H <NThash>
  Dump SAM:          nxc smb <target> -u <user> -p '<pass>' --sam
  Dump NTDS (DC):    nxc smb <target> -u <user> -p '<pass>' --ntds
  SMB exec (lateral movement): nxc smb <target> -u <user> -H <hash> -x 'whoami'
  WinRM exec:        nxc winrm <target> -u <user> -H <hash> -x 'whoami'
  Kerberoasting:     nxc ldap <DC_IP> -u <user> -p '<pass>' --kerberoasting output.txt
  AS-REP roasting:   nxc ldap <DC_IP> -u <user> -p '<pass>' --asreproast output.txt
  Spray all hosts:   nxc smb <ip1> <ip2> <ip3> -u <user> -H <hash> --continue-on-success
INVALID (NEVER USE): nxc smbexec, nxc smbrelayx, nxc kerberoast, nxc asreproast, crackmapexec
hashcat NTLM = -m 1000, Kerberoast = -m 13100, AS-REP = -m 18200, DCC2 = -m 2100
krbtgt hash = Golden Ticket attack (NOT AS-REP roasting)
LATERAL MOVEMENT = executing commands on remote hosts (-x flag), NOT just dumping credentials

NXC KNOWLEDGE BASE:
{context_text}"""
                user_msg = f"Question: {question}"

            else:
                # Fact-based mode
                facts_for_prompt, context_for_prompt = truncate_for_context_window(
                    self.llm, self.facts_text, context_text,
                    max_tokens=1536, static_prompt_chars=2800
                )

                system_prompt = f"""You are Syd, an expert penetration tester analysing NXC/NetExec output.

ANSWERING STRATEGY (3-Tier):

1. SPECIFIC SCAN DATA (Facts-First - NEVER Invent):
   - For hosts, credentials, shares, users: use ONLY the facts below
   - NEVER invent IP addresses, hostnames, usernames, passwords, hashes, domain names
   - If something is not in the facts, say "Not present in this scan output"

2. INFERENCE FROM EVIDENCE (Connect the dots):
   - Pwn3d! on host = credential dumping opportunity
   - SMB signing disabled = NTLM relay possible
   - Use phrases like "Based on the scan..." or "This indicates..."

3. GENERAL NXC KNOWLEDGE (Concepts and techniques):
   - Explain techniques, provide exact command syntax
   - Use "In general..." or "The NXC command for this is..."

EXACT NXC COMMAND SYNTAX — USE THESE FORMS ONLY:
  Password auth:     nxc smb <target> -u <user> -p '<password>'
  Hash/PTH auth:     nxc smb <target> -u <user> -H <NThash>
  Dump SAM:          nxc smb <target> -u <user> -p '<pass>' --sam
  Dump NTDS (DC):    nxc smb <target> -u <user> -p '<pass>' --ntds
  Dump LSA:          nxc smb <target> -u <user> -p '<pass>' --lsa
  Enum shares:       nxc smb <target> -u <user> -p '<pass>' --shares
  Enum users:        nxc smb <target> -u <user> -p '<pass>' --users
  Kerberoasting:     nxc ldap <DC_IP> -u <user> -p '<pass>' --kerberoasting output.txt
  AS-REP roasting:   nxc ldap <DC_IP> -u <user> -p '<pass>' --asreproast output.txt
  Relay list:        nxc smb <subnet>/24 --gen-relay-list targets_nosigning.txt
  WinRM exec:        nxc winrm <target> -u <user> -p '<pass>' -x 'whoami'
  SMB exec:          nxc smb <target> -u <user> -p '<pass>' -x 'whoami'
  Spray all hosts:   nxc smb <ip1> <ip2> <ip3> -u <user> -p '<pass>' --continue-on-success

LATERAL MOVEMENT means executing commands on remote hosts — use these:
  nxc smb <target> -u <user> -H <hash> -x 'whoami'           # remote command via SMB
  nxc winrm <target> -u <user> -H <hash> -x 'whoami'         # remote command via WinRM
  nxc smb <ip1> <ip2> <ip3> -u <user> -H <hash> --continue-on-success  # spread to all
  Dumping credentials (--sam/--ntds) is POST-EXPLOITATION, not lateral movement.

COMMAND RULES (CRITICAL):
- If plaintext passwords exist in the scan facts, ALWAYS use -p, NEVER suggest PTH with placeholder hashes
- When PTH is needed, use the ACTUAL full hash from the scan facts — NEVER use '<hash_from_lsassy>' placeholder
- INVALID commands (NEVER USE — these do not exist): nxc smbexec, nxc smbrelayx, nxc kerberoast, nxc asreproast, nxc psexec
- NEVER use crackmapexec or cme — always nxc
- hashcat NTLM cracking mode is -m 1000 (NOT -m 500, NOT -m 5600)
- hashcat Kerberoast mode: -m 13100 / AS-REP mode: -m 18200 / DCC2 = -m 2100

CVE REFERENCE (ONLY cite if confirmed by scan conditions):
- SMBv1 enabled  → CVE-2017-0144 (EternalBlue), CVE-2017-0145 (EternalRomance)  [NOT SMBGhost]
- ZeroLogon      → CVE-2020-1472  (Netlogon — requires unpatched DC)
- NoPac          → CVE-2021-42278, CVE-2021-42287
- PetitPotam     → CVE-2021-36942
- PrintNightmare → CVE-2021-1675, CVE-2021-34527
- SMBGhost       → CVE-2020-0796  (SMBv3 compression — NOT related to SMBv1)
- Any CVE not confirmed from scan conditions must be tagged [UNVERIFIED]

KERBEROS ATTACK KNOWLEDGE:
- krbtgt hash dumped → Golden Ticket attack (forge any TGT for any user, valid 10 years)
  Tool: ticketer.py -nthash <krbtgt_hash> -domain-sid <SID> -domain <DOMAIN> <username>
- Kerberoasting → crack service account TGS tickets (accounts with SPNs)
  nxc ldap <DC> -u <user> -H <hash> --kerberoasting output.txt  then  hashcat -m 13100
- AS-REP roasting → accounts with "do not require preauth" set (NOT krbtgt)
  nxc ldap <DC> -u <user> -H <hash> --asreproast output.txt  then  hashcat -m 18200
- DCSync → replicate all domain hashes (requires Pwn3d! on DC or replication rights)
  Confirmed by: admin access on DC + NTDS dump in scan

CRITICAL RULES:
- Do NOT invent hosts, users, credentials, or domains not in the facts
- Do NOT invent CVE numbers
- If asked about something not in the scan, say so clearly

SCAN FACTS (ground truth - do not contradict):
{facts_for_prompt}

NXC KNOWLEDGE BASE:
{context_for_prompt}"""
                user_msg = f"Question: {question}\n\nAnswer based on the facts above:"

            # Stage C: Generate
            response = self.llm.create_chat_completion(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_msg}
                ],
                max_tokens=1536,
                temperature=0.1,
                top_p=0.9,
                stop=["Question:", "Q:", "\n\n\n"]
            )
            answer = response['choices'][0]['message']['content'].strip()

            # Stage D: Post-process
            answer = tag_unverified_cves(answer, self._verified_cves)

            # Repetition detection
            lines        = answer.split('\n')
            seen_headers = {}
            clean_lines  = []
            for i, line in enumerate(lines):
                if i >= 60:
                    break
                stripped = line.strip()
                if len(stripped) > 5 and re.match(r'^[A-Z\s:=\-]{5,}$', stripped):
                    seen_headers[stripped] = seen_headers.get(stripped, 0) + 1
                    if seen_headers[stripped] >= 2:
                        break
                clean_lines.append(line)
            answer = '\n'.join(clean_lines)

            # Anti-hallucination check
            validation = self._validate_answer(answer)
            if not validation['valid']:
                answer += "\n\n[VALIDATION WARNING] " + "; ".join(validation['issues'])
                self.log_to_asksyd(f"[WARN] Hallucination detected: {validation['issues']}")

            self.after(0, self.remove_thinking_indicator)
            self.after(0, lambda: self.append_chat_message("SYD", answer))

        except Exception as e:
            self.after(0, self.remove_thinking_indicator)
            self.after(0, lambda: self.append_chat_message("SYD", f"Error: {e}"))
            import traceback
            traceback.print_exc()

    # ------------------------------------------------------------------
    # Copy helpers
    # ------------------------------------------------------------------

    def _copy_tab(self, widget, label):
        content = widget.get("1.0", "end").strip()
        if content:
            self.clipboard_clear()
            self.clipboard_append(content)
            self.clipboard_append("")
            messagebox.showinfo("Copied", f"{label} copied to clipboard.")
        else:
            messagebox.showinfo("Nothing to Copy",
                f"No {label.lower()} yet - run Analyze first.")

    def _copy_all_creds(self):   self._copy_tab(self.txt_creds, "Credentials")
    def _copy_all_hosts(self):   self._copy_tab(self.txt_hosts, "Hosts & Access")
    def _copy_all_vulns(self):   self._copy_tab(self.txt_vulns, "Vulnerabilities")
    def _copy_next_steps(self):  self._copy_tab(self.txt_next,  "Next Steps")

    # ------------------------------------------------------------------
    # Chat helpers
    # ------------------------------------------------------------------

    def append_chat_message(self, sender, message):
        self.txt_chat.insert(tk.END, f"\n{'='*60}\n[{sender}]\n{message}\n")
        self.txt_chat.see(tk.END)

    def show_thinking_indicator(self):
        self._thinking_start = self.txt_chat.index(tk.END)
        self.txt_chat.insert(tk.END, f"\n{'='*60}\n[SYD]\nThinking...\n")
        self.txt_chat.see(tk.END)

    def remove_thinking_indicator(self):
        try:
            if self._thinking_start:
                self.txt_chat.delete(self._thinking_start, tk.END)
        except Exception:
            pass

    def log_to_asksyd(self, message):
        def _update():
            self.txt_log.insert(tk.END, f"{message}\n")
            self.txt_log.see(tk.END)
        try:
            self.after(0, _update)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Clear
    # ------------------------------------------------------------------

    def _clear_results(self):
        for w in [self.txt_creds, self.txt_hosts, self.txt_vulns, self.txt_next]:
            w.delete("1.0", "end")

    def _clear_all(self):
        for w in [self.txt_paste, self.txt_creds, self.txt_hosts,
                  self.txt_vulns, self.txt_next, self.txt_chat]:
            w.delete("1.0", "end")
        self.facts          = None
        self.facts_text     = None
        self._verified_cves = set()
        self.lbl_status.configure(
            text="NXC ready - paste terminal output and click Analyze")
        self.log_to_asksyd("[INFO] Cleared")

    # ------------------------------------------------------------------
    # Right-click context menu
    # ------------------------------------------------------------------

    def _create_context_menu(self, widget):
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="Cut",        command=lambda: widget.event_generate("<<Cut>>"))
        menu.add_command(label="Copy",       command=lambda: widget.event_generate("<<Copy>>"))
        menu.add_command(label="Paste",      command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_separator()
        menu.add_command(label="Select All", command=lambda: widget.tag_add("sel", "1.0", "end"))

        def show_menu(event):
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        widget.bind("<Button-3>", show_menu)


# ---------------------------- PCAP Page ----------------------------
class PCAPPage(ttk.Frame):
    """PCAP Blue Team Analysis - C2 Detection, Lateral Movement, Exfil, IR"""

    def __init__(self, parent):
        super().__init__(parent)

        self.facts           = None
        self.facts_text      = None
        self.rag_ready       = False
        self.embed_model     = None
        self.llm             = None
        self.faiss_index     = None
        self.chunks          = None
        self._pcap_path      = None
        self._thinking_start = None

        main_paned = ttk.PanedWindow(self, orient="horizontal")
        main_paned.pack(fill="both", expand=True)

        left_frame  = ttk.Frame(main_paned)
        right_frame = ttk.Frame(main_paned)
        main_paned.add(left_frame,  weight=3)
        main_paned.add(right_frame, weight=2)
        right_frame.configure(width=500)

        # ===== LEFT =====
        controls_frame = ttk.Frame(left_frame)
        controls_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(controls_frame, text="PCAP Analysis - Blue Team Threat Hunting",
                  style="Header.TLabel").pack(anchor="w", pady=(0,6))

        btn_row = ttk.Frame(controls_frame)
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="Load PCAP File", command=self._load_pcap,
                   style="Accent.TButton").pack(side="left", padx=(0,5))
        ttk.Button(btn_row, text="Analyse", command=self._analyse,
                   style="Accent.TButton").pack(side="left", padx=(0,5))
        ttk.Button(btn_row, text="Clear All", command=self._clear_all).pack(side="left", padx=5)

        self.lbl_status = ttk.Label(controls_frame,
            text="Load a PCAP file to begin analysis",
            foreground=INK_SOFT)
        self.lbl_status.pack(anchor="w", pady=(4,0))

        self.lbl_file = ttk.Label(controls_frame, text="No file loaded",
                                   foreground=INK_SOFT, font=("Consolas", 8))
        self.lbl_file.pack(anchor="w")

        # Results tabs
        results_frame = ttk.Frame(left_frame)
        results_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.tabs = ttk.Notebook(results_frame)
        self.tabs.pack(fill="both", expand=True)

        def _make_tab(label):
            tab = ttk.Frame(self.tabs)
            self.tabs.add(tab, text=label)
            hdr = ttk.Frame(tab)
            hdr.pack(fill="x", padx=5, pady=(4,2))
            ttk.Button(hdr, text="Copy",
                command=lambda l=label: self._copy_tab(l)).pack(side="right")
            inner = ttk.Frame(tab)
            inner.pack(fill="both", expand=True)
            txt = tk.Text(inner, bg=BG_DARK, fg=INK, insertbackground=INK,
                          wrap="word", font=("Consolas", 9))
            sb = ttk.Scrollbar(inner, command=txt.yview)
            txt.configure(yscrollcommand=sb.set)
            txt.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            return txt

        self.txt_overview   = _make_tab("Overview")
        self.txt_threats    = _make_tab("Threats & IOCs")
        self.txt_c2         = _make_tab("C2 / Beaconing")
        self.txt_lateral    = _make_tab("Lateral Movement")
        self.txt_creds      = _make_tab("Credentials")
        self.txt_dns        = _make_tab("DNS Analysis")
        self.txt_exfil      = _make_tab("Exfiltration")
        self.txt_mitre      = _make_tab("MITRE ATT&CK")

        # ===== RIGHT - Ask Syd =====
        hdr = ttk.Frame(right_frame)
        hdr.pack(fill="x", padx=5, pady=5)
        title_row = ttk.Frame(hdr)
        title_row.pack(fill="x")
        ttk.Label(title_row, text="Ask Syd - PCAP Blue Team Expert",
                  style="Header.TLabel").pack(side="left")
        ttk.Label(title_row, text="Blue Team",
                  background="#1d4ed8", foreground="#fff", padding=(5,2)).pack(side="left", padx=10)

        chat_frame = ttk.Frame(right_frame)
        chat_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.txt_chat = tk.Text(chat_frame, bg=BG_DARK, fg=INK, insertbackground=INK,
                                wrap="word", height=20)
        sb2 = ttk.Scrollbar(chat_frame, command=self.txt_chat.yview)
        self.txt_chat.configure(yscrollcommand=sb2.set)
        self.txt_chat.pack(side="left", fill="both", expand=True)
        sb2.pack(side="right", fill="y")

        # Chat tags
        self.txt_chat.tag_configure("syd",      foreground="#4FC3F7", font=("Consolas", 9, "bold"))
        self.txt_chat.tag_configure("user",     foreground="#81C784", font=("Consolas", 9, "bold"))
        self.txt_chat.tag_configure("warning",  foreground="#FFB74D")
        self.txt_chat.tag_configure("thinking", foreground="#888888", font=("Consolas", 9, "italic"))

        log_frame = ttk.Frame(right_frame)
        log_frame.pack(fill="x", padx=5, pady=(0,2))
        self.txt_log = tk.Text(log_frame, bg=BG_DARK, fg=INK_SOFT, insertbackground=INK,
                               wrap="word", height=5)
        sb3 = ttk.Scrollbar(log_frame, command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=sb3.set)
        self.txt_log.pack(side="left", fill="both", expand=True)
        sb3.pack(side="right", fill="y")

        input_frame = ttk.Frame(right_frame)
        input_frame.pack(fill="x", padx=5, pady=5)
        self.entry_question = tk.Text(input_frame, height=3, bg=BG_DARK, fg=INK,
                                      insertbackground=INK, wrap="word",
                                      font=("Segoe UI", 10))
        self.entry_question.pack(side="left", fill="x", expand=True, padx=(0,5))
        self.entry_question.bind("<Return>",       self._on_enter)
        self.entry_question.bind("<Shift-Return>", lambda e: None)
        ttk.Button(input_frame, text="Ask", command=self._send,
                   style="Accent.TButton").pack(side="right")

        self.log_to_chat("[INFO] PCAP blue team analyzer ready")
        self.log_to_chat("[INFO] Load a PCAP file and click Analyse to begin")

    # ------------------------------------------------------------------
    # File loading
    # ------------------------------------------------------------------

    def _load_pcap(self):
        path = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[("PCAP files", "*.pcap *.pcapng *.cap"), ("All files", "*.*")]
        )
        if not path:
            return
        self._pcap_path = path
        filename = Path(path).name
        size_mb  = os.path.getsize(path) / (1024*1024)
        self.lbl_file.configure(text=f"{filename}  ({size_mb:.1f} MB)")
        self.lbl_status.configure(text=f"File loaded: {filename} — click Analyse")
        self.log_to_chat(f"[FILE] {filename} ({size_mb:.1f} MB) — click Analyse to begin")

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def _analyse(self):
        if not self._pcap_path:
            self.lbl_status.configure(text="No file loaded — click Load PCAP File first")
            return
        self.lbl_status.configure(text="Analysing PCAP... please wait")
        self.log_to_chat("[*] Parsing PCAP file...")
        import threading
        t = threading.Thread(target=self._analyse_thread, daemon=True)
        t.start()

    def _analyse_thread(self):
        try:
            from pcap_fact_extractor import extract, facts_to_text
        except ImportError:
            try:
                import importlib.util, sys
                spec = importlib.util.spec_from_file_location(
                    "pcap_fact_extractor",
                    str(BASE_PATH / "pcap_fact_extractor.py")
                )
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                extract      = mod.extract
                facts_to_text = mod.facts_to_text
            except Exception as e:
                self.after(0, self.lbl_status.configure, {"text": "Import error"})
                self.after(0, self.log_to_chat, f"[ERROR] Cannot import pcap_fact_extractor: {e}")
                return

        try:
            facts = extract(self._pcap_path)
            self.facts      = facts
            self.facts_text = facts_to_text(facts)

            if facts.warnings:
                for w in facts.warnings:
                    self.after(0, self.log_to_chat, f"[WARN] {w}")

            self.after(0, self._display_all)
            self.after(0, self._load_rag)

        except Exception as e:
            import traceback
            self.after(0, self.lbl_status.configure, {"text": "Analysis failed"})
            self.after(0, self.log_to_chat, f"[ERROR] {e}")
            traceback.print_exc()

    def _display_all(self):
        f = self.facts
        self._display_overview(f)
        self._display_threats(f)
        self._display_c2(f)
        self._display_lateral(f)
        self._display_creds(f)
        self._display_dns(f)
        self._display_exfil(f)
        self._display_mitre(f)

        n_threats = len(f.suspicious_activities)
        n_crit    = sum(1 for a in f.suspicious_activities if a.severity == "CRITICAL")
        n_high    = sum(1 for a in f.suspicious_activities if a.severity == "HIGH")
        self.lbl_status.configure(
            text=f"Done - {f.total_packets:,} packets | {len(f.hosts)} hosts | "
                 f"{n_threats} threats ({n_crit} CRITICAL, {n_high} HIGH)"
        )
        self.log_to_chat(
            f"[OK] Analysis complete: {f.total_packets:,} packets, {len(f.hosts)} hosts, "
            f"{n_threats} suspicious activities"
        )
        self.tabs.select(0)

    # ------------------------------------------------------------------
    # Display methods
    # ------------------------------------------------------------------

    def _ins(self, widget, text):
        widget.insert("end", text)

    def _display_overview(self, f):
        w = self.txt_overview
        w.delete("1.0", "end")
        from datetime import datetime

        start = datetime.fromtimestamp(f.capture_start).strftime("%Y-%m-%d %H:%M:%S") if f.capture_start else "Unknown"
        end   = datetime.fromtimestamp(f.capture_end).strftime("%Y-%m-%d %H:%M:%S") if f.capture_end else "Unknown"

        self._ins(w, "=" * 65 + "\n")
        self._ins(w, f"PCAP OVERVIEW: {f.filename}\n")
        self._ins(w, "=" * 65 + "\n\n")
        self._ins(w, f"File size:      {f.file_size_mb:.1f} MB\n")
        self._ins(w, f"Total packets:  {f.total_packets:,}\n")
        self._ins(w, f"Capture start:  {start}\n")
        self._ins(w, f"Capture end:    {end}\n")
        self._ins(w, f"Duration:       {f.capture_duration_s:.0f} seconds\n\n")

        self._ins(w, "PROTOCOL BREAKDOWN\n" + "-" * 40 + "\n")
        for proto, cnt in sorted(f.protocol_counts.items(), key=lambda x: x[1], reverse=True):
            self._ins(w, f"  {proto:<15} {cnt:>8,} packets\n")
        self._ins(w, "\n")

        self._ins(w, f"HOSTS DISCOVERED ({len(f.hosts)})\n" + "-" * 40 + "\n")
        sorted_hosts = sorted(f.hosts.items(),
                              key=lambda x: x[1].bytes_sent + x[1].bytes_recv,
                              reverse=True)
        for ip, h in sorted_hosts[:25]:
            role = "INT" if h.is_internal else "EXT"
            mb_s = h.bytes_sent / (1024*1024)
            mb_r = h.bytes_recv / (1024*1024)
            hn   = f" ({h.hostname})" if h.hostname else ""
            self._ins(w, f"  [{role}] {ip}{hn}\n")
            self._ins(w, f"         Sent: {mb_s:.1f}MB  Recv: {mb_r:.1f}MB  "
                       f"Protocols: {', '.join(sorted(h.protocols)) or 'unknown'}\n")
        self._ins(w, "\n")

        crit = sum(1 for a in f.suspicious_activities if a.severity == "CRITICAL")
        high = sum(1 for a in f.suspicious_activities if a.severity == "HIGH")
        med  = sum(1 for a in f.suspicious_activities if a.severity == "MEDIUM")
        self._ins(w, "THREAT SUMMARY\n" + "-" * 40 + "\n")
        self._ins(w, f"  CRITICAL:  {crit}\n")
        self._ins(w, f"  HIGH:      {high}\n")
        self._ins(w, f"  MEDIUM:    {med}\n")
        self._ins(w, f"  Beacons:   {len(f.beacon_candidates)}\n")
        self._ins(w, f"  Port scans:{len(f.port_scan_sources)}\n")
        self._ins(w, f"  Creds:     {len(f.credential_captures)}\n")
        self._ins(w, f"  Large xfer:{len(f.large_transfers)}\n")

    def _display_threats(self, f):
        w = self.txt_threats
        w.delete("1.0", "end")
        self._ins(w, "=" * 65 + "\n")
        self._ins(w, "ALL SUSPICIOUS ACTIVITIES (prioritised by severity)\n")
        self._ins(w, "=" * 65 + "\n\n")

        if not f.suspicious_activities:
            self._ins(w, "No suspicious activities detected.\n")
            return

        for act in f.suspicious_activities:
            self._ins(w, f"[{act.severity}] [{act.category}]\n")
            self._ins(w, f"  {act.description}\n")
            if act.mitre_technique:
                self._ins(w, f"  MITRE: {act.mitre_technique}\n")
            if act.src_ip and act.dst_ip:
                self._ins(w, f"  {act.src_ip} -> {act.dst_ip}\n")
            if act.evidence:
                self._ins(w, f"  Evidence: {act.evidence}\n")
            self._ins(w, "\n")

        # IOC summary
        all_ips = set()
        for act in f.suspicious_activities:
            if act.src_ip:
                all_ips.add(act.src_ip)
            if act.dst_ip and act.dst_ip != "EXTERNAL":
                all_ips.add(act.dst_ip)

        if all_ips or f.suspicious_domains:
            self._ins(w, "=" * 65 + "\n")
            self._ins(w, "IOC SUMMARY\n")
            self._ins(w, "=" * 65 + "\n\n")
            if all_ips:
                self._ins(w, "SUSPICIOUS IPs:\n")
                for ip in sorted(all_ips):
                    self._ins(w, f"  {ip}\n")
                self._ins(w, "\n")
            if f.suspicious_domains:
                self._ins(w, "SUSPICIOUS DOMAINS:\n")
                for d in sorted(f.suspicious_domains)[:30]:
                    self._ins(w, f"  {d}\n")

    def _display_c2(self, f):
        w = self.txt_c2
        w.delete("1.0", "end")
        self._ins(w, "=" * 65 + "\n")
        self._ins(w, "C2 / BEACONING ANALYSIS\n")
        self._ins(w, "=" * 65 + "\n\n")

        if f.beacon_candidates:
            self._ins(w, f"BEACONING DETECTED ({len(f.beacon_candidates)} flows)\n")
            self._ins(w, "-" * 40 + "\n")
            for bc in f.beacon_candidates:
                self._ins(w, f"  [{bc.confidence} CONFIDENCE]\n")
                self._ins(w, f"  {bc.src_ip} -> {bc.dst_ip}:{bc.dst_port}\n")
                self._ins(w, f"  Packets:  {bc.packet_count}\n")
                self._ins(w, f"  Interval: {bc.interval_avg:.1f}s avg (jitter: {bc.interval_jitter:.1f}s)\n")
                self._ins(w, f"  MITRE:    T1071 - Application Layer Protocol\n\n")
        else:
            self._ins(w, "No beaconing patterns detected.\n\n")

        if f.dga_candidates:
            self._ins(w, f"DGA DOMAIN CANDIDATES ({len(f.dga_candidates)})\n")
            self._ins(w, "-" * 40 + "\n")
            self._ins(w, "High-entropy domains indicative of DGA malware:\n")
            for d in f.dga_candidates[:20]:
                self._ins(w, f"  [DGA] {d}\n")
            self._ins(w, f"\nMITRE: T1568.002 - Domain Generation Algorithms\n\n")

        if f.dns_tunnel_candidates:
            self._ins(w, f"DNS TUNNEL CANDIDATES ({len(f.dns_tunnel_candidates)})\n")
            self._ins(w, "-" * 40 + "\n")
            for d in f.dns_tunnel_candidates[:10]:
                self._ins(w, f"  [TUNNEL] {d}\n")
            self._ins(w, f"\nMITRE: T1071.004 - DNS\n\n")

        if f.suspicious_user_agents:
            self._ins(w, "SUSPICIOUS HTTP USER AGENTS\n")
            self._ins(w, "-" * 40 + "\n")
            for ua in f.suspicious_user_agents:
                count = f.user_agents.get(ua, 1)
                self._ins(w, f"  [{count}x] {ua}\n")
            self._ins(w, "\n")

        c2_acts = [a for a in f.suspicious_activities if a.category == "C2_BEACON"]
        if not c2_acts and not f.beacon_candidates and not f.dga_candidates:
            self._ins(w, "No C2 indicators detected in this capture.\n")

    def _display_lateral(self, f):
        w = self.txt_lateral
        w.delete("1.0", "end")
        self._ins(w, "=" * 65 + "\n")
        self._ins(w, "LATERAL MOVEMENT DETECTION\n")
        self._ins(w, "=" * 65 + "\n\n")

        has_any = False

        if f.smb_connections:
            has_any = True
            internal = [s for s in f.smb_connections if s.get("internal_to_internal")]
            external = [s for s in f.smb_connections if not s.get("internal_to_internal")]
            self._ins(w, f"SMB CONNECTIONS ({len(f.smb_connections)} total)\n")
            self._ins(w, "-" * 40 + "\n")
            if internal:
                self._ins(w, f"  INTERNAL-TO-INTERNAL ({len(internal)}) [HIGH RISK - potential lateral movement]\n")
                for s in internal[:15]:
                    self._ins(w, f"    {s['src']} -> {s['dst']}:{s['port']}\n")
                self._ins(w, f"  MITRE: T1021.002 - SMB/Windows Admin Shares\n\n")
            if external:
                self._ins(w, f"  OTHER SMB ({len(external)})\n")
                for s in external[:10]:
                    self._ins(w, f"    {s['src']} -> {s['dst']}:{s['port']}\n")
            self._ins(w, "\n")

        if f.rdp_connections:
            has_any = True
            self._ins(w, f"RDP CONNECTIONS ({len(f.rdp_connections)})\n")
            self._ins(w, "-" * 40 + "\n")
            for r in f.rdp_connections[:15]:
                self._ins(w, f"  {r['src']} -> {r['dst']}:3389\n")
            self._ins(w, "  MITRE: T1021.001 - Remote Desktop Protocol\n\n")

        if f.winrm_connections:
            has_any = True
            self._ins(w, f"WINRM/POWERSHELL REMOTING ({len(f.winrm_connections)})\n")
            self._ins(w, "-" * 40 + "\n")
            for r in f.winrm_connections[:15]:
                self._ins(w, f"  {r['src']} -> {r['dst']}:{r['port']}\n")
            self._ins(w, "  MITRE: T1021.006 - Windows Remote Management\n\n")

        if f.wmi_connections:
            has_any = True
            self._ins(w, f"WMI/RPC CONNECTIONS ({len(f.wmi_connections)})\n")
            self._ins(w, "-" * 40 + "\n")
            for r in f.wmi_connections[:10]:
                self._ins(w, f"  {r['src']} -> {r['dst']}:135\n")
            self._ins(w, "  MITRE: T1047 - Windows Management Instrumentation\n\n")

        if not has_any:
            self._ins(w, "No lateral movement indicators detected.\n")

    def _display_creds(self, f):
        w = self.txt_creds
        w.delete("1.0", "end")
        self._ins(w, "=" * 65 + "\n")
        self._ins(w, "CREDENTIALS CAPTURED\n")
        self._ins(w, "=" * 65 + "\n\n")

        if not f.credential_captures:
            self._ins(w, "No credentials captured in this PCAP.\n")
            return

        # Group by type
        by_type = {}
        for c in f.credential_captures:
            by_type.setdefault(c.auth_type or c.protocol, []).append(c)

        for auth_type, creds in sorted(by_type.items()):
            self._ins(w, f"{auth_type} ({len(creds)})\n")
            self._ins(w, "-" * 40 + "\n")
            for c in creds[:20]:
                self._ins(w, f"  {c.src_ip} -> {c.dst_ip}\n")
                if c.username:
                    self._ins(w, f"    Username:  {c.username}\n")
                if c.cleartext:
                    self._ins(w, f"    Value:     {c.cleartext}\n")
                if c.hash_value:
                    self._ins(w, f"    Hash:      {c.hash_value}\n")
            self._ins(w, "\n")

        self._ins(w, "MITRE: T1557 - Adversary-in-the-Middle, T1110 - Brute Force\n")
        if any(c.auth_type == "NTLM" for c in f.credential_captures):
            self._ins(w, "\nNTLM RELAY RISK: NTLM hashes captured — relay attack possible\n")
            self._ins(w, "Tool: Responder + ntlmrelayx\n")
            self._ins(w, "MITRE: T1557.001 - LLMNR/NBT-NS Poisoning\n")

    def _display_dns(self, f):
        w = self.txt_dns
        w.delete("1.0", "end")
        self._ins(w, "=" * 65 + "\n")
        self._ins(w, "DNS ANALYSIS\n")
        self._ins(w, "=" * 65 + "\n\n")
        self._ins(w, f"Total DNS queries:     {len(f.dns_queries)}\n")
        self._ins(w, f"Unique domains:        {len(f.unique_domains)}\n")
        self._ins(w, f"NXDOMAIN responses:    {len(f.nx_domains)}\n")
        self._ins(w, f"DGA candidates:        {len(f.dga_candidates)}\n")
        self._ins(w, f"DNS tunnel candidates: {len(f.dns_tunnel_candidates)}\n\n")

        if f.dga_candidates:
            self._ins(w, "DGA CANDIDATES (high-entropy, malware-generated domains)\n")
            self._ins(w, "-" * 40 + "\n")
            for d in f.dga_candidates[:25]:
                self._ins(w, f"  {d}\n")
            self._ins(w, "\n")

        if f.dns_tunnel_candidates:
            self._ins(w, "DNS TUNNEL CANDIDATES\n")
            self._ins(w, "-" * 40 + "\n")
            for d in f.dns_tunnel_candidates[:10]:
                self._ins(w, f"  {d}\n")
            self._ins(w, "\n")

        if f.nx_domains:
            self._ins(w, f"NXDOMAIN FAILURES ({len(f.nx_domains)}) — High rate may indicate DGA\n")
            self._ins(w, "-" * 40 + "\n")
            for d in sorted(f.nx_domains)[:20]:
                self._ins(w, f"  {d}\n")
            self._ins(w, "\n")

        # Top queried domains
        domain_counts = {}
        for q in f.dns_queries:
            domain_counts[q.query] = domain_counts.get(q.query, 0) + 1
        top = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        if top:
            self._ins(w, "TOP QUERIED DOMAINS\n")
            self._ins(w, "-" * 40 + "\n")
            for domain, cnt in top:
                flag = " [DGA]" if domain in f.dga_candidates else \
                       " [TUNNEL]" if domain in f.dns_tunnel_candidates else \
                       " [SUSPICIOUS]" if domain in f.suspicious_domains else ""
                self._ins(w, f"  {cnt:>5}x  {domain}{flag}\n")

    def _display_exfil(self, f):
        w = self.txt_exfil
        w.delete("1.0", "end")
        self._ins(w, "=" * 65 + "\n")
        self._ins(w, "DATA EXFILTRATION INDICATORS\n")
        self._ins(w, "=" * 65 + "\n\n")

        has_any = False

        if f.large_transfers:
            has_any = True
            self._ins(w, f"LARGE OUTBOUND TRANSFERS ({len(f.large_transfers)})\n")
            self._ins(w, "-" * 40 + "\n")
            for xfer in f.large_transfers:
                self._ins(w, f"  {xfer['src_ip']}: {xfer['mb']:.1f} MB sent to external hosts\n")
            self._ins(w, "\n  MITRE: T1041 - Exfiltration Over C2 Channel\n\n")

        if f.dns_tunnel_candidates:
            has_any = True
            self._ins(w, f"DNS EXFILTRATION CANDIDATES ({len(f.dns_tunnel_candidates)})\n")
            self._ins(w, "-" * 40 + "\n")
            for d in f.dns_tunnel_candidates[:15]:
                self._ins(w, f"  {d}\n")
            self._ins(w, "\n  MITRE: T1048.003 - Exfiltration Over Unencrypted Protocol\n\n")

        # High-volume HTTP POSTs
        post_reqs = [r for r in f.http_requests if r.method == "POST" and r.content_length > 100000]
        if post_reqs:
            has_any = True
            self._ins(w, f"LARGE HTTP POST REQUESTS ({len(post_reqs)})\n")
            self._ins(w, "-" * 40 + "\n")
            for r in post_reqs[:10]:
                mb = r.content_length / (1024*1024)
                self._ins(w, f"  {r.src_ip} -> {r.host}{r.uri} ({mb:.1f}MB)\n")
            self._ins(w, "\n  MITRE: T1048 - Exfiltration Over Alternative Protocol\n\n")

        if not has_any:
            self._ins(w, "No data exfiltration indicators detected.\n")

    def _display_mitre(self, f):
        w = self.txt_mitre
        w.delete("1.0", "end")
        self._ins(w, "=" * 65 + "\n")
        self._ins(w, "MITRE ATT&CK MAPPING\n")
        self._ins(w, "=" * 65 + "\n\n")

        # Collect all unique MITRE techniques
        seen = {}
        for act in f.suspicious_activities:
            if act.mitre_technique:
                tid = act.mitre_technique.split(" - ")[0]
                if tid not in seen:
                    seen[tid] = {"technique": act.mitre_technique,
                                 "category": act.category,
                                 "severity": act.severity,
                                 "count": 0}
                seen[tid]["count"] += 1

        if not seen:
            self._ins(w, "No MITRE ATT&CK techniques mapped from this capture.\n")
            return

        # Sort by severity then count
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_items = sorted(seen.items(),
                              key=lambda x: (sev_order.get(x[1]["severity"], 4), -x[1]["count"]))

        for tid, info in sorted_items:
            self._ins(w, f"[{info['severity']}] {info['technique']}\n")
            self._ins(w, f"       Category: {info['category']}  |  Observed: {info['count']} time(s)\n\n")

        self._ins(w, "=" * 65 + "\n")
        self._ins(w, f"Total techniques identified: {len(seen)}\n")

    # ------------------------------------------------------------------
    # RAG / Ask Syd
    # ------------------------------------------------------------------

    def _load_rag(self):
        import threading
        t = threading.Thread(target=self._load_rag_thread, daemon=True)
        t.start()

    def _load_rag_thread(self):
        try:
            import faiss, pickle, numpy as np
            from sentence_transformers import SentenceTransformer

            self.after(0, self.log_to_chat, "[LOADING] Loading PCAP knowledge base...")

            idx_path = BASE_PATH / "rag_engine" / "embeddings" / "customers" / "customer_syd_pcap_knowledge.faiss"
            pkl_path = BASE_PATH / "rag_engine" / "embeddings" / "customers" / "customer_syd_pcap_knowledge.pkl"

            if not idx_path.exists():
                self.after(0, self.log_to_chat, "[WARN] PCAP knowledge base not found - RAG disabled")
                return

            self.faiss_index = faiss.read_index(str(idx_path))
            with open(pkl_path, "rb") as f:
                self.chunks = pickle.load(f)

            if self.embed_model is None:
                hf_home = BASE_PATH / "hf_home"
                if hf_home.exists():
                    import os
                    os.environ["SENTENCE_TRANSFORMERS_HOME"] = str(hf_home / "sentence_transformers")
                self.embed_model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

            self.after(0, self.log_to_chat, "[OK] Embedding model loaded")
            self.after(0, self.log_to_chat, f"[OK] Loaded {len(self.chunks)} PCAP knowledge chunks")
            self.after(0, self.log_to_chat, "[OK] Using shared LLM (Qwen 2.5 14B)")
            self.after(0, self.log_to_chat, "[OK] PCAP fact extractor ready")
            self.rag_ready = True
            self.after(0, self.log_to_chat, "[SUCCESS] Ask Syd ready! Ask about threats, C2, lateral movement, exfil...")

        except Exception as e:
            self.after(0, self.log_to_chat, "[WARN] Ask Syd knowledge base could not load. Ensure 'hf_home' folder is present.")

    def _query_rag(self, question: str) -> str:
        if not self.rag_ready or self.faiss_index is None:
            return ""
        try:
            import numpy as np
            emb = self.embed_model.encode([question]).astype("float32")
            norm = np.linalg.norm(emb)
            if norm > 0:
                emb = emb / norm
            D, I = self.faiss_index.search(emb, 2)
            contexts = []
            for idx in I[0]:
                if 0 <= idx < len(self.chunks):
                    contexts.append(self.chunks[idx]["text"])
            return "\n\n".join(contexts)
        except Exception:
            return ""

    def _on_enter(self, event):
        self._send()
        return "break"

    def _send(self):
        question = self.entry_question.get("1.0", "end").strip()
        if not question:
            return
        if not self.rag_ready:
            self.log_to_chat("[WARN] Knowledge base still loading - please wait...")
            return
        self.entry_question.delete("1.0", "end")
        self.append_chat("You", question, "user")
        import threading
        t = threading.Thread(target=self._query_thread, args=(question,), daemon=True)
        t.start()

    def _query_thread(self, question: str):
        try:
            self.after(0, self.show_thinking)
            rag_ctx = self._query_rag(question)

            if self.llm is None:
                self.llm = get_shared_llm()

            facts_text = self.facts_text or ""

            if not facts_text or not self.facts:
                # No PCAP data - answer general questions using knowledge base only
                system_prompt = f"""You are Syd, a blue team analyst specialising in PCAP analysis, network forensics, and threat hunting.

The user has asked a general question without providing PCAP data. Answer their question using your knowledge of PCAP analysis, network protocols, Wireshark, packet inspection, threat hunting, and network forensics.

Be specific and actionable. Include exact filter syntax (Wireshark display filters, BPF filters) where relevant.
If the question would benefit from actual PCAP data, suggest they load a PCAP file for analysis.

KNOWLEDGE CONTEXT:
{rag_ctx}"""
            else:
                facts_text, rag_ctx = truncate_for_context_window(
                    self.llm, facts_text, rag_ctx,
                    max_tokens=768, static_prompt_chars=600
                )

                system_prompt = f"""You are Syd, a blue team analyst specialising in PCAP analysis and threat hunting.

PCAP ANALYSIS RESULTS:
{facts_text}

RULES:
- Answer ONLY from the PCAP results above. Do NOT invent IPs, hosts, or findings not present.
- If something is not observed, say so.
- Be concise and actionable.

KNOWLEDGE CONTEXT:
{rag_ctx}"""

            prompt = f"[INST] {system_prompt}\n\nQuestion: {question} [/INST]"
            response = self.llm(prompt, max_tokens=768, temperature=0.1,
                                repeat_penalty=1.15,
                                stop=["[INST]", "</s>", "[Note:", "[END]"])
            answer = response["choices"][0]["text"].strip()

            validated = self._validate(answer)
            self.after(0, self.remove_thinking)
            self.after(0, self.append_chat, "Syd", validated["text"], "syd")
            if validated.get("warnings"):
                for w in validated["warnings"]:
                    self.after(0, self.append_chat, "WARNING", w, "warning")

        except Exception as e:
            self.after(0, self.remove_thinking)
            self.after(0, self.append_chat, "Syd", f"Error: {e}", "syd")

    def _validate(self, answer: str) -> dict:
        """Basic validation - flag IPs not seen in capture."""
        import re
        warnings = []
        if not self.facts:
            return {"text": answer, "warnings": warnings}

        valid_ips = set(self.facts.hosts.keys())
        mentioned = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', answer))

        # Exempt IPs in code blocks
        exempt = set()
        for block in re.findall(r'```[\s\S]*?```', answer):
            exempt.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', block))
        for code in re.findall(r'`[^`\n]+`', answer):
            exempt.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', code))

        # Subnet bases
        subnet_bases = set()
        for ip in valid_ips:
            parts = ip.rsplit('.', 1)
            if len(parts) == 2:
                subnet_bases.add(parts[0] + '.0')

        always_exempt = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}
        invented = mentioned - valid_ips - always_exempt - subnet_bases - exempt
        if invented:
            warnings.append(f"IP(s) not observed in capture: {', '.join(sorted(invented))}")

        return {"text": answer, "warnings": warnings}

    # ------------------------------------------------------------------
    # Chat helpers
    # ------------------------------------------------------------------

    def append_chat(self, sender, message, tag="syd"):
        self.txt_chat.insert("end", f"\n{sender}: ", tag)
        self.txt_chat.insert("end", message + "\n")
        self.txt_chat.see("end")

    def show_thinking(self):
        self.txt_chat.insert("end", "\nSyd: [thinking...]\n", "thinking")
        self.txt_chat.see("end")

    def remove_thinking(self):
        content = self.txt_chat.get("1.0", "end")
        if "[thinking...]" in content:
            idx = content.rfind("\nSyd: [thinking...]\n")
            if idx >= 0:
                self.txt_chat.delete(f"1.0 + {idx} chars",
                                     f"1.0 + {idx + len(chr(10) + 'Syd: [thinking...]' + chr(10))} chars")

    def log_to_chat(self, message):
        def _update():
            self.txt_log.insert(tk.END, f"{message}\n")
            self.txt_log.see(tk.END)
        try:
            self.after(0, _update)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _copy_tab(self, label):
        tab_map = {
            "Overview": self.txt_overview, "Threats & IOCs": self.txt_threats,
            "C2 / Beaconing": self.txt_c2, "Lateral Movement": self.txt_lateral,
            "Credentials": self.txt_creds, "DNS Analysis": self.txt_dns,
            "Exfiltration": self.txt_exfil, "MITRE ATT&CK": self.txt_mitre,
        }
        txt = tab_map.get(label)
        if txt:
            content = txt.get("1.0", "end").strip()
            self.clipboard_clear()
            self.clipboard_append(content)

    def _clear_all(self):
        for txt in (self.txt_overview, self.txt_threats, self.txt_c2, self.txt_lateral,
                    self.txt_creds, self.txt_dns, self.txt_exfil, self.txt_mitre):
            txt.delete("1.0", "end")
        self.txt_chat.delete("1.0", "end")
        self.txt_log.delete("1.0", "end")
        self.facts = None
        self.facts_text = None
        self._pcap_path = None
        self.lbl_file.configure(text="No file loaded")
        self.lbl_status.configure(text="Load a PCAP file to begin analysis")
        self.log_to_chat("[INFO] Cleared. Load a new PCAP file to begin.")


# ---------------------------- YARA Page ----------------------------
class YaraPage(ttk.Frame):
    """YARA Malware Detection and Threat Hunting Interface"""

    def __init__(self, parent):
        super().__init__(parent)

        # State
        self.yara_path = tk.StringVar()
        self.current_analysis = None
        self.current_facts = None
        self.current_facts_text = None

        # RAG components for YARA
        self.embed_model = None
        self.llm = None
        self.faiss_index = None
        self.chunks = None
        self.rag_ready = False

        # Layout: Two columns (Left: Tool, Right: Ask Syd Panel)
        main_paned = ttk.PanedWindow(self, orient="horizontal")
        main_paned.pack(fill="both", expand=True)

        left_frame = ttk.Frame(main_paned)
        right_frame = ttk.Frame(main_paned)
        main_paned.add(left_frame, weight=3)
        main_paned.add(right_frame, weight=2)
        right_frame.configure(width=500)

        # ========== LEFT COLUMN: Controls & Results ==========
        controls_frame = ttk.Frame(left_frame)
        controls_frame.pack(fill="x", padx=5, pady=5)

        ttk.Label(controls_frame, text="YARA - Threat Detection", style="Header.TLabel").pack(anchor="w", pady=(0,10))

        # File selector
        file_frame = ttk.Frame(controls_frame)
        file_frame.pack(fill="x", pady=(0,8))
        ttk.Label(file_frame, text="YARA Output:").pack(side="left", padx=5)
        file_entry = ttk.Entry(file_frame, textvariable=self.yara_path, width=35)
        file_entry.pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(file_frame, text="Browse", command=self._browse_file).pack(side="left", padx=2)
        ttk.Button(file_frame, text="Analyze", command=self._analyze_file).pack(side="left")

        # Status label
        self.lbl_status = ttk.Label(controls_frame, text="YARA analyzer ready", foreground=INK_SOFT)
        self.lbl_status.pack(side="left", padx=5, pady=5)

        # Tabbed results area
        results_frame = ttk.Frame(left_frame)
        results_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.tabs_results = ttk.Notebook(results_frame)
        self.tabs_results.pack(fill="both", expand=True)

        # Tab 1: Raw Output
        tab_raw = ttk.Frame(self.tabs_results)
        self.tabs_results.add(tab_raw, text="Raw Output")

        self.txt_raw = tk.Text(tab_raw, bg=BG_DARK, fg=INK, wrap="word", state="normal")
        raw_scroll = ttk.Scrollbar(tab_raw, orient="vertical", command=self.txt_raw.yview)
        self.txt_raw.configure(yscrollcommand=raw_scroll.set)
        self.txt_raw.pack(side="left", fill="both", expand=True)
        raw_scroll.pack(side="right", fill="y")
        self._create_context_menu(self.txt_raw)

        # Tab 2: Detected Threats (Treeview)
        tab_threats = ttk.Frame(self.tabs_results)
        self.tabs_results.add(tab_threats, text="Detected Threats")

        # Add "Copy All" button above tree
        threats_header = ttk.Frame(tab_threats)
        threats_header.pack(fill="x", padx=5, pady=5)
        ttk.Button(threats_header, text="Copy All Threats", command=self._copy_all_threats).pack(side="right")

        # Treeview for threats
        threats_tree_frame = ttk.Frame(tab_threats)
        threats_tree_frame.pack(fill="both", expand=True, padx=5, pady=(0,5))

        self.tree_threats = ttk.Treeview(threats_tree_frame, columns=("Rule", "File", "Category", "Severity"), show="tree headings")
        self.tree_threats.heading("#0", text="ID")
        self.tree_threats.heading("Rule", text="Rule Name")
        self.tree_threats.heading("File", text="File Path")
        self.tree_threats.heading("Category", text="Category")
        self.tree_threats.heading("Severity", text="Severity")
        self.tree_threats.column("#0", width=50)
        self.tree_threats.column("Rule", width=180)
        self.tree_threats.column("File", width=200)
        self.tree_threats.column("Category", width=120)
        self.tree_threats.column("Severity", width=80)

        threats_scroll = ttk.Scrollbar(threats_tree_frame, orient="vertical", command=self.tree_threats.yview)
        self.tree_threats.configure(yscrollcommand=threats_scroll.set)
        self.tree_threats.pack(side="left", fill="both", expand=True)
        threats_scroll.pack(side="right", fill="y")

        # Tab 3: Analysis Report
        self.tab_report = ttk.Frame(self.tabs_results)
        self.tabs_results.add(self.tab_report, text="Analysis Report")

        self.txt_report = tk.Text(self.tab_report, bg=BG_DARK, fg=INK, wrap="word", state="normal")
        report_scroll = ttk.Scrollbar(self.tab_report, orient="vertical", command=self.txt_report.yview)
        self.txt_report.configure(yscrollcommand=report_scroll.set)
        self.txt_report.pack(side="left", fill="both", expand=True)
        report_scroll.pack(side="right", fill="y")
        self._create_context_menu(self.txt_report)

        # Tab 4: Next Steps
        tab_next = ttk.Frame(self.tabs_results)
        self.tabs_results.add(tab_next, text="Next Steps")

        self.txt_next = tk.Text(tab_next, bg=BG_DARK, fg=INK, wrap="word", state="normal")
        next_scroll = ttk.Scrollbar(tab_next, orient="vertical", command=self.txt_next.yview)
        self.txt_next.configure(yscrollcommand=next_scroll.set)
        self.txt_next.pack(side="left", fill="both", expand=True)
        next_scroll.pack(side="right", fill="y")
        self._create_context_menu(self.txt_next)

        # Tab 5: Extracted IOCs (Indicators of Compromise)
        tab_iocs = ttk.Frame(self.tabs_results)
        self.tabs_results.add(tab_iocs, text="Extracted IOCs")

        # IOC header with export buttons
        ioc_header = ttk.Frame(tab_iocs)
        ioc_header.pack(fill="x", padx=5, pady=5)
        ttk.Label(ioc_header, text="Indicators of Compromise (IOCs)", style="Header.TLabel").pack(side="left")
        ttk.Button(ioc_header, text="Copy All IOCs", command=self._copy_all_iocs).pack(side="right", padx=2)
        ttk.Button(ioc_header, text="Export CSV", command=self._export_iocs_csv).pack(side="right", padx=2)

        # IOC display area
        self.txt_iocs = tk.Text(tab_iocs, bg=BG_DARK, fg=INK, wrap="word", state="normal")
        ioc_scroll = ttk.Scrollbar(tab_iocs, orient="vertical", command=self.txt_iocs.yview)
        self.txt_iocs.configure(yscrollcommand=ioc_scroll.set)
        self.txt_iocs.pack(side="left", fill="both", expand=True, padx=5, pady=(0,5))
        ioc_scroll.pack(side="right", fill="y")
        self._create_context_menu(self.txt_iocs)

        # Tab 6: Paste Results
        tab_paste = ttk.Frame(self.tabs_results)
        self.tabs_results.add(tab_paste, text="Paste Results")

        paste_header = ttk.Frame(tab_paste)
        paste_header.pack(fill="x", padx=5, pady=5)
        ttk.Label(paste_header, text="Paste YARA output (JSON, raw, or rules):", style="Header.TLabel").pack(side="left")
        ttk.Button(paste_header, text="Analyze Pasted", command=self._analyze_paste).pack(side="right", padx=5)

        self.txt_paste = tk.Text(tab_paste, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word")
        paste_scroll = ttk.Scrollbar(tab_paste, orient="vertical", command=self.txt_paste.yview)
        self.txt_paste.configure(yscrollcommand=paste_scroll.set)
        self.txt_paste.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        paste_scroll.pack(side="right", fill="y")
        self._create_context_menu(self.txt_paste)

        # ========== RIGHT COLUMN (Ask Syd Panel) ==========
        # Header bar
        header = ttk.Frame(right_frame)
        header.pack(fill="x", padx=5, pady=5)

        title_row = ttk.Frame(header)
        title_row.pack(fill="x")
        ttk.Label(title_row, text="Ask Syd - YARA Expert", style="Header.TLabel").pack(side="left")
        badge = ttk.Label(title_row, text="Fresh Context", background=ACCENT, foreground="#fff", padding=(5,2))
        badge.pack(side="left", padx=10)

        controls_row = ttk.Frame(header)
        controls_row.pack(fill="x", pady=(5,0))
        ttk.Label(controls_row, text="Tool:").pack(side="left", padx=5)
        self.cmb_tool = ttk.Combobox(controls_row, values=["YARA"], state="readonly", width=12)
        self.cmb_tool.current(0)
        self.cmb_tool.pack(side="left", padx=5)

        source_row = ttk.Frame(header)
        source_row.pack(fill="x", pady=(5,0))
        ttk.Label(source_row, text="Source:").pack(side="left", padx=5)
        self.var_source = tk.StringVar(value="Syd")
        ttk.Radiobutton(source_row, text="Syd", variable=self.var_source, value="Syd").pack(side="left", padx=5)
        ttk.Radiobutton(source_row, text="Customer", variable=self.var_source, value="Customer").pack(side="left", padx=5)

        # Main chat region
        chat_frame = ttk.Frame(right_frame)
        chat_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.txt_chat = tk.Text(chat_frame, bg=BG_DARK, fg=INK, insertbackground=INK, wrap="word", height=20)
        scroll_chat = ttk.Scrollbar(chat_frame, command=self.txt_chat.yview)
        self.txt_chat.configure(yscrollcommand=scroll_chat.set)
        self.txt_chat.pack(side="left", fill="both", expand=True)
        scroll_chat.pack(side="right", fill="y")
        self._create_context_menu(self.txt_chat)

        # Lower log panel
        log_frame = ttk.Frame(right_frame)
        log_frame.pack(fill="both", expand=False, padx=5, pady=5)

        self.txt_log = tk.Text(log_frame, bg=BG_DARK, fg=INK_SOFT, insertbackground=INK, wrap="word", height=6)
        scroll_log = ttk.Scrollbar(log_frame, command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=scroll_log.set)
        self.txt_log.pack(side="left", fill="both", expand=True)
        scroll_log.pack(side="right", fill="y")
        self._create_context_menu(self.txt_log)

        # Input field for questions - multiline text widget
        input_frame = ttk.Frame(right_frame)
        input_frame.pack(fill="both", expand=False, padx=5, pady=(5,0))

        self.entry_question = tk.Text(input_frame, height=3, bg=BG_DARK, fg=INK,
                                     insertbackground=INK, wrap="word", font=('Consolas', 10))
        self.entry_question.pack(fill="both", expand=True)
        self.entry_question.bind('<Control-Return>', lambda e: self._send_to_syd())
        self._create_context_menu(self.entry_question)

        # Bottom buttons
        bottom_btns = ttk.Frame(right_frame)
        bottom_btns.pack(fill="x", padx=5, pady=5)
        ttk.Button(bottom_btns, text="Send (Ctrl+Enter)", command=self._send_to_syd).pack(side="left", padx=5)
        ttk.Button(bottom_btns, text="Clear Chat", command=self._clear_chat_and_output).pack(side="left", padx=5)
        ttk.Button(bottom_btns, text="Upload data...", command=self._upload_data).pack(side="left", padx=5)

        # Log initial message
        self.log_to_asksyd("[INFO] YARA analyzer ready")
        self.log_to_asksyd("[INFO] Load a YARA output file or paste results to analyze")

        # Initialize RAG in background
        import threading
        threading.Thread(target=self._initialize_rag, daemon=True).start()

    def _initialize_rag(self):
        """Initialize YARA RAG system: Load FAISS + LLM"""
        try:
            self.log_to_asksyd("[LOADING] Loading YARA knowledge base...")

            # 1. Load embedding model using safe loader
            self.embed_model = load_embedding_model("all-MiniLM-L6-v2")
            self.log_to_asksyd("[OK] Embedding model loaded on cpu")

            # 2. Load YARA FAISS index
            faiss_path = BASE_PATH / "rag_engine" / "embeddings" / "customers" / "customer_syd_yara_knowledge.faiss"
            pkl_path = BASE_PATH / "rag_engine" / "embeddings" / "customers" / "customer_syd_yara_knowledge.pkl"

            if not faiss_path.exists() or not pkl_path.exists():
                self.log_to_asksyd("[ERROR] YARA knowledge files not found!")
                self.log_to_asksyd("[INFO] Run: python chunk_and_embed_yara.py")
                return

            self.faiss_index = faiss.read_index(str(faiss_path))
            with open(pkl_path, 'rb') as f:
                self.chunks = pickle.load(f)
            self.log_to_asksyd(f"[OK] Loaded {len(self.chunks)} YARA knowledge chunks from database")

            # 3. Get shared LLM (single instance for all tools)
            self.llm = get_shared_llm()
            self.log_to_asksyd("[OK] Using shared LLM (Qwen 2.5 14B)")

            # 4. Initialize YARA fact extractor
            from yara_fact_extractor import YaraFactExtractor
            self.fact_extractor = YaraFactExtractor()
            self.log_to_asksyd("[OK] YARA fact extractor ready (comprehensive pattern extraction)")

            self.rag_ready = True
            self.log_to_asksyd("[SUCCESS] Ask Syd ready! Ask me about YARA rules, malware detection, threat hunting, etc.")

        except Exception as e:
            self.log_to_asksyd("[WARNING] Ask Syd knowledge base could not load. Ensure 'hf_home' folder is present.")
            import traceback
            traceback.print_exc()

    def _browse_file(self):
        """Browse for YARA output file"""
        filename = filedialog.askopenfilename(
            title="Select YARA Output",
            filetypes=[
                ("YARA Files", "*.json *.txt *.yar *.yara"),
                ("JSON files", "*.json"),
                ("Text files", "*.txt"),
                ("YARA rules", "*.yar *.yara"),
                ("All files", "*.*")
            ]
        )

        if filename:
            self.yara_path.set(filename)

    def _analyze_file(self):
        """Analyze YARA output file"""
        filepath = self.yara_path.get().strip()

        if not filepath:
            messagebox.showwarning("No File", "Please select a YARA output file")
            return

        self.lbl_status.configure(text="Analyzing...")
        self.txt_raw.delete("1.0", "end")
        self.tree_threats.delete(*self.tree_threats.get_children())
        self.txt_report.delete("1.0", "end")
        self.txt_next.delete("1.0", "end")
        self.txt_iocs.delete("1.0", "end")

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                yara_data = f.read()

            self.txt_raw.insert("1.0", yara_data)
            self._process_yara_data(yara_data)

        except Exception as e:
            import traceback
            error_msg = f"Error analyzing file:\n{str(e)}\n\n{traceback.format_exc()}"
            self.txt_report.delete("1.0", "end")
            self.txt_report.insert("1.0", error_msg)
            self.lbl_status.configure(text="Analysis failed")
            self.log_to_asksyd(f"[ERROR] {str(e)}")

    def _analyze_paste(self):
        """Analyze pasted YARA output"""
        pasted = self.txt_paste.get("1.0", "end").strip()

        if not pasted:
            messagebox.showwarning("No Input", "Please paste YARA output first")
            return

        self.lbl_status.configure(text="Analyzing...")
        self.txt_raw.delete("1.0", "end")
        self.tree_threats.delete(*self.tree_threats.get_children())
        self.txt_report.delete("1.0", "end")
        self.txt_next.delete("1.0", "end")
        self.txt_iocs.delete("1.0", "end")

        try:
            self.txt_raw.insert("1.0", pasted)
            self._process_yara_data(pasted)

        except Exception as e:
            import traceback
            error_msg = f"Error analyzing pasted content:\n{str(e)}\n\n{traceback.format_exc()}"
            self.txt_report.delete("1.0", "end")
            self.txt_report.insert("1.0", error_msg)
            self.lbl_status.configure(text="Analysis failed")
            self.log_to_asksyd(f"[ERROR] {str(e)}")

    def _process_yara_data(self, yara_data):
        """Process YARA data and update all displays"""
        from yara_analyzer import YaraAnalyzer, format_analysis_report

        analyzer = YaraAnalyzer()
        result = analyzer.analyze_yara_output(yara_data)
        self.current_analysis = result

        # Extract facts
        if hasattr(self, 'fact_extractor'):
            try:
                self.current_facts = self.fact_extractor.extract_facts(yara_data)
                # Use comprehensive facts_to_text() method (includes all metadata, strings, scan_info)
                self.current_facts_text = self.fact_extractor.facts_to_text(self.current_facts)
                self.log_to_asksyd(f"[OK] Extracted {len(self.current_facts.get('matches', []))} matches, "
                                  f"{len(self.current_facts.get('qa_pairs', []))} Q&A pairs, "
                                  f"{self.current_facts.get('scan_metadata', {}).get('rules_loaded', 'N/A')} rules loaded")
            except Exception as e:
                self.log_to_asksyd(f"[WARNING] Fact extraction failed: {e}")
                import traceback
                traceback.print_exc()
                self.current_facts = None
                self.current_facts_text = None

        # Populate threats tree
        threats = result.get('threat_analysis', {}).get('threats', [])
        for idx, threat in enumerate(threats, 1):
            self.tree_threats.insert("", "end", text=str(idx), values=(
                threat.get('rule_matched', threat.get('rule', 'Unknown')),
                threat.get('file', 'N/A'),
                threat.get('category', 'Unknown'),
                threat.get('severity', 'Unknown')
            ))

        # Display analysis report
        report = format_analysis_report(result)
        self.txt_report.delete("1.0", "end")
        self.txt_report.insert("1.0", report)

        # Display next steps
        next_steps = result.get('next_steps', [])
        self.txt_next.delete("1.0", "end")
        if next_steps:
            self.txt_next.insert("1.0", "RECOMMENDED NEXT STEPS\n" + "="*50 + "\n\n")
            for i, step in enumerate(next_steps, 1):
                self.txt_next.insert("end", f"{i}. {step}\n\n")
        else:
            self.txt_next.insert("1.0", "No threats detected - no immediate action required.\n\n"
                                       "Consider:\n- Expanding YARA rule coverage\n- Scanning additional directories\n- Updating threat intelligence")

        # Display extracted IOCs
        self._display_iocs()

        # Switch to Analysis Report tab
        self.tabs_results.select(self.tab_report)

        self.lbl_status.configure(text="Analysis complete")
        self.log_to_asksyd(f"[SUCCESS] Analysis complete! Detected {len(threats)} threats")

    def _clear_chat_and_output(self):
        """Clear all chat and output screens"""
        self.txt_chat.delete('1.0', tk.END)
        self.entry_question.delete('1.0', tk.END)
        self.txt_raw.delete('1.0', tk.END)
        for item in self.tree_threats.get_children():
            self.tree_threats.delete(item)
        self.txt_report.delete('1.0', tk.END)
        self.txt_next.delete('1.0', tk.END)
        self.txt_iocs.delete('1.0', tk.END)
        self.txt_log.delete('1.0', tk.END)
        self.current_facts = None
        self.current_facts_text = None
        self.current_analysis = None
        self.log_to_asksyd("[INFO] Chat and output cleared")

    def _copy_all_threats(self):
        """Copy all detected threats from Treeview to clipboard in tab-separated format"""
        try:
            # Get all items from the tree
            items = self.tree_threats.get_children()

            if not items:
                self.log_to_asksyd("[INFO] No threats to copy")
                return

            # Build tab-separated output with headers
            output = "ID\tRule Name\tFile Path\tCategory\tSeverity\n"
            output += "="*80 + "\n"

            for item in items:
                # Get values: item text is ID, values are (Rule, File, Category, Severity)
                item_id = self.tree_threats.item(item, 'text')
                values = self.tree_threats.item(item, 'values')

                # Format as tab-separated line
                line = f"{item_id}\t{values[0]}\t{values[1]}\t{values[2]}\t{values[3]}\n"
                output += line

            # Copy to clipboard
            self.clipboard_clear()
            self.clipboard_append(output)
            self.update()  # Required for clipboard to work

            self.log_to_asksyd(f"[SUCCESS] Copied {len(items)} threats to clipboard")

        except Exception as e:
            self.log_to_asksyd(f"[ERROR] Failed to copy threats: {e}")

    def _display_iocs(self):
        """Display extracted IOCs in the IOCs tab"""
        try:
            self.txt_iocs.delete("1.0", "end")

            if not self.current_facts:
                self.txt_iocs.insert("1.0", "No facts extracted. Run analysis first.\n")
                return

            iocs = self.current_facts.get('iocs', {})
            if not iocs:
                self.txt_iocs.insert("1.0", "No IOCs extracted.\n")
                return

            # Count total IOCs
            total_iocs = sum(len(v) for v in iocs.values() if v)

            if total_iocs == 0:
                self.txt_iocs.insert("1.0", "No IOCs found in this scan.\n\n"
                                           "This could mean:\n"
                                           "- Clean scan with no malicious indicators\n"
                                           "- Rules focused on behavioral patterns rather than specific IOCs\n"
                                           "- Matched strings don't contain extractable indicators\n")
                return

            # Display header
            header = "="*80 + "\n"
            header += "EXTRACTED INDICATORS OF COMPROMISE (IOCs)\n"
            header += "="*80 + "\n"
            header += f"Total IOCs Extracted: {total_iocs}\n"
            header += "="*80 + "\n\n"
            self.txt_iocs.insert("end", header)

            # Display each IOC category
            if iocs.get('ip_addresses'):
                self.txt_iocs.insert("end", f"IP ADDRESSES ({len(iocs['ip_addresses'])}):\n")
                self.txt_iocs.insert("end", "-"*40 + "\n")
                for ip in iocs['ip_addresses']:
                    self.txt_iocs.insert("end", f"  {ip}\n")
                self.txt_iocs.insert("end", "\n")

            if iocs.get('domains'):
                self.txt_iocs.insert("end", f"DOMAINS ({len(iocs['domains'])}):\n")
                self.txt_iocs.insert("end", "-"*40 + "\n")
                for domain in iocs['domains']:
                    self.txt_iocs.insert("end", f"  {domain}\n")
                self.txt_iocs.insert("end", "\n")

            if iocs.get('urls'):
                self.txt_iocs.insert("end", f"URLs ({len(iocs['urls'])}):\n")
                self.txt_iocs.insert("end", "-"*40 + "\n")
                for url in iocs['urls']:
                    self.txt_iocs.insert("end", f"  {url}\n")
                self.txt_iocs.insert("end", "\n")

            if iocs.get('mutexes'):
                self.txt_iocs.insert("end", f"MUTEXES ({len(iocs['mutexes'])}):\n")
                self.txt_iocs.insert("end", "-"*40 + "\n")
                for mutex in iocs['mutexes']:
                    self.txt_iocs.insert("end", f"  {mutex}\n")
                self.txt_iocs.insert("end", "\n")

            if iocs.get('named_pipes'):
                self.txt_iocs.insert("end", f"NAMED PIPES ({len(iocs['named_pipes'])}):\n")
                self.txt_iocs.insert("end", "-"*40 + "\n")
                for pipe in iocs['named_pipes']:
                    self.txt_iocs.insert("end", f"  {pipe}\n")
                self.txt_iocs.insert("end", "\n")

            if iocs.get('file_extensions'):
                self.txt_iocs.insert("end", f"FILE EXTENSIONS ({len(iocs['file_extensions'])}):\n")
                self.txt_iocs.insert("end", "-"*40 + "\n")
                for ext in iocs['file_extensions']:
                    self.txt_iocs.insert("end", f"  {ext}\n")
                self.txt_iocs.insert("end", "\n")

            if iocs.get('registry_keys'):
                self.txt_iocs.insert("end", f"REGISTRY KEYS ({len(iocs['registry_keys'])}):\n")
                self.txt_iocs.insert("end", "-"*40 + "\n")
                for key in iocs['registry_keys']:
                    self.txt_iocs.insert("end", f"  {key}\n")
                self.txt_iocs.insert("end", "\n")

            if iocs.get('commands'):
                self.txt_iocs.insert("end", f"SYSTEM COMMANDS ({len(iocs['commands'])}):\n")
                self.txt_iocs.insert("end", "-"*40 + "\n")
                for cmd in iocs['commands']:
                    self.txt_iocs.insert("end", f"  {cmd}\n")
                self.txt_iocs.insert("end", "\n")

            if iocs.get('crypto_addresses'):
                self.txt_iocs.insert("end", f"CRYPTOCURRENCY ADDRESSES ({len(iocs['crypto_addresses'])}):\n")
                self.txt_iocs.insert("end", "-"*40 + "\n")
                for crypto in iocs['crypto_addresses']:
                    self.txt_iocs.insert("end", f"  {crypto}\n")
                self.txt_iocs.insert("end", "\n")

            if iocs.get('file_paths'):
                self.txt_iocs.insert("end", f"FILE PATHS ({len(iocs['file_paths'])}):\n")
                self.txt_iocs.insert("end", "-"*40 + "\n")
                for path in iocs['file_paths']:
                    self.txt_iocs.insert("end", f"  {path}\n")
                self.txt_iocs.insert("end", "\n")

            # Add usage notes
            self.txt_iocs.insert("end", "="*80 + "\n")
            self.txt_iocs.insert("end", "USAGE NOTES:\n")
            self.txt_iocs.insert("end", "="*80 + "\n")
            self.txt_iocs.insert("end", "- Use 'Copy All IOCs' to copy to clipboard\n")
            self.txt_iocs.insert("end", "- Use 'Export CSV' to save as structured CSV file\n")
            self.txt_iocs.insert("end", "- Feed IOCs to SIEM, firewall, EDR for blocking/hunting\n")
            self.txt_iocs.insert("end", "- Cross-reference with threat intelligence platforms\n")

            self.log_to_asksyd(f"[SUCCESS] Extracted {total_iocs} IOCs across {sum(1 for v in iocs.values() if v)} categories")

        except Exception as e:
            import traceback
            error_msg = f"Error displaying IOCs:\n{str(e)}\n{traceback.format_exc()}"
            self.txt_iocs.delete("1.0", "end")
            self.txt_iocs.insert("1.0", error_msg)
            self.log_to_asksyd(f"[ERROR] Failed to display IOCs: {e}")

    def _copy_all_iocs(self):
        """Copy all extracted IOCs to clipboard"""
        try:
            if not self.current_facts:
                self.log_to_asksyd("[INFO] No facts extracted. Run analysis first.")
                return

            iocs = self.current_facts.get('iocs', {})
            if not iocs:
                self.log_to_asksyd("[INFO] No IOCs to copy")
                return

            # Build text output
            output = []
            output.append("="*80)
            output.append("EXTRACTED INDICATORS OF COMPROMISE (IOCs)")
            output.append("="*80)
            output.append("")

            categories = [
                ('ip_addresses', 'IP ADDRESSES'),
                ('domains', 'DOMAINS'),
                ('urls', 'URLs'),
                ('mutexes', 'MUTEXES'),
                ('named_pipes', 'NAMED PIPES'),
                ('file_extensions', 'FILE EXTENSIONS'),
                ('registry_keys', 'REGISTRY KEYS'),
                ('commands', 'SYSTEM COMMANDS'),
                ('crypto_addresses', 'CRYPTOCURRENCY ADDRESSES'),
                ('file_paths', 'FILE PATHS')
            ]

            total = 0
            for key, label in categories:
                values = iocs.get(key, [])
                if values:
                    output.append(f"{label} ({len(values)}):")
                    output.append("-"*40)
                    for val in values:
                        output.append(f"  {val}")
                    output.append("")
                    total += len(values)

            output.append(f"Total IOCs: {total}")

            # Copy to clipboard
            text = "\n".join(output)
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()

            self.log_to_asksyd(f"[SUCCESS] Copied {total} IOCs to clipboard")

        except Exception as e:
            self.log_to_asksyd(f"[ERROR] Failed to copy IOCs: {e}")

    def _export_iocs_csv(self):
        """Export IOCs to CSV file"""
        try:
            if not self.current_facts:
                messagebox.showwarning("No Data", "No facts extracted. Run analysis first.")
                return

            iocs = self.current_facts.get('iocs', {})
            if not iocs or sum(len(v) for v in iocs.values()) == 0:
                messagebox.showwarning("No IOCs", "No IOCs to export")
                return

            # Ask user for save location
            from tkinter import filedialog
            filepath = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                title="Export IOCs to CSV"
            )

            if not filepath:
                return

            # Write CSV
            import csv
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Category', 'Value'])

                categories = [
                    ('ip_addresses', 'IP Address'),
                    ('domains', 'Domain'),
                    ('urls', 'URL'),
                    ('mutexes', 'Mutex'),
                    ('named_pipes', 'Named Pipe'),
                    ('file_extensions', 'File Extension'),
                    ('registry_keys', 'Registry Key'),
                    ('commands', 'System Command'),
                    ('crypto_addresses', 'Cryptocurrency Address'),
                    ('file_paths', 'File Path')
                ]

                total = 0
                for key, label in categories:
                    values = iocs.get(key, [])
                    for val in values:
                        writer.writerow([label, val])
                        total += 1

            self.log_to_asksyd(f"[SUCCESS] Exported {total} IOCs to {filepath}")
            messagebox.showinfo("Export Complete", f"Exported {total} IOCs to:\n{filepath}")

        except Exception as e:
            import traceback
            error_msg = f"Failed to export IOCs:\n{str(e)}\n{traceback.format_exc()}"
            self.log_to_asksyd(f"[ERROR] {error_msg}")
            messagebox.showerror("Export Failed", error_msg)

    def log_to_asksyd(self, message):
        """Log messages to Ask Syd log panel (thread-safe)"""
        def _update():
            self.txt_log.insert(tk.END, f"{message}\n")
            self.txt_log.see(tk.END)

        try:
            self.after(0, _update)
        except:
            pass

    def _send_to_syd(self):
        """Handle Send button - query YARA RAG system"""
        if not self.rag_ready:
            messagebox.showwarning("Ask Syd", "Still loading knowledge base, please wait...")
            return

        question = self.entry_question.get("1.0", "end").strip()
        if not question:
            return

        self.entry_question.delete("1.0", "end")
        self.append_chat_message("YOU", question)

        self.show_thinking_indicator()

        def query_rag():
            try:
                # Get knowledge base context
                query_vec = self.embed_model.encode([question]).astype('float32')
                faiss.normalize_L2(query_vec)
                distances, indices = self.faiss_index.search(query_vec, 3)

                contexts = []
                for idx in indices[0]:
                    if idx < len(self.chunks):
                        chunk = self.chunks[idx]
                        text = chunk.get('content', str(chunk))
                        contexts.append(text)
                context_text = "\n\n".join(contexts)

                # Build prompt based on whether we have YARA data
                if self.current_facts_text:
                    # Truncate facts and context to fit within context window
                    facts_for_prompt, context_for_prompt = truncate_for_context_window(
                        self.llm, self.current_facts_text, context_text,
                        max_tokens=1536, static_prompt_chars=1500
                    )

                    system_prompt = f"""You are Syd, an expert malware analyst and threat hunter specializing in YARA rules and detection.

ANSWERING STRATEGY:

1. YARA SCAN RESULTS (Facts-First - NEVER Invent):
   - For detected threats, rules, files: Use ONLY the facts below
   - NEVER invent: rule names, file paths, threat categories, severity levels
   - If not in facts, say "Not present in this YARA scan"

2. INFERENCE FROM EVIDENCE (Connect the Dots):
   - Multiple ransomware detections = potential active infection
   - C2 framework detection = network compromise
   - Credential stealer + banking trojan = financial fraud risk
   - Use phrases like: "Based on the detections..." or "This indicates..."

3. GENERAL YARA/MALWARE KNOWLEDGE (Explain Concepts):
   - How specific malware families work
   - YARA rule writing techniques
   - Incident response procedures
   - Use phrases like: "This malware family..." or "YARA rules detect this by..."

CRITICAL RULES:
   - If the user asks about a specific CVE by number, you may discuss it - explain the vulnerability and exploitation approach.
   - Do NOT invent additional CVE numbers on your own. Describe vulnerability classes by name without guessing CVE numbers.
   - When discussing exploits or malware, focus on the TECHNIQUE rather than guessing CVE numbers.

FACTS FROM THIS YARA SCAN:
{facts_for_prompt}

KNOWLEDGE BASE (for general YARA/malware concepts):
{context_for_prompt}

RESPONSE FORMAT:
- Start with facts from the scan
- Add inferences based on evidence
- Include general knowledge if helpful
- Always distinguish: Facts vs Inference vs General knowledge"""
                else:
                    system_prompt = f"""You are Syd, an expert malware analyst and threat hunter specializing in YARA rules, detection, and exploit analysis.

The user has asked a general question without providing YARA scan data. Answer their question using your knowledge of YARA, malware analysis, threat hunting, and exploitation techniques.

KNOWLEDGE BASE:
{context_text}

RESPONSE GUIDELINES:
- Provide clear, practical explanations
- Include YARA rule examples when helpful
- Mention relevant MITRE ATT&CK techniques
- If asked about exploits, provide guidance on malware analysis, reverse engineering, and proof-of-concept development for authorized security testing
- If asked about writing YARA rules, provide complete working rule examples
- Keep answers concise but informative
- If the question requires YARA scan data to answer, politely explain that and ask them to provide YARA output"""

                user_message = f"Question: {question}"

                response = self.llm.create_chat_completion(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ],
                    max_tokens=1536,
                    temperature=0.2,
                    top_p=0.9,
                    stop=["Question:", "Q:"]
                )
                answer = response['choices'][0]['message']['content'].strip()
                answer = tag_unverified_cves(answer)

                # Validate answer against facts if we have YARA scan data
                if self.current_facts:
                    validation_result = self._validate_answer_against_facts(answer, self.current_facts)

                    if not validation_result['valid']:
                        # Warn about potential hallucination but show full answer
                        warning = f"[WARNING - POSSIBLE HALLUCINATION]\n\n"
                        warning += f"Syd's answer may contain information not confirmed in the YARA scan:\n"
                        for issue in validation_result['issues']:
                            warning += f"  - {issue}\n"
                        warning += f"\nPlease verify the following answer against your analysis results:\n"
                        warning += f"{'=' * 50}\n\n"
                        answer = warning + answer

                self.after(0, lambda: self.remove_thinking_indicator())
                self.after(0, lambda: self.append_chat_message("SYD", answer))

            except Exception as e:
                error_msg = f"Error processing question: {str(e)}"
                self.log_to_asksyd(f"[ERROR] {error_msg}")
                self.after(0, lambda: self.remove_thinking_indicator())
                self.after(0, lambda: self.append_chat_message("SYSTEM", error_msg))

        import threading
        threading.Thread(target=query_rag, daemon=True).start()

    def _upload_data(self):
        """Upload a file to the chat (for context)"""
        filepath = filedialog.askopenfilename(
            title="Select file to upload",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("YARA rules", "*.yar *.yara"), ("All files", "*.*")]
        )

        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                self.txt_chat.insert(tk.END, f"\n[UPLOADED: {os.path.basename(filepath)}]\n")
                self.txt_chat.insert(tk.END, content[:5000])
                if len(content) > 5000:
                    self.txt_chat.insert(tk.END, "\n\n[... truncated ...]")
                self.txt_chat.see(tk.END)

            except Exception as e:
                messagebox.showerror("Upload Error", str(e))

    def show_thinking_indicator(self):
        """Show 'Syd is thinking...' with animated dots"""
        self.thinking_start = self.txt_chat.index(tk.END)
        self.txt_chat.insert(tk.END, f"\n{'='*60}\n")
        self.txt_chat.insert(tk.END, "[SYD]\n")
        self.thinking_text_start = self.txt_chat.index(tk.END)
        self.txt_chat.insert(tk.END, "Thinking.\n")
        self.txt_chat.see(tk.END)
        self.thinking_dots = 1
        self.thinking_active = True
        self.animate_thinking()

    def animate_thinking(self):
        """Animate the thinking dots"""
        if not hasattr(self, 'thinking_active') or not self.thinking_active:
            return
        dots = "." * self.thinking_dots
        self.thinking_dots = (self.thinking_dots % 3) + 1
        try:
            self.txt_chat.delete(self.thinking_text_start, f"{self.thinking_text_start} lineend")
            self.txt_chat.insert(self.thinking_text_start, f"Thinking{dots}")
            self.txt_chat.see(tk.END)
        except:
            pass
        if self.thinking_active:
            self.after(500, self.animate_thinking)

    def remove_thinking_indicator(self):
        """Remove the 'Syd is thinking...' message"""
        self.thinking_active = False
        try:
            if hasattr(self, 'thinking_start'):
                self.txt_chat.delete(self.thinking_start, tk.END)
        except:
            pass

    def _validate_answer_against_facts(self, answer, facts):
        """Validate answer against extracted YARA facts to prevent hallucinations"""
        import re

        issues = []

        if not facts or not self.current_facts:
            return {'valid': True, 'issues': []}

        # Extract rule names mentioned in answer (YARA rules often have underscores/capitals)
        # Match patterns like: rule_name, RuleName, RULE_NAME
        answer_lower = answer.lower()

        # Get valid rule names from facts
        valid_rules = set()
        for rule in facts.get('rules_triggered', []):
            valid_rules.add(rule.lower())

        # Check for common rule patterns mentioned
        # Look for capitalized words or underscore-separated identifiers that might be rule names
        potential_rules = re.findall(r'\b[A-Z][a-z]*(?:_[A-Z][a-z]*)*\b', answer)
        potential_rules.extend(re.findall(r'\b[a-z]+(?:_[a-z]+)+\b', answer))

        for potential_rule in potential_rules:
            # Skip common words that aren't rules
            if potential_rule.lower() in ['yara', 'rule', 'scan', 'file', 'threat', 'malware', 'detection']:
                continue

            # Skip if it's part of a file path (contains file extensions or path separators nearby)
            if re.search(rf'{re.escape(potential_rule)}\.(?:exe|dll|sys|tmp|log|php|asp|jsp|bat|ps1|sh)', answer, re.IGNORECASE):
                continue  # It's a filename, not a rule
            if re.search(rf'[/\\]{re.escape(potential_rule)}', answer):
                continue  # It's in a path, not a rule

            # Skip if it's a string identifier (preceded by $ or mentioned as $identifier)
            if re.search(rf'\${re.escape(potential_rule)}', answer):
                continue  # It's a YARA string identifier, not a rule

            # Skip if it's a substring of a valid rule name (e.g., "Cobalt" in "CobaltStrike_Beacon")
            if any(potential_rule.lower() in valid_rule for valid_rule in valid_rules):
                continue  # It's part of a real rule name, not a fake rule

            # If it looks like a rule name and isn't in our valid rules, flag it
            if len(potential_rule) > 4 and potential_rule.lower() not in valid_rules:
                if any(keyword in potential_rule.lower() for keyword in ['ransom', 'trojan', 'apt', 'malware', 'beacon', 'cobalt']):
                    issues.append(f"Mentioned rule '{potential_rule}' not in YARA scan results")

        # Check file paths mentioned
        valid_files = set(facts.get('files_scanned', []))
        # Match Windows/Linux paths
        mentioned_paths = re.findall(r'[A-Za-z]:\\[^\s]+|/[^\s]+', answer)
        for path in mentioned_paths:
            # Skip protocol syntax (://, //, tcp://, ldap://, etc.)
            if path in ['//', '://', 'tcp://', 'ldap://', 'http://', 'https://', 'ftp://', 'stratum+tcp://']:
                continue
            # Skip command-line flags (/all, /quiet, /force, etc.)
            if path.startswith('/') and len(path) < 15 and ' ' not in path:
                continue  # Likely a command flag, not a file path
            # Skip if path is likely complete but contains spaces (full path like "Program Files")
            # The regex splits at spaces, so paths with spaces get fragmented
            # If a path fragment ends mid-word or is very short, it's likely part of a longer path
            if ' ' in answer and len(path) < 30:
                # Check if this path fragment appears within a longer path in the answer
                # Look for the path fragment within quotes or followed by more path components
                context = answer[max(0, answer.find(path)-50):answer.find(path)+len(path)+50]
                if ' ' in context:
                    # Likely part of a path with spaces, skip validation
                    continue

            if path not in valid_files and not any(vf in path for vf in valid_files):
                issues.append(f"Mentioned file path '{path}' not in scanned files")

        # Check threat categories if mentioned
        threat_keywords = ['critical', 'high', 'medium', 'low', 'ransomware', 'trojan', 'apt', 'c2', 'backdoor']
        mentioned_threats = [kw for kw in threat_keywords if kw in answer_lower]

        if mentioned_threats and facts.get('threat_intelligence'):
            # If threats are mentioned, make sure we actually detected some
            if not facts.get('matches'):
                issues.append("Mentioned threats but no YARA rules matched")

        return {
            'valid': len(issues) == 0,
            'issues': issues
        }

    def append_chat_message(self, sender, message):
        """Append a message to the chat display"""
        self.txt_chat.insert(tk.END, f"\n{'='*60}\n")
        self.txt_chat.insert(tk.END, f"[{sender}]\n")
        self.txt_chat.insert(tk.END, f"{message}\n")
        self.txt_chat.see(tk.END)

    # ========== Context Menu (Right-click) ==========
    def _create_context_menu(self, widget):
        """Add right-click copy/paste menu to Text widget"""
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="Cut", command=lambda: widget.event_generate("<<Cut>>"))
        menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
        menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_separator()
        menu.add_command(label="Select All", command=lambda: widget.tag_add("sel", "1.0", "end"))

        def show_menu(event):
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        widget.bind("<Button-3>", show_menu)  # Right-click


# ---------------------------- License Activation Window ----------------------------
class LicenseWindow(tk.Tk):
    """Shown on first run when no valid activation record exists."""

    def __init__(self):
        super().__init__()
        self.title("Syd – Activation Required")
        self.geometry("520x400")
        self.resizable(False, False)
        self.configure(bg=BG_DARK)
        self.activated = False

        # Centre on screen
        self.update_idletasks()
        x = (self.winfo_screenwidth()  - 520) // 2
        y = (self.winfo_screenheight() - 400) // 2
        self.geometry(f"520x400+{x}+{y}")

        # ── Header ──
        header = tk.Frame(self, bg=ACCENT, height=90)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="Syd", font=("Segoe UI", 30, "bold"),
                 bg=ACCENT, fg="#ffffff").pack(pady=(14, 0))
        tk.Label(header, text="Offline Pentest Assistant",
                 font=("Segoe UI", 10), bg=ACCENT, fg="#d0e0ff").pack()

        # ── Body ──
        body = tk.Frame(self, bg=BG_DARK)
        body.pack(fill="both", expand=True, padx=32, pady=20)

        tk.Label(body, text="License Activation",
                 font=("Segoe UI", 14, "bold"), bg=BG_DARK, fg=INK).pack(pady=(0, 6))

        tk.Label(body,
                 text="Enter your license key below to activate Syd.\n"
                      "Each license may be installed on up to 2 computers.",
                 font=("Segoe UI", 10), bg=BG_DARK, fg=INK_SOFT,
                 justify="left").pack(pady=(0, 14), anchor="w")

        tk.Label(body, text="License Key  (SYD3-XXXX-XXXX-XXXX-XXXX)",
                 font=("Segoe UI", 9), bg=BG_DARK, fg=INK_SOFT).pack(anchor="w")

        self.key_entry = tk.Entry(body, font=("Consolas", 14),
                                  bg=BG, fg=INK, insertbackground=INK,
                                  selectbackground=ACCENT, selectforeground="#ffffff",
                                  relief="flat", bd=8)
        self.key_entry.pack(fill="x", pady=(2, 2), ipady=6)
        self.key_entry.bind("<Return>", lambda _: self.on_activate())
        self.after(100, self.key_entry.focus_set)

        self.error_label = tk.Label(body, text="", font=("Segoe UI", 9),
                                    bg=BG_DARK, fg="#ef4444")
        self.error_label.pack(anchor="w", pady=(0, 14))

        # ── Buttons ──
        btn_row = tk.Frame(body, bg=BG_DARK)
        btn_row.pack(anchor="w")
        tk.Button(btn_row, text="Activate", font=("Segoe UI", 10, "bold"),
                  bg=ACCENT, fg="#ffffff", activebackground=ACCENT_SOFT,
                  activeforeground="#ffffff", relief="flat", bd=0,
                  padx=24, pady=8, cursor="hand2",
                  command=self.on_activate).pack(side="left")
        tk.Button(btn_row, text="Exit", font=("Segoe UI", 10),
                  bg=PANEL, fg=INK_SOFT, activebackground=BG, activeforeground=INK,
                  relief="flat", bd=0, padx=16, pady=8, cursor="hand2",
                  command=self.on_exit).pack(side="left", padx=(8, 0))

        # ── Support footer ──
        tk.Label(body, text="Need a license key?  Contact  info@sydsec.co.uk",
                 font=("Segoe UI", 8), bg=BG_DARK, fg=INK_SOFT).pack(side="bottom", pady=(6, 0))

    # ── callbacks ──
    def on_activate(self):
        key = self.key_entry.get()
        if not key.strip():
            self.error_label.config(text="Please enter your license key.")
            return
        success, msg = activate_license(key)
        if success:
            self.activated = True
            self.destroy()
        else:
            self.error_label.config(text=msg)

    def on_exit(self):
        self.activated = False
        self.destroy()


# ---------------------------- Main Window (Boilerplate) ----------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1450x900")
        init_style(self)
        
        main_notebook = ttk.Notebook(self)
        main_notebook.pack(fill="both", expand=True, padx=8, pady=8)

        # Red Team notebook
        red_notebook = ttk.Notebook(main_notebook)
        for tool in RED_TOOLS:
            if tool == "Nmap":
                page = NmapPage(red_notebook)
            elif tool == "BloodHound":
                page = BloodHoundPage(red_notebook)
            elif tool == "NXC/NetExec":
                page = NXCPage(red_notebook)
            else:
                page = GenericToolPage(red_notebook, tool)
            red_notebook.add(page, text=tool)
        main_notebook.add(red_notebook, text="Red Team")

        # Blue Team notebook
        blue_notebook = ttk.Notebook(main_notebook)
        for tool in BLUE_TOOLS:
            if tool == "Volatility3":
                page = VolatilityPage(blue_notebook)
            elif tool == "YARA":
                page = YaraPage(blue_notebook)
            elif tool == "PCAP Analysis":
                page = PCAPPage(blue_notebook)
            else:
                page = GenericToolPage(blue_notebook, tool)
            blue_notebook.add(page, text=tool)
        main_notebook.add(blue_notebook, text="Blue Team")

        # Utilities notebook
        util_notebook = ttk.Notebook(main_notebook)
        for tool in UTILS:
            page = GenericToolPage(util_notebook, tool)
            util_notebook.add(page, text=tool)
        main_notebook.add(util_notebook, text="Utilities")

if __name__ == "__main__":
    import sys
    import traceback

    def handle_exception(exc_type, exc_value, exc_traceback):
        """Global exception handler to prevent crashes"""
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return

        error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        print(f"UNCAUGHT EXCEPTION:\n{error_msg}", file=sys.stderr)

        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "Syd Error",
                f"An unexpected error occurred:\n\n{exc_type.__name__}: {exc_value}\n\nCheck console for full traceback."
            )
        except:
            pass

    # Set global exception handler
    sys.excepthook = handle_exception

    try:
        # ── License check ──
        is_activated, _ = check_activation()
        if not is_activated:
            license_win = LicenseWindow()
            license_win.mainloop()
            if not license_win.activated:
                sys.exit(0)

        # ── Main application ──
        app = App()
        app.mainloop()
    except Exception as e:
        print(f"FATAL ERROR: {e}", file=sys.stderr)
        traceback.print_exc()
