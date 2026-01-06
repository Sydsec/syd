import os
# Fix PyTorch meta tensor issue - must be set before any torch/transformers imports
os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"
os.environ["TRANSFORMERS_NO_ADVISORY_WARNINGS"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["TORCH_DEVICE_BACKEND_INIT_PRIORITY"] = "cpu"
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"
# CRITICAL: Disable meta device entirely to prevent "Cannot copy out of meta tensor" error
os.environ["TRANSFORMERS_OFFLINE"] = "0"  # Ensure online mode
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
# Force transformers to not use meta device for initialization
os.environ["ACCELERATE_USE_CPU"] = "1"
os.environ["TRANSFORMERS_USE_FAST_TOKENIZER"] = "1"

# Disable lazy module initialization that causes meta tensor issues
import torch
torch.set_default_device('cpu')

# Disable meta device usage in PyTorch
import torch._meta_registrations
torch.set_default_dtype(torch.float32)

# Nuclear option: Monkey-patch torch.empty to never create meta tensors
_original_empty = torch.empty
def patched_empty(*args, **kwargs):
    if 'device' in kwargs and kwargs['device'] == 'meta':
        kwargs['device'] = 'cpu'
    return _original_empty(*args, **kwargs)
torch.empty = patched_empty

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import threading
import re
import json
import ipaddress
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET
import pickle
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
from llama_cpp import Llama

# Helper function to load SentenceTransformer
def load_embedding_model(model_name="all-MiniLM-L6-v2"):
    """Load SentenceTransformer model without meta tensor issues"""
    import torch

    # Strategy 1: Try normal loading WITHOUT device parameter (uses default)
    # This works because we set torch.set_default_device('cpu') at startup
    try:
        # Don't specify device - let it use torch default (cpu)
        import warnings
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore")
            model = SentenceTransformer(model_name)

        model.eval()
        return model
    except RuntimeError as e:
        if "meta tensor" not in str(e).lower() and "copy out of meta" not in str(e).lower():
            raise  # Re-raise if it's not the meta tensor issue

        print(f"[DEBUG] Meta tensor error caught, trying workaround: {e}")

    # Strategy 2: Manual load with state dict manipulation
    try:
        # Load model config only (no weights)
        from transformers import AutoModel, AutoTokenizer

        # This loads the model structure but weights on CPU directly
        model = SentenceTransformer(model_name, device='cpu')

        # Force all parameters to CPU
        for param in model.parameters():
            if param.device.type == 'meta':
                # This shouldn't happen now, but just in case
                param.data = param.data.to('cpu')

        model.eval()
        return model
    except Exception as e:
        print(f"[ERROR] Failed to load embedding model: {e}")
        raise

APP_NAME = "Sydsec"

# ---------------------------- Catalogs ----------------------------
RED_TOOLS = [
    "Nmap","Metasploit","Sliver","BloodHound","CrackMapExec","Impacket",
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

# ---------------------------- Reusable Widgets (Boilerplate) ----------------------------
class ChatBlock(ttk.Frame):
    """A non-functional placeholder for the chat interface."""
    def __init__(self, parent, tool_name=""):
        super().__init__(parent)
        ttk.Label(self, text=f"Chat for {tool_name}", style="Header.TLabel").pack(pady=10)
        text = tk.Text(self, height=10, bg=BG_DARK, fg=INK, state="disabled")
        text.pack(fill="both", expand=True, padx=10, pady=5)
        entry = ttk.Entry(self)
        entry.pack(fill="x", padx=10, pady=5)
        ttk.Button(self, text="Send (Boilerplate)").pack(padx=10, pady=5)

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
        self.config_file = Path("nmap_config.json")
        self.output_dir = Path("output/nmap")
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

        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return {**default_config, **json.load(f)}
            except:
                return default_config
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

            # 2. Load Nmap FAISS index
            faiss_path = Path("rag_engine/embeddings/customers/customer_syd_Nmap.faiss")
            pkl_path = Path("rag_engine/embeddings/customers/customer_syd_Nmap.pkl")

            self.faiss_index = faiss.read_index(str(faiss_path))
            with open(pkl_path, 'rb') as f:
                self.chunks = pickle.load(f)
            self.log_to_asksyd(f"[OK] Loaded {len(self.chunks)} Nmap knowledge chunks")

            # 3. Load LLM - using Qwen 2.5 14B (90% accuracy with new architecture)
            model_path = Path("rag_engine/models/qwen2.5-14b-instruct-q5_k_m.gguf")
            self.llm = Llama(
                model_path=str(model_path),
                n_ctx=8192,
                n_threads=8,
                n_gpu_layers=25,
                chat_format="chatml",
                verbose=False
            )
            self.log_to_asksyd("[OK] Qwen 2.5 14B loaded (90% accuracy)")

            # 4. Initialize fact extractor for deterministic parsing
            from nmap_fact_extractor import NmapFactExtractor
            self.fact_extractor = NmapFactExtractor()
            self.log_to_asksyd("[OK] Fact extractor ready")

            self.rag_ready = True
            self.log_to_asksyd("[SUCCESS] Ask Syd ready! Type your Nmap question.")

        except Exception as e:
            self.log_to_asksyd(f"[WARNING] Failed: {e}")
            import traceback
            traceback.print_exc()

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
        self.current_output_file = self.output_dir / f"scan_{{safe_target}}_{timestamp}.txt"
        self.current_xml_file = self.output_dir / f"scan_{{safe_target}}_{timestamp}.xml"

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
            # Debug: Log the exact command
            self.append_output(f"[DEBUG] Executing: {' '.join(cmd)}\n")
            self.append_output(f"[DEBUG] Command parts: {len(cmd)} arguments\n\n")

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
                self.on_scan_complete()
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
            # Get host address
            address = host.find('address').get('addr')

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
                    # Parse and export as CSV
                    if self.current_xml_file and self.current_xml_file.exists():
                        services = self.parse_xml_results(self.current_xml_file)
                        with open(filepath, 'w') as f:
                            f.write("Host,Hostname,Port,Protocol,Service,Product,Version,Extra Info\n")
                            for svc in services:
                                f.write(f"{svc['host']},{svc['hostname']},{svc['port']},{svc['protocol']},{svc['service']},{svc['product']},{svc['version']},{svc['extra_info']}\n")
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
                self.current_output_file = self.output_dir / f"scan_{{safe_target}}_{timestamp}.txt"
                self.current_xml_file = self.output_dir / f"scan_{{safe_target}}_{timestamp}.xml"

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
                # Get current scan context
                current_scan = self.txtRawOutput.get("1.0", tk.END).strip()

                if not current_scan or len(current_scan) < 50:
                    self.after(0, lambda: self.remove_thinking_indicator())
                    self.after(0, lambda: self.append_chat_message("Syd", "No scan data loaded yet. Please paste an Nmap scan first."))
                    return

                # === STAGE A: DETERMINISTIC FACT EXTRACTION ===
                # Extract facts using deterministic parser (100% accurate)
                facts = self.fact_extractor.extract_facts(current_scan)
                facts_text = self.fact_extractor.facts_to_text(facts)

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
   - Use phrases like: "In penetration testing..." or "Generally..."

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
                    max_tokens=512,
                    temperature=0.1,
                    top_p=0.9,
                    stop=["Question:", "Q:"]
                )
                answer = response['choices'][0]['message']['content'].strip()

                # === STAGE C: VALIDATION LAYER ===
                # Validate answer against extracted facts
                validation_result = self._validate_answer_against_facts(answer, facts)

                if not validation_result['valid']:
                    # Block hallucinated answer
                    original_answer = answer
                    answer = f"[BLOCKED - HALLUCINATION DETECTED]\n\n"
                    answer += f"Syd tried to answer but mentioned information not in the scan:\n"
                    for issue in validation_result['issues']:
                        answer += f"  - {issue}\n"
                    answer += f"\nOriginal (blocked) answer: {original_answer[:200]}..."

                # === OPTIONAL SUGGESTION ENHANCEMENT ===
                # The hybrid prompt should handle most cases, but if strictly "Not present",
                # we can still add targeted guidance for how to get that info
                if answer.strip() == "Not present in the facts" or answer.strip() == "Not present in the facts.":
                    # Only for very terse "Not present" - add how to get the info
                    suggestion_prompt = f"""The user asked: "{question}"

This specific information wasn't in the scan output. Provide a brief (1-2 sentences) suggestion:
- What Nmap flag/script would capture this information?
- OR if it's a general concept, briefly explain it.

Be concise and actionable."""

                    try:
                        suggestion_response = self.llm.create_chat_completion(
                            messages=[
                                {"role": "system", "content": f"You are a helpful Nmap expert. Provide brief, actionable guidance.\n\nKNOWLEDGE BASE:\n{context_text}"},
                                {"role": "user", "content": suggestion_prompt}
                            ],
                            max_tokens=100,
                            temperature=0.3,
                            stop=["Question:", "Q:", "\n\n\n"]
                        )
                        suggestion = suggestion_response['choices'][0]['message']['content'].strip()

                        # Add suggestion to answer with clear labeling
                        answer += f"\n\n💡 How to get this info:\n{suggestion}"
                    except:
                        pass  # If suggestion fails, just show the original answer

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

        # Check IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        mentioned_ips = set(re.findall(ip_pattern, answer))
        valid_ips = set(facts['targets'])

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

            # Populate Services tab
            self.txtServices.delete("1.0", tk.END)
            if services:
                self.txtServices.insert(tk.END, "Host,Hostname,Port,Protocol,Service,Product,Version,Extra Info\n")
                for svc in services:
                    self.txtServices.insert(tk.END, f"{svc['host']},{svc['hostname']},{svc['port']},{svc['protocol']},{svc['service']},{svc['product']},{svc['version']},{svc['extra_info']}\n")
            else:
                self.txtServices.insert(tk.END, "No services detected in pasted text.\n")

            # Generate Next Steps
            self.txtNextSteps.delete("1.0", tk.END)
            if services:
                next_steps = self.generate_next_steps(services)
                self.txtNextSteps.insert(tk.END, next_steps)
            else:
                self.txtNextSteps.insert(tk.END, "Paste valid nmap scan results to get recommendations.\n")

            # Switch to Services tab to show results
            self.tabsResults.select(1)

            messagebox.showinfo("Success", f"Analyzed {len(services)} service(s)")

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
            # Match host line: "Nmap scan report for 10.10.10.1"
            if "Nmap scan report for" in line:
                parts = line.split("Nmap scan report for")[-1].strip().split()
                if len(parts) >= 1:
                    current_hostname = parts[0] if len(parts) > 1 and '(' in line else ""
                    current_host = parts[-1].replace('(', '').replace(')', '')

            # Match service line: "22/tcp   open  ssh     OpenSSH 7.2p2"
            match = re.match(r'(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)', line)
            if match:
                port = match.group(1)
                protocol = match.group(2)
                state = match.group(3)
                service = match.group(4)
                version_info = match.group(5).strip()

                # Parse version info - FIXED to handle "Apache httpd 2.4.52"
                product = ""
                version = ""
                extra = version_info

                # Smarter parsing: Find first version-like string (contains digits and dots)
                parts = version_info.split()
                if len(parts) >= 1:
                    version_idx = -1
                    # Find first part that looks like a version (e.g., "2.4.52", "8.9p1")
                    for i, part in enumerate(parts):
                        if re.search(r'\d', part) and (re.search(r'[\d.]+', part) or re.search(r'\d+[a-z]\d+', part)):
                            version_idx = i
                            break

                    if version_idx > 0:
                        # Product is everything before version
                        product = " ".join(parts[:version_idx])
                        version = parts[version_idx]
                        extra = " ".join(parts[version_idx+1:]) if len(parts) > version_idx+1 else ""
                    elif len(parts) >= 2:
                        # Fallback: first part is product, second is version
                        product = parts[0]
                        version = parts[1]
                        extra = " ".join(parts[2:]) if len(parts) > 2 else ""
                    else:
                        # Only one part - treat as product
                        product = parts[0]
                        version = ""
                        extra = ""

                if state == "open":
                    services.append({
                        'host': current_host,
                        'hostname': current_hostname,
                        'port': port,
                        'protocol': protocol,
                        'service': service,
                        'product': product,
                        'version': version,
                        'extra_info': extra
                    })

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
        """Helper to log messages to Ask Syd log panel"""
        self.txtAskSydLog.insert(tk.END, f"{message}\n")
        self.txtAskSydLog.see(tk.END)

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
        """Parse Nmap NSE script output using PURE pattern matching - NO service name checks"""
        vulnerabilities = []
        total_score = 0

        lines = nmap_text.split('\n')
        current_port = None
        current_service = None
        current_protocol = None

        for i, line in enumerate(lines):
            # Extract port and service info for context only
            port_match = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)', line)
            if port_match:
                current_port = port_match.group(1)
                current_protocol = port_match.group(2)
                current_service = port_match.group(3)

            # Match against ALL vulnerability patterns
            for vuln_type, vuln_config in self.VULN_PATTERNS.items():
                for pattern in vuln_config['patterns']:
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': vuln_type,
                            'severity': vuln_config['severity'],
                            'score': vuln_config['score'],
                            'category': vuln_config['category'],
                            'port': current_port,
                            'protocol': current_protocol,
                            'service': current_service,
                            'details': line.strip(),
                            'matched_pattern': pattern
                        })
                        total_score += vuln_config['score']
                        break  # Only match once per line per type

            # CVE pattern with CVSS scoring
            cve_match = re.search(r'(CVE-\d{4}-\d+)\s+(\d+\.?\d*)', line)
            if cve_match:
                cve_id = cve_match.group(1)
                cvss = float(cve_match.group(2))
                if cvss >= 7.0:
                    score = 5 if cvss < 9.0 else 8
                    vulnerabilities.append({
                        'type': 'CVE',
                        'cve_id': cve_id,
                        'severity': 'CRITICAL' if cvss >= 9.0 else 'HIGH',
                        'score': score,
                        'category': 'Known CVE',
                        'cvss': cvss,
                        'port': current_port,
                        'protocol': current_protocol,
                        'service': current_service,
                        'details': line.strip()
                    })
                    total_score += score

        return vulnerabilities, total_score

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

        # Convert dict services to ServiceFinding objects
        service_findings = []
        for svc in services:
            # Create a simple text representation to parse
            text_line = f"{svc['port']}/{svc['protocol']} open {svc['service']} {svc['product']} {svc['version']}"
            findings = parse_nmap_text(text_line)
            service_findings.extend(findings)

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

                # List vulnerabilities sorted by score
                for vuln in vulnerabilities_sorted:
                    vuln_type = vuln['type']
                    port = vuln.get('port', 'unknown')
                    service = vuln.get('service', 'unknown')
                    category = vuln.get('category', 'Unknown')
                    severity = vuln.get('severity', 'UNKNOWN')
                    score = vuln.get('score', 0)

                    if vuln_type == 'CVE':
                        critical_section.append(f"[Score: {score}] {severity} - {vuln.get('cve_id')} on {service}:{port} (CVSS: {vuln.get('cvss', 'N/A')})")
                    else:
                        critical_section.append(f"[Score: {score}] {severity} - {category} on {service}:{port}")

                critical_section.append("")
                critical_section.append("💥 **RECOMMENDED EXPLOITS (Prioritized by Score):**")
                critical_section.append("")

                # Generate exploits using GENERIC TEMPLATES (NO service name checks)
                for vuln in vulnerabilities_sorted:
                    vuln_type = vuln['type']
                    template = self.EXPLOIT_TEMPLATES.get(vuln_type)

                    if not template:
                        continue  # Skip if no template defined

                    port = vuln.get('port', 'unknown')
                    service = vuln.get('service', 'unknown')
                    category = vuln.get('category', 'Unknown')

                    critical_section.append(f"**[{category}] {service.upper()}:{port}**")
                    critical_section.append(f"   {template['description']}")
                    critical_section.append("   ```bash")

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
        default_vol_path = os.path.join(os.path.dirname(__file__), "vol.py")
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
        ttk.Button(bottom_btns, text="Upload data...", command=self._upload_data).pack(side="left", padx=5)

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

                if vol_path and os.path.exists(vol_path):
                    # Use configured vol.py path
                    vol_cmd = f'"{python_exe}" "{vol_path}"'
                else:
                    # Try auto-detection with python module
                    vol_cmd = f'"{python_exe}" -m volatility3.cli'

                # Build command - use shell=True on Windows to handle paths with spaces
                cmd = f'{vol_cmd} -f "{dump}" {plugin}'

                self.after(0, lambda: self.txt_raw.insert("end", f"Command: {cmd}\n\n"))

                # Run process and capture output
                self.current_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=True,
                    errors='replace'  # Replace invalid unicode characters
                )

                # Use communicate() to avoid deadlocks and hanging
                try:
                    stdout_output, stderr_output = self.current_process.communicate(timeout=300)  # 5 minute timeout

                    # Display stdout
                    if stdout_output:
                        self.after(0, lambda out=stdout_output: self.txt_raw.insert("end", out))
                        self.after(0, lambda: self.txt_raw.see("end"))

                except subprocess.TimeoutExpired:
                    self.current_process.kill()
                    stdout_output, stderr_output = self.current_process.communicate()
                    self.after(0, lambda: self.txt_raw.insert("end", "\n[ERROR] Process timed out after 5 minutes\n"))
                    if stdout_output:
                        self.after(0, lambda out=stdout_output: self.txt_raw.insert("end", out))
                    if stderr_output:
                        stderr_output += "\n[Process killed due to timeout]"

                # Capture return code before clearing current_process
                return_code = self.current_process.returncode

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

    def _stop_process(self):
        """Stop running process"""
        if self.current_process:
            self.current_process.terminate()
            self.txt_raw.insert("end", "\n[Process stopped]\n")
            self.current_process = None

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
                self.log_to_asksyd(f"[WARNING] Could not load embedding model: {str(e)}")
                self.log_to_asksyd("Ask Syd will not be available. Volatility analysis will still work.")
                self.rag_ready = False
                return

            # 2. Load Volatility FAISS index
            import faiss
            import pickle
            from pathlib import Path

            faiss_path = Path("rag_engine/embeddings/customers/customer_syd_volatility_knowledge_Volatility3.faiss")
            pkl_path = Path("rag_engine/embeddings/customers/customer_syd_volatility_knowledge_Volatility3.pkl")

            self.faiss_index = faiss.read_index(str(faiss_path))
            with open(pkl_path, 'rb') as f:
                self.chunks = pickle.load(f)
            self.log_to_asksyd(f"[OK] Loaded {len(self.chunks)} Volatility knowledge chunks")

            # 3. Load LLM - using Qwen 2.5 14B for better instruction following
            from llama_cpp import Llama
            model_path = Path("rag_engine/models/qwen2.5-14b-instruct-q5_k_m.gguf")
            self.llm = Llama(
                model_path=str(model_path),
                n_ctx=4096,
                n_threads=8,
                n_gpu_layers=25,
                chat_format="chatml",  # Required for chat completion
                verbose=False
            )
            self.log_to_asksyd("[OK] Qwen 2.5 14B loaded")

            # 4. Initialize Volatility fact extractor (mirrors Nmap architecture)
            from volatility_fact_extractor import VolatilityFactExtractor
            self.fact_extractor = VolatilityFactExtractor()
            self.log_to_asksyd("[OK] Volatility fact extractor ready (comprehensive pattern extraction)")

            self.rag_ready = True
            self.log_to_asksyd("[SUCCESS] Ask Syd ready! Type your Volatility question.")

        except Exception as e:
            self.log_to_asksyd(f"[WARNING] Failed to load RAG: {e}")
            import traceback
            traceback.print_exc()

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
                # === STAGE A: EXTRACT FACTS FROM VOLATILITY OUTPUT (mirrors Nmap/BloodHound) ===
                current_output = self.txt_raw.get("1.0", tk.END).strip()

                if not current_output or len(current_output) < 50:
                    self.after(0, lambda: self.remove_thinking_indicator())
                    self.after(0, lambda: self.append_chat_message("Syd", "No Volatility output loaded yet. Please paste Volatility results first."))
                    return

                # Extract structured facts using deterministic parser
                facts = self.fact_extractor.extract_facts(current_output)
                facts_text = self.fact_extractor.facts_to_text(facts)

                # Store facts for validation later
                if not hasattr(self, 'current_facts'):
                    self.current_facts = {}
                self.current_facts = facts

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
                    max_tokens=1024,
                    temperature=0.1,
                    top_p=0.9,
                    stop=["Question:", "Q:", "\n\n\n"]
                )
                answer = response['choices'][0]['message']['content'].strip()

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
                    # Block hallucinated answer
                    original_answer = answer
                    answer = f"[BLOCKED - HALLUCINATION DETECTED]\n\n"
                    answer += f"Syd tried to answer but mentioned information not in the memory dump:\n"
                    for violation in validation_result['violations']:
                        answer += f"  - {violation}\n"
                    answer += f"\nOriginal (blocked) answer: {original_answer[:200]}..."

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
        """Log messages to Ask Syd log panel"""
        self.txt_log.insert(tk.END, f"{message}\n")
        self.txt_log.see(tk.END)

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
        """Log messages to Ask Syd log panel"""
        self.txt_log.insert(tk.END, f"{message}\n")
        self.txt_log.see(tk.END)

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
        ttk.Button(bottom_btns, text="Upload data...", command=self._upload_data).pack(side="left", padx=5)

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
            faiss_path = Path("rag_engine/embeddings/customers/customer_syd_bloodhound_knowledge_BloodHound.faiss")
            pkl_path = Path("rag_engine/embeddings/customers/customer_syd_bloodhound_knowledge_BloodHound.pkl")

            if not faiss_path.exists() or not pkl_path.exists():
                self.log_to_asksyd("[ERROR] BloodHound knowledge files not found!")
                self.log_to_asksyd("[INFO] Run: python chunk_and_embed_bloodhound.py")
                return

            self.faiss_index = faiss.read_index(str(faiss_path))
            with open(pkl_path, 'rb') as f:
                self.chunks = pickle.load(f)
            self.log_to_asksyd(f"[OK] Loaded {len(self.chunks)} BloodHound knowledge chunks from database")

            # 3. Load LLM - using Qwen 2.5 14B (better instruction following than Dolphin 8B)
            model_path = Path("rag_engine/models/qwen2.5-14b-instruct-q5_k_m.gguf")

            if not model_path.exists():
                self.log_to_asksyd("[WARNING] LLM model not found, RAG will work without generation")
                self.rag_ready = True
                self.log_to_asksyd("[SUCCESS] BloodHound knowledge base loaded! Ask me anything.")
                return

            self.llm = Llama(
                model_path=str(model_path),
                n_ctx=4096,
                n_threads=8,
                n_gpu_layers=25,
                chat_format="chatml",  # Required for chat completion
                verbose=False
            )
            self.log_to_asksyd("[OK] Qwen 2.5 14B loaded")

            # 4. Initialize BloodHound fact extractor (mirrors Nmap architecture)
            from bloodhound_fact_extractor import BloodHoundFactExtractor
            self.fact_extractor = BloodHoundFactExtractor()
            self.log_to_asksyd("[OK] BloodHound fact extractor ready (comprehensive pattern extraction)")

            self.rag_ready = True
            self.log_to_asksyd("[SUCCESS] Ask Syd ready! Ask me about BloodHound, AD attacks, Cypher queries, etc.")

        except Exception as e:
            self.log_to_asksyd(f"[WARNING] RAG initialization failed: {e}")
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
                report, vulnerabilities = analyze_bloodhound_zip(filepath)

                self.txt_raw.insert("1.0", f"[ZIP FILE ANALYZED: {filepath}]\n\n")
                self.txt_raw.insert("end", "ZIP files contain multiple JSON files. See Analysis Report for full details.")
                # Note: ZIP handling is more complex for fact extraction, will implement if needed
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
                    self.current_facts_text = self.fact_extractor.facts_to_text(self.current_facts)
                    self.log_to_asksyd(f"[OK] Extracted {len(self.current_facts.get('all_users', []))} users, {len(self.current_facts.get('all_groups', []))} groups, {len(self.current_facts.get('attack_paths', []))} attack paths")
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

            # Parse JSON for fact extraction
            import json
            json_data = json.loads(pasted)

            # Analyze with BloodHound analyzer
            from bloodhound_analyzer import BloodHoundAnalyzer
            report, vulnerabilities = BloodHoundAnalyzer.analyze_bloodhound_output(pasted)

            # === NEW: Extract facts using fact extractor (mirrors Nmap architecture) ===
            if json_data and hasattr(self, 'fact_extractor'):
                try:
                    self.current_facts = self.fact_extractor.extract_facts(json_data)
                    self.current_facts_text = self.fact_extractor.facts_to_text(self.current_facts)
                    self.log_to_asksyd(f"[OK] Extracted {len(self.current_facts.get('all_users', []))} users, {len(self.current_facts.get('all_groups', []))} groups, {len(self.current_facts.get('attack_paths', []))} attack paths")
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

    def log_to_asksyd(self, message):
        """Log messages to Ask Syd log panel"""
        self.txt_log.insert(tk.END, f"{message}\n")
        self.txt_log.see(tk.END)

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
                if not hasattr(self, 'current_facts_text') or not self.current_facts_text:
                    self.after(0, lambda: self.remove_thinking_indicator())
                    self.after(0, lambda: self.append_chat_message("SYD", "No BloodHound data loaded yet. Please analyze a BloodHound JSON file first."))
                    return

                # === STAGE B: GET KNOWLEDGE BASE CONTEXT ===
                # Embed question
                query_vec = self.embed_model.encode([question]).astype('float32')
                faiss.normalize_L2(query_vec)

                # Search FAISS for top 3 chunks
                distances, indices = self.faiss_index.search(query_vec, 3)

                # Get chunk text
                contexts = []
                for idx in indices[0]:
                    if idx < len(self.chunks):
                        chunk = self.chunks[idx]
                        text = chunk.get('content', str(chunk))
                        contexts.append(text)

                context_text = "\n\n".join(contexts)

                # === STAGE C: BUILD FACT-BASED PROMPT (mirrors Nmap architecture) ===
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

FACTS FROM THIS BLOODHOUND SCAN:
{self.current_facts_text}

KNOWLEDGE BASE (for general AD/BloodHound concepts):
{context_text}

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
                    max_tokens=1024,  # Higher than Nmap (512) - BloodHound needs detailed explanations
                    temperature=0.1,
                    top_p=0.9,
                    stop=["Question:", "Q:", "\n\n\n"]
                )
                answer = response['choices'][0]['message']['content'].strip()

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
                        # Block hallucinated answer
                        original_answer = answer
                        answer = f"[BLOCKED - HALLUCINATION DETECTED]\n\n"
                        answer += f"Syd tried to answer but mentioned information not in the BloodHound scan:\n"
                        for violation in validation_result['violations']:
                            answer += f"  - {violation}\n"
                        answer += f"\nOriginal (blocked) answer: {original_answer[:200]}..."

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
            else:
                page = GenericToolPage(red_notebook, tool)
            red_notebook.add(page, text=tool)
        main_notebook.add(red_notebook, text="Red Team")

        # Blue Team notebook
        blue_notebook = ttk.Notebook(main_notebook)
        for tool in BLUE_TOOLS:
            if tool == "Volatility3":
                page = VolatilityPage(blue_notebook)
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
        app = App()
        app.mainloop()
    except Exception as e:
        print(f"FATAL ERROR: {e}", file=sys.stderr)
        traceback.print_exc()
