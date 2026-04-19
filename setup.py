#!/usr/bin/env python3
"""
Syd Setup Script
Installs dependencies and downloads the model. No HuggingFace account required.
"""

import os
import sys
import subprocess
from pathlib import Path


def run(cmd, check=True):
    return subprocess.run(cmd, check=check)


def install_llama_cpp():
    print("\n[1/4] Installing llama-cpp-python (CPU-optimised build)...")
    print("      This takes a few minutes - it compiles from source.")
    try:
        run([
            sys.executable, "-m", "pip", "install",
            "llama-cpp-python==0.3.16",
            "--force-reinstall",
            "--no-cache-dir",
            '--config-settings=cmake.args=-DGGML_AVX2=OFF;-DGGML_AVX=OFF;-DGGML_F16C=OFF;-DGGML_FMA=OFF'
        ])
        print("      Done.\n")
        return True
    except subprocess.CalledProcessError:
        print("\n      llama-cpp-python build failed.")
        print("      Make sure you have CMake and a C++ compiler installed.")
        print("      On Windows: install Visual Studio Build Tools from https://visualstudio.microsoft.com/downloads/")
        return False


def install_dependencies():
    print("[2/4] Installing remaining dependencies...")
    try:
        run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("      Done.\n")
        return True
    except subprocess.CalledProcessError:
        print("      Failed. Try: pip install -r requirements.txt")
        return False


def download_embedding_model():
    print("[3/4] Downloading embedding model (all-MiniLM-L6-v2, ~90MB)...")
    try:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")
        test = model.encode("test", show_progress_bar=False)
        if test is not None and len(test) > 0:
            print("      Done.\n")
            return True
        return False
    except Exception as e:
        print(f"      Warning: {e}")
        print("      Syd will attempt to download it on first launch.\n")
        return False


def download_llm():
    print("[4/4] Downloading Qwen 2.5 14B model (~9.7GB)...")
    print("      This will take 20-30 minutes depending on your connection.")
    print("      Do not close this window.\n")

    from huggingface_hub import hf_hub_download

    model_dir = Path("rag_engine/models")
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "qwen2.5-14b-instruct-q5_k_m.gguf"

    if model_path.exists():
        size_gb = model_path.stat().st_size / (1024 ** 3)
        if size_gb > 9.0:
            print(f"      Model already exists ({size_gb:.1f}GB). Skipping download.\n")
            return True
        else:
            print(f"      Incomplete model found ({size_gb:.1f}GB). Re-downloading...")
            model_path.unlink()

    repo_id = "Qwen/Qwen2.5-14B-Instruct-GGUF"
    parts = [
        "qwen2.5-14b-instruct-q5_k_m-00001-of-00003.gguf",
        "qwen2.5-14b-instruct-q5_k_m-00002-of-00003.gguf",
        "qwen2.5-14b-instruct-q5_k_m-00003-of-00003.gguf",
    ]

    try:
        part_files = []
        for i, part in enumerate(parts, 1):
            print(f"      Downloading part {i}/3...")
            path = hf_hub_download(
                repo_id=repo_id,
                filename=part,
                local_dir=model_dir,
                local_dir_use_symlinks=False
            )
            part_files.append(Path(path))

        print("      Merging parts...")
        with open(model_path, "wb") as out:
            for i, part_file in enumerate(part_files, 1):
                print(f"      Merging {i}/3...")
                with open(part_file, "rb") as f:
                    out.write(f.read())
                part_file.unlink()

        final_size = model_path.stat().st_size / (1024 ** 3)
        if final_size < 9.0:
            print(f"      Warning: model is only {final_size:.1f}GB, expected ~9.7GB. Download may be incomplete.")
            return False

        print(f"      Done. ({final_size:.1f}GB)\n")
        return True

    except Exception as e:
        print(f"\n      Download failed: {e}")
        print("\n      Manual download:")
        print("      1. Go to https://huggingface.co/Qwen/Qwen2.5-14B-Instruct-GGUF")
        print("      2. Download all 3 parts of qwen2.5-14b-instruct-q5_k_m")
        print("      3. Merge them into rag_engine/models/qwen2.5-14b-instruct-q5_k_m.gguf")
        print("         Windows: copy /b part1+part2+part3 qwen2.5-14b-instruct-q5_k_m.gguf")
        return False


def verify():
    checks = {
        "LLM model":              Path("rag_engine/models/qwen2.5-14b-instruct-q5_k_m.gguf"),
        "Nmap index":             Path("rag_engine/embeddings/customers/customer_syd_nmap_knowledge.faiss"),
        "BloodHound index":       Path("rag_engine/embeddings/customers/customer_syd_bloodhound_knowledge_BloodHound.faiss"),
        "Volatility index":       Path("rag_engine/embeddings/customers/customer_syd_volatility_knowledge_Volatility3.faiss"),
        "YARA index":             Path("rag_engine/embeddings/customers/customer_syd_yara_knowledge.faiss"),
        "NetExec index":          Path("rag_engine/embeddings/customers/customer_syd_nxc_knowledge.faiss"),
        "PCAP index":             Path("rag_engine/embeddings/customers/customer_syd_pcap_knowledge.faiss"),
    }

    print("\nVerifying installation:")
    all_good = True
    for name, path in checks.items():
        if path.exists():
            size_mb = path.stat().st_size / (1024 ** 2)
            size_str = f"{size_mb/1024:.1f}GB" if size_mb > 1024 else f"{size_mb:.0f}MB"
            print(f"  OK  {name} ({size_str})")
        else:
            print(f"  MISSING  {name}: {path}")
            all_good = False

    return all_good


def main():
    print("\nSyd Setup")
    print("=" * 40)
    print("This will install everything needed to run Syd.")
    print("Approx 20-30 minutes (mostly model download).")
    print("=" * 40 + "\n")

    input("Press Enter to start...")

    if not install_llama_cpp():
        sys.exit(1)

    if not install_dependencies():
        sys.exit(1)

    download_embedding_model()

    if not download_llm():
        sys.exit(1)

    if verify():
        print("\n" + "=" * 40)
        print("Setup complete. Run:  python syd.py")
        print("First launch: 10-20 seconds to load the model.")
        print("Queries after that: 2-5 seconds.")
        print("=" * 40 + "\n")
    else:
        print("\nSetup incomplete — check missing files above.")
        print("If FAISS indexes are missing, run: python build_all_databases.py")
        sys.exit(1)


if __name__ == "__main__":
    main()
