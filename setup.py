#!/usr/bin/env python3
"""
Syd Setup Script
Installs all dependencies and downloads model
No HuggingFace account required
"""

import os
import sys
import subprocess
from pathlib import Path

def install_all_dependencies():
    """Install all required packages from requirements.txt"""
    print("\n" + "="*60)
    print("INSTALLING DEPENDENCIES")
    print("="*60)
    print("Installing packages from requirements.txt...")
    print("This may take 5-10 minutes...\n")

    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("\n✓ All dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n✗ Failed to install dependencies: {e}")
        print("\nTry manually:")
        print("  pip install -r requirements.txt")
        return False

def check_dependencies():
    """Check if required packages are installed"""
    required = [
        'huggingface_hub',
        'sentence_transformers',
        'faiss',
        'llama_cpp',
        'torch'
    ]

    missing = []
    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)

    return len(missing) == 0, missing

def download_model():
    """Download Qwen 2.5 14B model from HuggingFace"""
    from huggingface_hub import hf_hub_download

    model_dir = Path("rag_engine/models")
    model_dir.mkdir(parents=True, exist_ok=True)

    model_path = model_dir / "qwen2.5-14b-instruct-q5_k_m.gguf"

    # Check if model already exists
    if model_path.exists():
        size_gb = model_path.stat().st_size / (1024**3)
        if size_gb > 9.0:  # Should be ~9.7GB
            print(f"Model already exists: {model_path}")
            print(f"Size: {size_gb:.1f}GB")
            return True
        else:
            print(f"Incomplete model found ({size_gb:.1f}GB), redownloading...")
            model_path.unlink()

    print("\n" + "="*60)
    print("DOWNLOADING QWEN 2.5 14B MODEL")
    print("="*60)
    print("Model: Qwen2.5-14B-Instruct-GGUF (Q5_K_M)")
    print("Size: ~9.7GB (split into 3 parts)")
    print("Time: 10-30 minutes depending on connection")
    print("No HuggingFace account required")
    print("="*60 + "\n")

    try:
        # Download split model parts
        repo_id = "Qwen/Qwen2.5-14B-Instruct-GGUF"

        parts = [
            "qwen2.5-14b-instruct-q5_k_m-00001-of-00003.gguf",
            "qwen2.5-14b-instruct-q5_k_m-00002-of-00003.gguf",
            "qwen2.5-14b-instruct-q5_k_m-00003-of-00003.gguf"
        ]

        print("Downloading model parts...")
        part_files = []

        for i, part_name in enumerate(parts, 1):
            print(f"\n[{i}/3] Downloading {part_name}...")
            part_path = hf_hub_download(
                repo_id=repo_id,
                filename=part_name,
                local_dir=model_dir,
                local_dir_use_symlinks=False
            )
            part_files.append(Path(part_path))
            print(f"      Downloaded to: {part_path}")

        # Merge parts into single file
        print("\nMerging model parts...")
        with open(model_path, 'wb') as outfile:
            for i, part_file in enumerate(part_files, 1):
                print(f"  Merging part {i}/3...")
                with open(part_file, 'rb') as infile:
                    outfile.write(infile.read())
                # Delete part after merging
                part_file.unlink()

        # Verify final size
        final_size_gb = model_path.stat().st_size / (1024**3)
        print(f"\nModel downloaded successfully!")
        print(f"Location: {model_path}")
        print(f"Size: {final_size_gb:.1f}GB")

        if final_size_gb < 9.0:
            print("\nWARNING: Model size is smaller than expected. Download may be incomplete.")
            return False

        return True

    except Exception as e:
        print(f"\nERROR: Download failed: {e}")
        print("\nManual download instructions:")
        print("1. Go to: https://huggingface.co/Qwen/Qwen2.5-14B-Instruct-GGUF")
        print("2. Download these 3 files:")
        print("   - qwen2.5-14b-instruct-q5_k_m-00001-of-00003.gguf")
        print("   - qwen2.5-14b-instruct-q5_k_m-00002-of-00003.gguf")
        print("   - qwen2.5-14b-instruct-q5_k_m-00003-of-00003.gguf")
        print("3. Merge them with:")
        print("   cat qwen2.5-14b-instruct-q5_k_m-*.gguf > rag_engine/models/qwen2.5-14b-instruct-q5_k_m.gguf")
        print("   (On Windows, use: copy /b part1+part2+part3 merged.gguf)")
        return False

def verify_installation():
    """Check if all required files exist"""
    print("\n" + "="*60)
    print("VERIFYING INSTALLATION")
    print("="*60)

    checks = {
        "Model file": Path("rag_engine/models/qwen2.5-14b-instruct-q5_k_m.gguf"),
        "Nmap FAISS index": Path("rag_engine/embeddings/customers/customer_syd_Nmap.faiss"),
        "BloodHound FAISS index": Path("rag_engine/embeddings/customers/customer_syd_bloodhound_knowledge_BloodHound.faiss"),
        "Volatility FAISS index": Path("rag_engine/embeddings/customers/customer_syd_volatility_knowledge_Volatility3.faiss"),
    }

    all_good = True
    for name, path in checks.items():
        if path.exists():
            size = path.stat().st_size / (1024**2)
            unit = "MB" if size < 1024 else "GB"
            size_display = size if size < 1024 else size / 1024
            print(f"✓ {name}: {size_display:.1f}{unit}")
        else:
            print(f"✗ {name}: MISSING")
            all_good = False

    return all_good

def main():
    print("\n" + "="*60)
    print("SYD AUTOMATED SETUP")
    print("="*60)
    print("This script will:")
    print("  1. Install all Python dependencies")
    print("  2. Download Qwen 2.5 14B model (~9.7GB)")
    print("  3. Verify installation")
    print("\nFAISS indexes are included - no generation needed!")
    print("Total time: 15-30 minutes")
    print("="*60 + "\n")

    input("Press Enter to begin setup...")

    # Step 1: Install dependencies
    deps_ok, missing = check_dependencies()
    if not deps_ok:
        print(f"\nMissing packages: {', '.join(missing)}")
        if not install_all_dependencies():
            print("\n✗ Dependency installation failed")
            print("Please run manually: pip install -r requirements.txt")
            sys.exit(1)
    else:
        print("\n✓ All dependencies already installed")

    # Step 2: Download model
    if not download_model():
        print("\n✗ Model download failed")
        print("\nManual download instructions:")
        print("1. Go to: https://huggingface.co/Qwen/Qwen2.5-14B-Instruct-GGUF")
        print("2. Download all 3 parts of qwen2.5-14b-instruct-q5_k_m")
        print("3. Merge them into: rag_engine/models/qwen2.5-14b-instruct-q5_k_m.gguf")
        sys.exit(1)

    # Step 3: Verify everything
    if verify_installation():
        print("\n" + "="*60)
        print("SETUP COMPLETE!")
        print("="*60)
        print("\n✓ All dependencies installed")
        print("✓ Model downloaded (9.7GB)")
        print("✓ FAISS indexes verified")
        print("\nYou can now run Syd:")
        print("  python syd.py")
        print("\nFirst launch takes 10-20 seconds to load models.")
        print("Subsequent queries: 2-5 seconds.")
        print("="*60 + "\n")
    else:
        print("\n✗ Setup incomplete. Please check missing files above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
