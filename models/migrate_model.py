"""Copy an installed Ollama model into a portable project folder named after the model.

    python models/migrate_model.py qwen3:8b

creates models/qwen3-8b/ with:
    model.gguf   the weights (copied from the local Ollama store)
    Modelfile    FROM ./model.gguf plus the original template, system prompt and parameters
    LICENSE      the model's license text (redistribution requires it)
    model.json   name, size and sha256 of the weights

Any machine (or the Docker `ollama` service) can then recreate the exact model with:
    ollama create qwen3:8b -f models/qwen3-8b/Modelfile
"""

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

MODELS_DIR = Path(__file__).resolve().parent


def folder_name(model):
    return re.sub(r"[^A-Za-z0-9._-]", "-", model.replace(":", "-"))


def ollama_binary():
    found = shutil.which("ollama")
    if found:
        return found
    candidate = Path.home() / "AppData/Local/Programs/Ollama/ollama.exe"
    if candidate.exists():
        return str(candidate)
    sys.exit("ollama CLI not found; install Ollama first")


def split_modelfile(text):
    """Return (blob path, the Modelfile body without FROM and LICENSE, license text)."""
    blob = re.search(r"^FROM (.+)$", text, re.MULTILINE).group(1).strip()
    license_match = re.search(r'^LICENSE """(.*?)"""', text, re.MULTILINE | re.DOTALL)
    license_text = license_match.group(1).strip() if license_match else ""
    body = re.sub(r'^LICENSE """.*?"""\n?', "", text, flags=re.MULTILINE | re.DOTALL)
    body = re.sub(r"^FROM .+\n", "", body, flags=re.MULTILINE)
    body = "\n".join(line for line in body.splitlines() if not line.startswith("#")).strip()
    return blob, body, license_text


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def migrate(model):
    target = MODELS_DIR / folder_name(model)
    target.mkdir(parents=True, exist_ok=True)
    text = subprocess.run([ollama_binary(), "show", "--modelfile", model], capture_output=True, text=True, encoding="utf-8", check=True).stdout
    blob, body, license_text = split_modelfile(text)
    weights = target / "model.gguf"
    expected = Path(blob).name.removeprefix("sha256-")
    if weights.exists() and sha256(weights) == expected:
        print(f"{weights} already up to date")
    else:
        print(f"Copying {blob} -> {weights} ...")
        shutil.copyfile(blob, weights)
        if sha256(weights) != expected:
            sys.exit("Checksum mismatch after copy")
    (target / "Modelfile").write_text(f"# Migrated from the local Ollama store by models/migrate_model.py\n# Recreate with: ollama create {model} -f Modelfile\nFROM ./model.gguf\n{body}\n", encoding="utf-8")
    if license_text:
        (target / "LICENSE").write_text(license_text + "\n", encoding="utf-8")
    (target / "model.json").write_text(json.dumps({"name": model, "file": "model.gguf", "size_bytes": weights.stat().st_size, "sha256": expected}, indent=2) + "\n", encoding="utf-8")
    print(f"Migrated {model} to {target}")


if __name__ == "__main__":
    for name in sys.argv[1:] or ["qwen3:8b"]:
        migrate(name)
