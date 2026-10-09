import hashlib
import yaml
import audit

with open("manifest.yaml", "rb") as f:
    raw = f.read()

manifest = yaml.safe_load(raw)
fingerprint = hashlib.sha256(raw).hexdigest()[:16]

audit.log("manifest", "manifest_registered", {
    "agent": manifest["agent"]["name"],
    "version": manifest["agent"]["version"],
    "model": manifest["model"]["name"],
    "tools": [t["name"] for t in manifest["tools"]],
    "sha256_prefix": fingerprint,
})
print("Registered", manifest["agent"]["name"], "fingerprint", fingerprint)