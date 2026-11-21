#!/usr/bin/env python3
"""Build a single-layer container image (docker-archive / `docker save`
format) from a static binary, without a Docker daemon.

RouterOS imports this format with `/container/add file=...`, and so does
`docker load`.

usage: mkimage.py --binary vartadns --arch arm64 [--variant v7] \
                  --ca ca-certificates.crt --config deploy/config.json \
                  --tag vartadns:1.0 --out vartadns-arm64.tar
"""
import argparse
import hashlib
import io
import json
import tarfile
import time


def add_file(tar, path, data, mode, mtime):
    ti = tarfile.TarInfo(path)
    ti.size = len(data)
    ti.mode = mode
    ti.mtime = mtime
    ti.uid = ti.gid = 0
    tar.addfile(ti, io.BytesIO(data))


def add_dir(tar, path, mtime):
    ti = tarfile.TarInfo(path)
    ti.type = tarfile.DIRTYPE
    ti.mode = 0o755
    ti.mtime = mtime
    tar.addfile(ti)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--arch", required=True, choices=["amd64", "arm64", "arm"])
    ap.add_argument("--variant", default="")
    ap.add_argument("--ca", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    mtime = int(time.time())
    # ---- layer ---------------------------------------------------------
    lbuf = io.BytesIO()
    with tarfile.open(fileobj=lbuf, mode="w", format=tarfile.USTAR_FORMAT) as lt:
        for d in ("etc", "etc/ssl", "etc/ssl/certs", "etc/vartadns", "data", "tmp"):
            add_dir(lt, d, mtime)
        add_file(lt, "vartadns", open(a.binary, "rb").read(), 0o755, mtime)
        add_file(lt, "etc/ssl/certs/ca-certificates.crt", open(a.ca, "rb").read(), 0o644, mtime)
        add_file(lt, "etc/vartadns/config.json", open(a.config, "rb").read(), 0o644, mtime)
    layer = lbuf.getvalue()
    layer_sha = hashlib.sha256(layer).hexdigest()

    # ---- image config --------------------------------------------------------
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime))
    cfg = {
        "architecture": a.arch,
        "os": "linux",
        "created": created,
        "config": {
            "Entrypoint": ["/vartadns", "-config", "/etc/vartadns/config.json"],
            "Env": ["VARTA_DATA_DIR=/data", "PATH=/"],
            "ExposedPorts": {"53/udp": {}, "53/tcp": {}, "8080/tcp": {}},
            "Volumes": {"/data": {}},
            "WorkingDir": "/",
        },
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + layer_sha]},
        "history": [{"created": created, "created_by": "tools/mkimage.py"}],
    }
    if a.variant:
        cfg["variant"] = a.variant
    cfg_bytes = json.dumps(cfg, separators=(",", ":")).encode()
    cfg_sha = hashlib.sha256(cfg_bytes).hexdigest()

    repo, _, tag = a.tag.partition(":")
    tag = tag or "latest"
    manifest = [{
        "Config": cfg_sha + ".json",
        "RepoTags": [f"{repo}:{tag}"],
        "Layers": [layer_sha + "/layer.tar"],
    }]

    # ---- outer docker-archive ---------------------------------------------------
    with tarfile.open(a.out, mode="w", format=tarfile.USTAR_FORMAT) as out:
        add_dir(out, layer_sha, mtime)
        add_file(out, layer_sha + "/VERSION", b"1.0", 0o644, mtime)
        add_file(out, layer_sha + "/json", json.dumps({"id": layer_sha, "created": created}).encode(), 0o644, mtime)
        add_file(out, layer_sha + "/layer.tar", layer, 0o644, mtime)
        add_file(out, cfg_sha + ".json", cfg_bytes, 0o644, mtime)
        add_file(out, "manifest.json", json.dumps(manifest).encode(), 0o644, mtime)
        add_file(out, "repositories", json.dumps({repo: {tag: layer_sha}}).encode(), 0o644, mtime)
    print(f"{a.out}: {a.arch}{('/' + a.variant) if a.variant else ''}, layer {len(layer) // 1024} KiB")


if __name__ == "__main__":
    main()
