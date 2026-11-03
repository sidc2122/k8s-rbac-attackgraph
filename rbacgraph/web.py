"""
Local web dashboard for the RBAC attack-path analyser.

Run it with:
    python -m rbacgraph.web

Then a browser tab opens at http://127.0.0.1:5000 with a clickable UI:
upload a YAML file or pick a live cluster, hit Scan, and see ranked attack
paths as colour-coded cards. Everything runs on your own machine; nothing is
sent anywhere.
"""

import os
import tempfile
import threading
import webbrowser

from flask import Flask, jsonify, render_template, request

from . import service

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB upload cap


@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "That file is too large (limit 25 MB)."}), 413


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/contexts")
def contexts():
    return jsonify(service.list_contexts())


@app.route("/api/scan/live", methods=["POST"])
def scan_live():
    data = request.get_json(force=True, silent=True) or {}
    ctx = data.get("context") or None
    include_system = bool(data.get("include_system"))
    try:
        return jsonify(service.scan_live(ctx, include_system))
    except RuntimeError as exc:          # already a friendly message
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Could not scan the cluster: {exc}"}), 400


@app.route("/api/scan/upload", methods=["POST"])
def scan_upload():
    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "No file uploaded."}), 400

    tmpdir = tempfile.mkdtemp(prefix="rbacgraph_")
    paths = []
    for f in files:
        name = f.filename or "upload.yaml"
        dest = os.path.join(tmpdir, os.path.basename(name))
        f.save(dest)
        paths.append(dest)
    try:
        return jsonify(service.scan_yaml(paths))
    except ValueError as exc:            # InvalidInputError and friends
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Could not analyse the file: {exc}"}), 400


# Built-in example manifests, so visitors can try the tool without a file of
# their own. Only names in this list can be scanned (no arbitrary paths).
SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
SAMPLES = [
    ("vulnerable_rbac.yaml", "Vulnerable cluster (2 attack paths)"),
    ("default_sa_admin.yaml", "Default account is cluster-admin"),
    ("goat_rbac.yaml", "Kubernetes Goat-style scenarios"),
    ("fix_partial_rbac.yaml", "After a partial fix"),
    ("benign_rbac.yaml", "Safe, least-privilege cluster"),
]


@app.route("/api/samples")
def samples():
    return jsonify([{"name": n, "label": l} for n, l in SAMPLES])


@app.route("/api/scan/sample", methods=["POST"])
def scan_sample():
    data = request.get_json(force=True, silent=True) or {}
    name = data.get("name")
    if name not in dict(SAMPLES):
        return jsonify({"error": "Unknown example."}), 400
    try:
        return jsonify(service.scan_yaml([os.path.join(SAMPLES_DIR, name)]))
    except Exception as exc:
        return jsonify({"error": f"Could not analyse the example: {exc}"}), 400


@app.route("/api/compare", methods=["POST"])
def compare():
    data = request.get_json(force=True, silent=True) or {}
    before = data.get("before", [])
    after = data.get("after", [])
    return jsonify(service.compare(before, after))


def main():
    url = "http://127.0.0.1:5000"
    # Open the browser a moment after the server starts.
    threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    print(f"\n  RBAC Attack-Path Dashboard running at {url}")
    print("  Press Ctrl+C to stop.\n")
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
