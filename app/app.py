"""
Minimal Flask API.

The app is intentionally trivial — it exists to give the pipeline something
to build, scan, sign, and deploy. All the interesting work happens in
infra/terraform, k8s/, and .github/workflows/.
"""
import os

from flask import Flask, jsonify

app = Flask(__name__)

APP_VERSION = os.environ.get("APP_VERSION", "dev")


@app.route("/")
def index():
    return jsonify(service="secure-cicd-demo", status="ok")


@app.route("/healthz")
def healthz():
    """Liveness/readiness probe target."""
    return jsonify(status="healthy"), 200


@app.route("/version")
def version():
    return jsonify(version=APP_VERSION)


if __name__ == "__main__":
    # Dev server only — gunicorn is the production entrypoint (see Dockerfile)
    # and binds 0.0.0.0 there deliberately (that's what makes the container
    # reachable at all). This path defaults to loopback-only so a bare
    # `python app.py` doesn't expose the dev server to the LAN; override
    # with FLASK_RUN_HOST if you actually need that.
    app.run(host=os.environ.get("FLASK_RUN_HOST", "127.0.0.1"), port=8080)
