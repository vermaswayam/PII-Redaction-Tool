import os
import tempfile
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, send_file, url_for

from redact_pii import redact_document

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key")
app.config["MAX_CONTENT_LENGTH"] = 15 * 1024 * 1024


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/redact")
def redact():
    uploaded = request.files.get("document")
    if not uploaded or not uploaded.filename:
        flash("Pick a .docx file first.")
        return redirect(url_for("index"))

    if not uploaded.filename.lower().endswith(".docx"):
        flash("Only .docx for now.")
        return redirect(url_for("index"))

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        src = tmp_path / "input.docx"
        dst = tmp_path / "redacted.docx"
        uploaded.save(src)
        try:
            redact_document(src, dst, tmp_path / "summary.json")
        except Exception as exc:
            flash(f"Failed: {exc}")
            return redirect(url_for("index"))
        data = dst.read_bytes()

    out = tempfile.NamedTemporaryFile(delete=False, suffix=".docx")
    out.write(data)
    out.close()

    return send_file(
        out.name,
        as_attachment=True,
        download_name=Path(uploaded.filename).stem + "_REDACTED.docx",
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )


@app.get("/health")
def health():
    return {"ok": True}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
