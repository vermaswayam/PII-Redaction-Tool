import tempfile
from pathlib import Path

import streamlit as st

from redact_pii import redact_document

st.set_page_config(page_title="PII Redaction", page_icon=None, layout="centered")

st.title("PII Redaction Tool")
st.write(
    "Upload a .docx file. The app redacts names, emails, phones, companies, "
    "addresses, SSNs, cards, DOBs and IPs, then lets you download the result."
)

uploaded = st.file_uploader("Choose a .docx", type=["docx"])

if uploaded is not None:
    if st.button("Redact", type="primary"):
        with st.spinner("Working… larger files can take a couple of minutes"):
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                src = tmp_path / "input.docx"
                dst = tmp_path / "redacted.docx"
                summary = tmp_path / "summary.json"

                src.write_bytes(uploaded.getvalue())
                result = redact_document(src, dst, summary)

                data = dst.read_bytes()
                out_name = Path(uploaded.name).stem + "_REDACTED.docx"

        st.success(f"Done — {result.get('total_redactions', 0)} replacements")
        if result.get("by_type"):
            st.json(result["by_type"])

        st.download_button(
            label="Download redacted docx",
            data=data,
            file_name=out_name,
            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
