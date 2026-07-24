# PII Redaction Tool

Redacts personally identifiable info from `.docx` files (names, emails, phones, companies, addresses, SSN, cards, DOB, IPs) and replaces them with consistent fake values.

Built for the Scaler Enterprise Data assignment on a Red Herring Prospectus. Approach: regex + name/company list from the document.

## Run

```bash
pip install -r requirements.txt
python redact_pii.py -i input.docx -o redacted.docx
python evaluate.py
streamlit run streamlit_app.py
```

## Deploy

Streamlit Cloud → this repo → main file `streamlit_app.py`
