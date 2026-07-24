# pii-redaction

Scaler assignment — redact PII from a .docx (Red Herring Prospectus) and replace with fake values.

Uses regex + a name/company list pulled from the document. No spaCy/Presidio.

### run locally
```
pip install -r requirements.txt
python redact_pii.py -i input.docx -o submission/redacted.docx
python evaluate.py
```

### web demo (Streamlit — recommended for deploy)
```
pip install -r requirements.txt
streamlit run streamlit_app.py
```

### optional Flask demo
```
python app.py
```

### deploy on Streamlit Community Cloud
1. Push this repo to GitHub (public is easiest).
2. Go to https://share.streamlit.io → New app.
3. Pick the repo, branch `main`, main file `streamlit_app.py`.
4. Deploy. Use the public URL on the submission form.

Render/Railway still works for the Flask app (`Procfile`) if you prefer that instead.


### notes
Same real string always maps to the same fake value. CIN / ticket ids / generic terms like "Equity Shares" are left alone on purpose. Scoring details are in `submission/Evaluation_Strategy_and_Metrics.docx`.
