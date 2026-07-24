# PII Redaction Tool

Scaler assignment — take a .docx (the Red Herring Prospectus) and scrub PII out of it.

I used plain Python + regex. Also pull people/company names from the doc itself (promoters, contact persons, anything ending in Limited etc). Didn't go the spaCy/Presidio route; felt easier to control on this kind of legal doc.

Covers: names, emails, phones, companies, addresses, SSN, credit cards, DOB, IPs.

Left alone on purpose: CIN, ticket/order ids, random boilerplate like "Equity Shares".

## how to run

```
pip install -r requirements.txt
python redact_pii.py -i "yourfile.docx" -o redacted.docx
python evaluate.py
```

Web UI:

```
streamlit run streamlit_app.py
```

Same app is what's deployed on Streamlit Cloud (entry file: `streamlit_app.py`).

Same original value always maps to the same fake one so the redacted file is still readable.
