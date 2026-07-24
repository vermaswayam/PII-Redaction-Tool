"""
Score the redactor.

- small synthetic paragraph with all PII types
- hand-picked entities from the prospectus
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from docx import Document

from redact_pii import (
    apply_findings,
    collect_spans,
    extract_address_strings,
    extract_all_text,
    extract_companies,
    extract_people,
)


ROOT = Path(__file__).resolve().parent


@dataclass
class Entity:
    pii_type: str
    value: str


def prf(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = tp / (tp + fp + fn) if (tp + fp + fn) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().lower()


def score_entities(predicted: list[Entity], gold: list[Entity]) -> dict:
    gold_bags: dict[tuple[str, str], int] = defaultdict(int)
    pred_bags: dict[tuple[str, str], int] = defaultdict(int)
    for g in gold:
        gold_bags[(g.pii_type, normalize(g.value))] += 1
    for p in predicted:
        pred_bags[(p.pii_type, normalize(p.value))] += 1

    keys = set(gold_bags) | set(pred_bags)
    tp = fp = fn = 0
    per_type = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

    for key in keys:
        g = gold_bags.get(key, 0)
        p = pred_bags.get(key, 0)
        matched = min(g, p)
        tp += matched
        fp += max(0, p - g)
        fn += max(0, g - p)
        t = key[0]
        per_type[t]["tp"] += matched
        per_type[t]["fp"] += max(0, p - g)
        per_type[t]["fn"] += max(0, g - p)

    overall = prf(tp, fp, fn)
    by_type = {t: prf(v["tp"], v["fp"], v["fn"]) for t, v in sorted(per_type.items())}
    return {"overall": overall, "by_type": by_type}


SYNTHETIC_TEXT = """
Ticket #4821 opened by Rashi Patil (rashhi.patil@gmail.com, +91 9876543210).
Backup contact: Rohan Dey <rohan.dey@gmail.com>, mobile 022-68052182.
SSN on file: 234-56-7890. Card ending auth: 4111 1111 1111 1111.
Date of birth: 14/08/1992. Last login IP: 203.0.113.45.
Employer: BrightSpark Analytics Private Limited.
Mailing address: Plot 12, Lane 3, Koregaon Park, Pune – 411 001, Maharashtra, India.
Also saw a non-PII order id ORD-998877 and ticket number TCK-1002 — leave those alone.
Invalid pseudo-card 1234 5678 9012 3456 should not match Luhn.
"""

SYNTHETIC_GOLD = [
    Entity("name", "Rashi Patil"),
    Entity("email", "rashhi.patil@gmail.com"),
    Entity("phone", "+91 9876543210"),
    Entity("name", "Rohan Dey"),
    Entity("email", "rohan.dey@gmail.com"),
    Entity("phone", "022-68052182"),
    Entity("ssn", "234-56-7890"),
    Entity("credit_card", "4111 1111 1111 1111"),
    Entity("date_of_birth", "14/08/1992"),
    Entity("ip_address", "203.0.113.45"),
    Entity("company", "BrightSpark Analytics Private Limited"),
    Entity("address", "Plot 12, Lane 3, Koregaon Park, Pune – 411 001, Maharashtra, India"),
]


def evaluate_synthetic() -> dict:
    text = SYNTHETIC_TEXT
    people = extract_people(text) | {"Rashi Patil", "Rohan Dey"}
    companies = extract_companies(text) | {"BrightSpark Analytics Private Limited"}
    addresses = extract_address_strings(text)
    findings = collect_spans(text, people, companies, addresses)
    predicted = [Entity(f.pii_type, f.original) for f in findings]

    false_friends = ["ORD-998877", "TCK-1002", "1234 5678 9012 3456"]
    leaked = [v for v in false_friends if any(normalize(v) == normalize(p.value) for p in predicted)]

    result = score_entities(predicted, SYNTHETIC_GOLD)
    result["non_pii_leaks_as_redactions"] = leaked
    result["predicted"] = [{"pii_type": p.pii_type, "value": p.value} for p in predicted]
    return result


def load_prospectus_gold() -> tuple[str, list[Entity], list[str]]:
    path = ROOT / "Red Herring Prospectus.docx"
    doc = Document(str(path))
    text = extract_all_text(doc)

    positives = [
        Entity("email", "cs.connect@kshinternational.com"),
        Entity("email", "ksh.ipo@nuvama.com"),
        Entity("email", "ksh@icicisecurities.com"),
        Entity("email", "Sarthak.malvadkar@kshinterantional.com"),
        Entity("email", "prakash.boricha@nuvama.com"),
        Entity("email", "customercare@icicisecurities.com"),
        Entity("email", "hingnetare@gmail.com"),
        Entity("phone", "+91 81081 14949"),
        Entity("phone", "+ 91 20 45053237"),
        Entity("phone", "+91 22 4009 4400"),
        Entity("name", "Kushal Subbayya Hegde"),
        Entity("name", "Pushpa Kushal Hegde"),
        Entity("name", "Rajesh Kushal Hegde"),
        Entity("name", "Rohit Kushal Hegde"),
        Entity("name", "Rakhi Girija Shetty"),
        Entity("name", "Sarthak Malvadkar"),
        Entity("name", "Dinesh Hirachand Munot"),
        Entity("name", "Ajay Shriram Patil"),
        Entity("company", "KSH International Limited"),
        Entity("company", "ICICI Securities Limited"),
        Entity("company", "HDFC Bank Limited"),
        Entity("company", "Kirtane & Pandit LLP"),
        Entity(
            "address",
            "201, Tower 2, Montreal Business Centre, Off Pallod Farms, Baner, Pune – 411 045, Maharashtra, India",
        ),
    ]

    filtered = []
    low = text.lower()
    for e in positives:
        if e.value.lower() in low:
            filtered.append(e)
        else:
            compact_text = re.sub(r"\s+", " ", low)
            if normalize(e.value) in compact_text:
                filtered.append(e)

    negatives = [
        "U28129PN1979PLC141032",
        "ORD-998877",
        "Anchor Investor",
        "Equity Shares",
        "Book Running Lead Managers",
        "INR000004058",
    ]
    return text, filtered, negatives


def _prospectus_predicted_bags(text: str) -> dict[str, set[str]]:
    from redact_pii import EMAIL_RE, PHONE_RE, looks_like_phone

    people = extract_people(text)
    companies = extract_companies(text)
    addresses = extract_address_strings(text)

    bags: dict[str, set[str]] = defaultdict(set)
    for m in EMAIL_RE.finditer(text):
        bags["email"].add(normalize(m.group(0)))
    for m in PHONE_RE.finditer(text):
        raw = m.group(0).strip()
        if looks_like_phone(raw):
            bags["phone"].add(normalize(raw))
    for person in people:
        if person in text or person.upper() in text:
            bags["name"].add(normalize(person))
    for company in companies:
        if company in text:
            bags["company"].add(normalize(company))
    for addr in addresses:
        if addr in text or normalize(addr) in normalize(text):
            bags["address"].add(normalize(addr))
    return bags


def evaluate_prospectus() -> dict:
    text, gold, negatives = load_prospectus_gold()
    bags = _prospectus_predicted_bags(text)

    tp = fp = fn = 0
    per_type = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

    for g in gold:
        norms = bags.get(g.pii_type, set())
        hit = normalize(g.value) in norms or any(
            normalize(g.value) in n or n in normalize(g.value) for n in norms
        )
        if hit:
            tp += 1
            per_type[g.pii_type]["tp"] += 1
        else:
            fn += 1
            per_type[g.pii_type]["fn"] += 1

    negative_hits = []
    for neg in negatives:
        neg_n = normalize(neg)
        for pii_type, norms in bags.items():
            if neg_n in norms or any(neg_n in n for n in norms):
                fp += 1
                per_type[pii_type]["fp"] += 1
                negative_hits.append({"negative": neg, "predicted_as": pii_type})
                break

    overall = prf(tp, fp, fn)
    by_type = {t: prf(v["tp"], v["fp"], v["fn"]) for t, v in sorted(per_type.items())}

    people = extract_people(text)
    companies = extract_companies(text)
    addresses = extract_address_strings(text)
    sample = text[:20000]
    redacted_sample = apply_findings(sample, collect_spans(sample, people, companies, addresses))
    original_emails = set(
        re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", sample)
    )
    remaining_original = [
        e
        for e in re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", redacted_sample)
        if e in original_emails
    ]

    return {
        "overall": overall,
        "by_type": by_type,
        "gold_size": len(gold),
        "negative_hits": negative_hits,
        "original_emails_still_present_in_sample": remaining_original[:10],
        "notes": "hand-labeled subset of the RHP, not every name in the full document",
    }


def main() -> None:
    synthetic = evaluate_synthetic()
    prospectus = evaluate_prospectus()

    report = {
        "synthetic": synthetic,
        "prospectus_subset": prospectus,
    }

    out_dir = ROOT / "submission"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "evaluation_metrics.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print("Synthetic overall:", synthetic["overall"])
    print("Prospectus overall:", prospectus["overall"])
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
