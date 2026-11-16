"""Download public email corpora and merge them into one CSV file.

The corpora contain phishing, spam and legitimate emails.
Read classifier/data/README.md for the sources and the licenses.

Usage:  python3 classifier/data/fetch_datasets.py

Output: classifier/data/emails.csv. The columns are:
    source   The corpus that the row comes from.
    kind     phishing, spam or legit.
    label    1 = phishing or spam, 0 = legit.
    group    Rows with the same group are versions of one email. Keep them in the same split.
    sender, subject, body

The script keeps the downloaded files in classifier/data/raw/. Git ignores this folder.
If you run the script again, it does not download these files again.
The script reads the emails as text only. It does not write or open the attachments.
"""
import csv
import hashlib
import json
import mailbox
import re
import subprocess
import sys
import tarfile
from email import policy
from email.parser import BytesParser
from html import unescape
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW = HERE / "raw"
OUT = HERE / "emails.csv"
MAX_BODY = 20_000

# Champa et al., "Phishing Email Curated Datasets", Zenodo 8339691, CC-BY-4.0.
ZENODO = "https://zenodo.org/api/records/8339691/files/{}/content"
# For each file: the kind of the rows with label 1.
ZENODO_FILES = {
    "Nazario.csv": "phishing", "Nazario_5.csv": "phishing",
    "Nigerian_Fraud.csv": "phishing", "Nigerian_5.csv": "phishing",
    "SpamAssasin.csv": "spam", "Enron.csv": "spam", "Ling.csv": "spam", "CEAS_08.csv": "spam",
    "TREC_05.csv": "spam", "TREC_06.csv": "spam", "TREC_07.csv": "spam",
}
# Jose Nazario's phishing corpus, CC-BY-4.0. There is one mbox file for each year.
# The Zenodo Nazario.csv has the years 2015 to 2022. Thus, we add the years after 2022.
NAZARIO = "https://monkey.org/~jose/phishing/phishing-{}"
NAZARIO_YEARS = [2023, 2024, 2025]
# Toth, Bisztray, Gruschka, PhishFuzzer, CC-BY-NC-4.0. Human seeds and LLM versions of each seed.
PHISHFUZZER = "https://raw.githubusercontent.com/DataPhish/PhishFuzzer/main/{}"
PHISHFUZZER_FILES = {
    "seed.json": "PhishFuzzer_emails_original_seed_v1.json",
    "rephrased.json": "PhishFuzzer_emails_entity_rephrased_v1.json",
}
PHISHFUZZER_KIND = {"Phishing": "phishing", "Spam": "spam", "Valid": "legit"}
# Eze and Shamir, AI-generated phishing emails. The page does not give a license.
KSU = "https://people.cs.ksu.edu/~lshamir/data/ai_phishing/AI_phishing_emails.tar.gz"
# rf-peixoto/phishing_pot, CC-BY-NC-4.0. Real phishing emails from honeypot addresses.
PHISHING_POT = "https://codeload.github.com/rf-peixoto/phishing_pot/tar.gz/refs/heads/main"

csv.field_size_limit(sys.maxsize)
parse_email = BytesParser(policy=policy.default).parsebytes


def download(url, dest):
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading {url}", flush=True)
    tmp = dest.with_suffix(".part")
    # Use curl, not urllib. The python.org Python for macOS does not include CA certificates.
    # Thus, urllib cannot verify the TLS certificate of the server.
    subprocess.run(["curl", "-fsSL", "--retry", "3", "-o", str(tmp), url], check=True)
    tmp.rename(dest)
    return dest


def html_to_text(html):
    html = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
    return unescape(re.sub(r"<[^>]+>", " ", html))


def clean(s):
    return re.sub(r"\s+", " ", s or "").strip()


def is_junk(subject, body):
    # The mail program writes these messages into the mbox file. They are not real emails.
    return "FOLDER INTERNAL DATA" in subject or (not subject and not body)


def email_fields(raw_bytes):
    """Return sender, subject and plain-text body of one raw email."""
    msg = parse_email(raw_bytes)
    part = msg.get_body(preferencelist=("plain", "html"))
    body = ""
    if part is not None:
        try:
            body = part.get_content()
        except Exception:  # Some emails have an incorrect charset or encoding.
            body = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if part.get_content_type() == "text/html":
            body = html_to_text(body)
    return str(msg["from"] or ""), str(msg["subject"] or ""), body


# Each reader yields rows: (source, kind, label, group, sender, subject, body).

def zenodo_rows():
    for name, positive_kind in ZENODO_FILES.items():
        path = download(ZENODO.format(name), RAW / "zenodo" / name)
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                label = row["label"]
                kind = positive_kind if label == "1" else "legit"
                yield path.stem, kind, label, "", row.get("sender", ""), row.get("subject", ""), row.get("body", "")


def nazario_rows():
    for year in NAZARIO_YEARS:
        path = download(NAZARIO.format(year), RAW / "nazario" / f"phishing-{year}.mbox")
        for msg in mailbox.mbox(path):
            try:
                yield (f"Nazario_{year}", "phishing", "1", "", *email_fields(msg.as_bytes()))
            except Exception as e:  # If one message is broken, do not stop the script.
                print(f"  skip a bad message in Nazario {year}: {e}", file=sys.stderr)


def phishfuzzer_rows():
    for local, remote in PHISHFUZZER_FILES.items():
        path = download(PHISHFUZZER.format(remote), RAW / "phishfuzzer" / local)
        source = "PhishFuzzer_" + ("human" if local == "seed.json" else "LLM")
        for row in json.loads(path.read_text(encoding="utf-8")):
            kind = PHISHFUZZER_KIND.get(row.get("Type"))
            if kind is None:
                continue
            label = "0" if kind == "legit" else "1"
            group = f"PhishFuzzer-{row.get('Original_ID') or row.get('No.')}"
            yield source, kind, label, group, row.get("Sender", ""), row.get("Subject", ""), row.get("Body", "")


def tar_files(path, suffix):
    """Yield the bytes of each file in a tar.gz archive. The script does not extract the files to disk."""
    with tarfile.open(path, "r:gz") as tar:
        for member in tar:
            if member.isfile() and member.name.endswith(suffix):
                yield tar.extractfile(member).read()


def ksu_rows():
    path = download(KSU, RAW / "ksu" / "AI_phishing_emails.tar.gz")
    for data in tar_files(path, ".txt"):
        text = data.decode("utf-8", "replace").strip()
        first, _, rest = text.partition("\n")
        subject = first.removeprefix("Header:") if first.startswith("Header:") else ""
        body = rest if subject else text
        yield "KSU_AI", "phishing", "1", "", "", subject, body


def phishing_pot_rows():
    path = download(PHISHING_POT, RAW / "phishing_pot" / "phishing_pot.tar.gz")
    for data in tar_files(path, ".eml"):
        try:
            yield ("phishing_pot", "phishing", "1", "", *email_fields(data))
        except Exception as e:  # If one message is broken, do not stop the script.
            print(f"  skip a bad message in phishing_pot: {e}", file=sys.stderr)


def main():
    readers = [zenodo_rows, nazario_rows, phishfuzzer_rows, ksu_rows, phishing_pot_rows]
    seen, counts = set(), {}
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["source", "kind", "label", "group", "sender", "subject", "body"])
        for reader in readers:
            for source, kind, label, group, sender, subject, body in reader():
                # Some phishing emails add many KB of random text to fool spam filters.
                # A classifier reads only the start of the body. Thus, we keep the first 20,000 characters.
                subject, body = clean(subject), clean(body)[:MAX_BODY]
                if label not in ("0", "1") or is_junk(subject, body):
                    continue
                # ponytail: This removes only exact duplicates. Emails that are almost the same stay in the data.
                key = hashlib.sha1(f"{subject}\n{body}".lower().encode()).digest()
                if key in seen:
                    continue
                seen.add(key)
                w.writerow([source, kind, label, group, clean(sender), subject, body])
                counts[(source, kind)] = counts.get((source, kind), 0) + 1

    print(f"\nwrote {OUT}")
    for (source, kind), n in sorted(counts.items()):
        print(f"  {source:<20} {kind:<9} {n:>7}")
    for kind in ("phishing", "spam", "legit"):
        print(f"  TOTAL {kind:<9} {sum(n for (_, k), n in counts.items() if k == kind):>7}")


if __name__ == "__main__":
    main()
