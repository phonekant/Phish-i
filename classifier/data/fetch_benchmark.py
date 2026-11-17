"""Download the Phishing Validation Emails v3 test set and make benchmark.csv."""

import csv
import hashlib
from collections import Counter
from pathlib import Path
from tempfile import NamedTemporaryFile

from fetch_datasets import HERE, RAW, clean, download

RECORD = "https://zenodo.org/api/records/23954793/files/{}/content"
MESSAGES = "Phishing_validation_emails_v3.csv"
METADATA = "phishing_v3_metadata.csv"
CHECKSUMS = {
    MESSAGES: "d09536161bc6d0e94c98f6c9bb24c0c2898ba94bf28eed8f89367297276eb320",
    METADATA: "f1c10cd1dce580c7877ca450a2069007c561781b8d408da07ccd756f07a16732",
}
KINDS = {"Safe Email": "legit", "Phishing Email": "phishing"}
SOURCES = {
    "original_v1": "Validation_v3_original",
    "generated_v3": "Validation_v3_generated",
}
OUTPUT = HERE / "benchmark.csv"


def read_source(filename):
    path = download(RECORD.format(filename), RAW / "validation" / filename)
    if hashlib.sha256(path.read_bytes()).hexdigest() != CHECKSUMS[filename]:
        raise ValueError(f"Checksum error. Delete {path} and run this script again.")
    with path.open(encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


def main():
    messages = read_source(MESSAGES)
    metadata = read_source(METADATA)
    rows = []
    counts = Counter()
    for index, (message, info) in enumerate(zip(messages, metadata, strict=True), 1):
        email_type = message["Email Type"]
        if info["record_id"] != str(index) or info["email_type"] != email_type:
            raise ValueError(f"Metadata does not agree with message {index}.")
        kind = KINDS[email_type]
        category = info["source_category"]
        source = SOURCES[category]
        group = f"original-{index}" if category == "original_v1" else info["template_id"]
        rows.append((source, kind, int(kind == "phishing"), group, "", "",
                     clean(message["Email Text"])))
        counts[source, kind] += 1

    file = NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="", dir=HERE, delete=False
    )
    temporary = Path(file.name)
    try:
        with file:
            writer = csv.writer(file)
            writer.writerow(["source", "kind", "label", "group", "sender", "subject", "body"])
            writer.writerows(rows)
        temporary.replace(OUTPUT)
    finally:
        temporary.unlink(missing_ok=True)

    print(f"Wrote {len(rows)} rows to {OUTPUT}")
    for (source, kind), count in sorted(counts.items()):
        print(f"  {source} {kind}: {count}")


if __name__ == "__main__":
    main()
