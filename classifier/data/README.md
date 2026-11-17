# Email datasets for the phishing classifier

The merged dataset is too large for git so it is not in the repository.

To make the dataset:

1. Go to the root folder of the repository.
2. Run this command:

```bash
python3 classifier/data/fetch_datasets.py
```

The script uses only the Python standard library and `curl`. It downloads approximately 1.5 GB into `classifier/data/raw/`. Git ignores this folder. The script writes the result to `classifier/data/emails.csv` (approximately 430 MB).

If you run the script again, it does not download the files that are already in `raw/`.

**Safety:** Some of the emails are real phishing emails. They can contain dangerous links and attachments. The script reads the emails as text only. It does not write or open the attachments. Do not open the links in the dataset.

## Columns in `emails.csv`

| Column  | Description |
|---------|-------------|
| source  | The corpus that the row comes from, for example `Enron` or `phishing_pot`. |
| kind    | `phishing`, `spam` or `legit`. |
| label   | `1` is phishing or spam. `0` is legit. |
| group   | Rows with the same group are versions of one email. Keep these rows in the same split. Only PhishFuzzer rows have a group. |
| sender  | The "From" header. Some corpora do not have this header. Then the cell is empty. |
| subject | The subject line. |
| body    | The body in plain text, with a maximum of 20,000 characters. |

The script removes these rows:

- Rows that have the same subject and body as a previous row.
- Rows with the subject "FOLDER INTERNAL DATA". The mail program makes these rows. They are not real emails.

## Sources

| Corpus | Contents | License |
|--------|----------|---------|
| [Phishing Email Curated Datasets](https://zenodo.org/records/8339691) (Champa et al.) | Nazario 2015-2022, Nigerian Fraud, SpamAssassin, Enron, Ling-Spam, CEAS 2008, TREC 2005-2007 | CC-BY-4.0 |
| [Nazario phishing corpus](https://monkey.org/~jose/phishing/) (Jose Nazario) | Phishing emails from 2023, 2024 and 2025 | CC-BY-4.0 |
| [phishing_pot](https://github.com/rf-peixoto/phishing_pot) (rf-peixoto) | Real phishing emails from honeypot addresses. The maintainer adds new emails frequently. | CC-BY-NC-4.0 |
| [PhishFuzzer](https://github.com/DataPhish/PhishFuzzer) (Toth, Bisztray, Gruschka) | Phishing, spam and legit emails from 2002 to 2026. It has human emails and LLM versions of each email. | CC-BY-NC-4.0 |
| [AI-generated phishing emails](https://people.cs.ksu.edu/~lshamir/data/ai_phishing/) (Eze and Shamir, 2024) | Phishing emails that an LLM wrote | Not stated |

## Number of rows

| Source | Phishing | Spam | Legit |
|--------|---------:|-----:|------:|
| phishing_pot | 10,687 | | |
| PhishFuzzer_LLM | 6,756 | 6,444 | 6,600 |
| PhishFuzzer_human | 877 | 1,007 | 253 |
| Nigerian_Fraud | 3,291 | | |
| Nazario | 1,550 | | |
| Nazario_2023 / 2024 / 2025 | 393 / 378 / 448 | | |
| KSU_AI | 713 | | |
| CEAS_08 | | 21,674 | 16,689 |
| Enron | | 13,948 | 15,474 |
| Ling | | 458 | 2,401 |
| SpamAssasin | | 1,712 | 3,490 |
| TREC_05 | | 22,821 | 31,640 |
| TREC_06 | | 3,974 | 11,783 |
| TREC_07 | | 29,112 | 23,744 |
| Nazario_5 / Nigerian_5 | | | 1,498 / 1,664 |
| **Total** | **25,093** | **101,150** | **115,236** |

## Separate test set

From the root folder, download the test set and make `classifier/data/benchmark.csv`:

```bash
python3 classifier/data/fetch_benchmark.py
```

The script uses Python and `curl`. It checks the downloaded files against fixed checksums.
The output has the same columns as `emails.csv`. The `sender` and `subject` fields are empty because the source supplies message text only.
Keep all of `benchmark.csv` out of training and threshold selection.

| Source | Phishing | Legit |
|--------|---------:|------:|
| `Validation_v3_generated` | 977 | 923 |
| `Validation_v3_original` | 23 | 77 |
| **Total** | **1,000** | **1,000** |

The generated rows use 52 templates. The `group` field identifies the template.
The authors report that the 100 original rows come from email and SMS. 

Source credit goes to Radoslav Miltchev, Dimitar Rangelov and Evgeni Genchev (2026), CC BY 4.0. The script changes the column names and normalizes whitespace. [Phishing Validation Emails Dataset v3](https://doi.org/10.5281/zenodo.23954793)
