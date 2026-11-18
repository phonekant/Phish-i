import json
import urllib.request
from pathlib import Path

DISCONNECT_URL = "https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json"

# Maps raw Disconnect categories to UI-friendly labels and plain-language explanations
CATEGORY_METADATA = {
    "Advertising": {
        "label": "Advertising",
        "explanation": "Tracks your visits across websites to build an ad profile."
    },
    "Analytics": {
        "label": "Analytics",
        "explanation": "Records which pages you visit and what you click on."
    },
    "FingerprintingInvasive": {
        "label": "Fingerprinting",
        "explanation": "Identifies your specific device and browser settings without cookies."
    },
    "FingerprintingGeneral": {
        "label": "Fingerprinting",
        "explanation": "Collects device details that can be used to track you across sites."
    },
    "Cryptomining": {
        "label": "Cryptomining",
        "explanation": "Uses your computer's processing power without permission."
    },
    "Social": {
        "label": "Social Tracking",
        "explanation": "Lets social media networks see which websites you visit."
    }
}

MAX_RULES = 2500
TRACKING_PARAMS = [
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "mc_cid", "mc_eid"
]


def fetch_disconnect_list(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "Phish-i-RuleBuilder/1.0"})
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def build_artifacts(raw_data: dict, max_rules: int = MAX_RULES):
    categories = raw_data.get("categories", {})
    seen_domains = set()
    dnr_rules = []
    entity_map = {}
    rule_id = 1

    # Rule 1: Strip cross-site tracking query parameters
    dnr_rules.append({
        "id": rule_id,
        "priority": 2,
        "action": {
            "type": "redirect",
            "redirect": {
                "transform": {
                    "queryTransform": {
                        "removeParams": TRACKING_PARAMS
                    }
                }
            }
        },
        "condition": {
            "urlFilter": "*",
            "resourceTypes": ["main_frame"]
        }
    })
    rule_id += 1

    for raw_cat, meta in CATEGORY_METADATA.items():
        entities = categories.get(raw_cat, [])
        for entity_block in entities:
            if rule_id > max_rules:
                break

            for entity_name, site_dict in entity_block.items():
                if not isinstance(site_dict, dict):
                    continue

                for primary_url, domains in site_dict.items():
                    if not isinstance(domains, list):
                        continue

                    for domain in domains:
                        clean_domain = domain.lower().strip().lstrip(".")
                        if not clean_domain or clean_domain in seen_domains:
                            continue
                        if rule_id > max_rules:
                            break

                        seen_domains.add(clean_domain)

                        entity_map[clean_domain] = {
                            "entity": entity_name,
                            "category": meta["label"],
                            "explanation": meta["explanation"]
                        }

                        dnr_rules.append({
                            "id": rule_id,
                            "priority": 1,
                            "action": {"type": "block"},
                            "condition": {
                                "urlFilter": f"||{clean_domain}^",
                                "domainType": "thirdParty",
                                "resourceTypes": [
                                    "script",
                                    "xmlhttprequest",
                                    "image",
                                    "sub_frame",
                                    "ping",
                                    "other"
                                ]
                            }
                        })
                        rule_id += 1

    return dnr_rules, entity_map


def main():
    raw_data = fetch_disconnect_list(DISCONNECT_URL)
    dnr_rules, entity_map = build_artifacts(raw_data)

    Path("rules").mkdir(exist_ok=True)
    Path("data").mkdir(exist_ok=True)

    with Path("rules/tracker_rules.json").open("w", encoding="utf-8") as f:
        json.dump(dnr_rules, f, indent=2)

    with Path("data/entity_map.json").open("w", encoding="utf-8") as f:
        json.dump(entity_map, f, indent=2)

    print(f"Generated {len(dnr_rules)} DNR rules and {len(entity_map)} entity mappings.")


if __name__ == "__main__":
    main()