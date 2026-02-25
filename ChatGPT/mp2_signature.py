import json
import os


# 🔹 Load rules from JSON
def load_rules(json_path="mp2_rules.json"):
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"{json_path} not found.")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rules = []

    for rule in data["rules"]:
        extension = rule["extension"]
        size_min = rule.get("size_min")
        size_max = rule.get("size_max")

        for magic in rule["magic"]:
            magic_bytes = bytes.fromhex(magic)

            rules.append({
                "extension": extension,
                "magic": magic_bytes,
                "length": len(magic_bytes),
                "size_min": size_min,
                "size_max": size_max
            })

    rules.sort(key=lambda x: x["length"], reverse=True)

    return rules


# 🔹 Load rules once globally
RULES = load_rules()


# 🔹 Main detection function
def detect_file_type(data, file_size=None):

    if not data:
        return "Unknown"

    # 1️⃣ Check JSON rules (longest match first)
    for rule in RULES:
        if data.startswith(rule["magic"]):

            size_min = rule.get("size_min")
            size_max = rule.get("size_max")

            if file_size is not None:
                if size_min is not None and file_size < size_min - 50:
                    continue

                if size_max is not None and file_size > size_max + 50:
                    continue

            return rule["extension"]

    return "Unknown"