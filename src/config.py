import json

def load_signature_rules(file_path):
    with open(file_path, 'r') as f:
        rules = json.load(f)
    return rules


