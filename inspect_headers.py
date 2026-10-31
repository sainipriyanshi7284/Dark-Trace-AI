import json
import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('threat_classifier_v2.ipynb', 'r', encoding='utf-8') as f:
    nb = json.load(f)

for idx, cell in enumerate(nb['cells']):
    if cell['cell_type'] == 'markdown':
        src = ''.join(cell.get('source', []))
        for line in src.split('\n'):
            if line.startswith('#'):
                print(f"Cell {idx:2d}: {line}")

