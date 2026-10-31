import json
import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('threat_classifier_v2.ipynb', 'r', encoding='utf-8') as f:
    nb = json.load(f)

for idx, cell in enumerate(nb['cells']):
    src = ''.join(cell.get('source', []))
    if 'comparison_report_df' in src or 'RESULTS[' in src:
        print(f"=== Cell index {idx}, id={cell.get('id')}, exec_count={cell.get('execution_co