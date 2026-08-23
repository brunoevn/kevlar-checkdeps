#!/usr/bin/env python
"""
Helper utility to pack assets/report_template.html into the compressed
_HTML_TEMPLATE_GZIP_B64 constant inside kevlar.py.
"""
import base64
import gzip
import os
import re
import sys

def pack():
    template_path = os.path.join(os.path.dirname(__file__), "..", "assets", "report_template.html")
    kevlar_path = os.path.join(os.path.dirname(__file__), "..", "kevlar.py")

    if not os.path.exists(template_path):
        print(f"Error: Template not found at {template_path}")
        sys.exit(1)

    with open(template_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    compressed = gzip.compress(html_content.encode("utf-8"), compresslevel=9)
    b64_encoded = base64.b64encode(compressed).decode("ascii")

    chunk_size = 100
    chunks = [b64_encoded[i:i+chunk_size] for i in range(0, len(b64_encoded), chunk_size)]
    formatted_b64 = "(\n" + "\n".join([f'    "{c}"' for c in chunks]) + "\n)"

    with open(kevlar_path, "r", encoding="utf-8") as f:
        kevlar_code = f.read()

    pattern = r'_HTML_TEMPLATE_GZIP_B64\s*=\s*\([^\)]+\)'
    if re.search(pattern, kevlar_code):
        new_code = re.sub(pattern, f"_HTML_TEMPLATE_GZIP_B64 = {formatted_b64}", kevlar_code)
        with open(kevlar_path, "w", encoding="utf-8") as f:
            f.write(new_code)
        print(f"Successfully updated _HTML_TEMPLATE_GZIP_B64 in kevlar.py ({len(b64_encoded)} chars, {len(compressed)} compressed bytes)")
    else:
        print("Could not find _HTML_TEMPLATE_GZIP_B64 constant in kevlar.py to update.")

if __name__ == "__main__":
    pack()
