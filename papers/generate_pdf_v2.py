#!/usr/bin/env python3
"""Generate PDF from paper v2 markdown."""
import markdown
import subprocess
import os
import tempfile

INPUT = "/Users/tima/agent-passport-system/papers/monotonic-narrowing-v2.md"
OUTPUT = "/Users/tima/agent-passport-system/papers/monotonic-narrowing-v2.pdf"

with open(INPUT, 'r') as f:
    md = f.read()

html = markdown.markdown(md, extensions=['tables', 'fenced_code'])
full = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
body {{ font-family: Georgia, serif; max-width: 750px; margin: 40px auto; padding: 0 20px; line-height: 1.6; color: #222; font-size: 11pt; }}
h1 {{ font-size: 18pt; text-align: center; margin-top: 30px; }}
h2 {{ font-size: 14pt; border-bottom: 1px solid #ccc; padding-bottom: 5px; margin-top: 25px; }}
h3 {{ font-size: 12pt; margin-top: 20px; }}
pre {{ background: #f5f5f5; padding: 10px; border-radius: 4px; font-size: 9pt; }}
code {{ background: #f0f0f0; padding: 2px 5px; border-radius: 3px; font-size: 9.5pt; }}
table {{ border-collapse: collapse; width: 100%; margin: 15px 0; font-size: 10pt; }}
th, td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: left; }}
th {{ background: #f5f5f5; }}
@page {{ size: letter; margin: 1in; }}
</style></head><body>{html}</body></html>"""

tmp = tempfile.NamedTemporaryFile(suffix='.html', delete=False)
tmp.write(full.encode())
tmp.close()

# Use Chrome headless to generate PDF
r = subprocess.run([
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '--headless', '--disable-gpu', '--no-sandbox',
    f'--print-to-pdf={OUTPUT}',
    '--print-to-pdf-no-header',
    f'file://{tmp.name}'
], capture_output=True, text=True, timeout=30)

os.unlink(tmp.name)
if os.path.exists(OUTPUT):
    print(f"PDF: {OUTPUT} ({os.path.getsize(OUTPUT)} bytes)")
else:
    print(f"Chrome failed: {r.stderr[:200]}")
    # Fallback: try weasyprint
    try:
        from weasyprint import HTML
        HTML(string=full).write_pdf(OUTPUT)
        print(f"PDF (weasyprint): {OUTPUT} ({os.path.getsize(OUTPUT)} bytes)")
    except:
        print("Both Chrome and weasyprint failed")
