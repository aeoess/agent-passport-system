#!/usr/bin/env python3
"""Generate PDF from monotonic narrowing paper markdown."""
import markdown
import subprocess
import os

INPUT = "/Users/tima/agent-passport-system/papers/monotonic-narrowing.md"
OUTPUT = "/Users/tima/agent-passport-system/papers/monotonic-narrowing.pdf"

with open(INPUT, 'r') as f:
    md_content = f.read()

html = markdown.markdown(md_content, extensions=[
    'tables', 'fenced_code', 'toc', 'smarty'
])

full_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
@page {{ size: letter; margin: 1in; }}
body {{
    font-family: 'Georgia', 'Times New Roman', serif;
    font-size: 11pt; line-height: 1.6; color: #1a1a1a;
    max-width: 7in; margin: 0 auto; padding: 0;
}}
h1 {{ font-size: 18pt; text-align: center; margin-top: 0.5in; margin-bottom: 0.3in; line-height: 1.3; }}
h2 {{ font-size: 14pt; margin-top: 1.5em; margin-bottom: 0.5em; border-bottom: 1px solid #ccc; padding-bottom: 0.2em; }}
h3 {{ font-size: 12pt; margin-top: 1.2em; margin-bottom: 0.4em; }}
p {{ margin: 0.5em 0; text-align: justify; }}
strong {{ font-weight: bold; }}
em {{ font-style: italic; }}
code {{ font-family: 'Menlo', 'Monaco', monospace; font-size: 9pt; background: #f5f5f5; padding: 2px 4px; border-radius: 3px; }}
pre {{ background: #f5f5f5; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 8.5pt; line-height: 1.4; border: 1px solid #e0e0e0; }}
pre code {{ background: none; padding: 0; }}
table {{ border-collapse: collapse; width: 100%; margin: 1em 0; font-size: 9pt; }}
th, td {{ border: 1px solid #ccc; padding: 6px 8px; text-align: left; }}
th {{ background: #f0f0f0; font-weight: bold; }}
hr {{ border: none; border-top: 1px solid #ccc; margin: 1.5em 0; }}
blockquote {{ border-left: 3px solid #ccc; margin-left: 0; padding-left: 1em; color: #555; }}
ol, ul {{ margin: 0.5em 0; padding-left: 1.5em; }}
li {{ margin: 0.3em 0; }}
body > p:first-of-type {{ text-align: center; font-size: 13pt; }}
body > p:nth-of-type(2) {{ text-align: center; font-size: 10pt; color: #555; }}
body > p:nth-of-type(3) {{ text-align: center; font-style: italic; font-size: 10pt; color: #666; }}
</style>
</head>
<body>
{html}
</body>
</html>"""

html_path = OUTPUT.replace('.pdf', '.html')
with open(html_path, 'w') as f:
    f.write(full_html)

chrome_paths = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
]
chrome = None
for p in chrome_paths:
    if os.path.exists(p):
        chrome = p
        break

if chrome:
    subprocess.run([
        chrome, "--headless", "--disable-gpu",
        "--print-to-pdf=" + OUTPUT,
        "--no-pdf-header-footer",
        html_path
    ], check=True, timeout=30)
    print(f"PDF generated: {OUTPUT}")
else:
    print(f"Chrome not found. HTML saved: {html_path}")

print(f"Words: {len(md_content.split())}")
print(f"Lines: {len(md_content.splitlines())}")
