#!/usr/bin/python3

import subprocess
import shutil
import sys
import os

JSDOC_CONFIG = os.path.join(os.getcwd(), "docs/apidoc.json")
DOCS_DIR = os.path.join(os.getcwd(), "html")

try:
    print("🗑️ Deleting html folder...")
    shutil.rmtree(DOCS_DIR, ignore_errors=True)
    print("🚀 Generating JSDoc...")
    subprocess.run(["pnpm", "exec", "jsdoc", "-c", JSDOC_CONFIG], check=True)
except subprocess.CalledProcessError as e:
    print("❌ Error generating JSDoc:", e)
    sys.exit(1)
