# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Dev-server entry point: honors $PORT (used by the preview pane)."""
import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1",
                port=int(os.environ.get("PORT", "8787")),
                app_dir=os.path.dirname(os.path.abspath(__file__)))
