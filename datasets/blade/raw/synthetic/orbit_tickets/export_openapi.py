import json
from app import app
from pathlib import Path
Path("openapi.json").write_text(json.dumps(app.openapi(),indent=2))
