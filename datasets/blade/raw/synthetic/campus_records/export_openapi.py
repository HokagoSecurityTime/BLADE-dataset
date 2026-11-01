import urllib.request
from pathlib import Path
Path("openapi.json").write_bytes(urllib.request.urlopen("http://localhost:18084/v3/api-docs").read())
