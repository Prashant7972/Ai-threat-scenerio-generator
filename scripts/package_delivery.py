"""Package source and retained evidence without credentials, caches or Git metadata."""
import hashlib
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT.parent / 'ai-threat-scenario-generator-release-candidate.zip'
INCLUDE = {'src','tests','docs','data','specs','reports','config','deployment','ui','scripts'}
ROOT_FILES = {'README.md','DELIVERY_STATUS.md','requirements.txt','pytest.ini'}
EXCLUDE = {'__pycache__','node_modules','.venv','venv','.git','.pytest_cache','secrets'}
files = []
for path in sorted(ROOT.rglob('*')):
    rel = path.relative_to(ROOT)
    if not path.is_file() or path.is_symlink(): continue
    if rel.parts[0] not in INCLUDE and str(rel) not in ROOT_FILES: continue
    if any(part in EXCLUDE or part.startswith('.env') for part in rel.parts): continue
    if path.suffix in {'.pyc','.pyo','.pem','.key'}: continue
    raw = path.read_bytes()
    # Abort without printing potential credentials.
    if re.search(rb'AIza[0-9A-Za-z_-]{35}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', raw):
        raise RuntimeError('Credential-like material detected; inspect locally before packaging')
    files.append((rel.as_posix(), raw))
manifest = {'delivery_status':'development_candidate_not_client_accepted',
            'files':{name:hashlib.sha256(raw).hexdigest() for name,raw in files}}
with zipfile.ZipFile(OUTPUT, 'w', zipfile.ZIP_DEFLATED) as archive:
    for name, raw in files:
        archive.writestr('ai-threat-scenario-generator/' + name, raw)
    archive.writestr('ai-threat-scenario-generator/PACKAGE_MANIFEST.json', json.dumps(manifest,indent=2)+'\n')
with zipfile.ZipFile(OUTPUT) as archive:
    assert archive.testzip() is None
    for name, expected in manifest['files'].items():
        assert hashlib.sha256(archive.read('ai-threat-scenario-generator/'+name)).hexdigest() == expected
print(json.dumps({'archive':str(OUTPUT),'files':len(files)+1,'bytes':OUTPUT.stat().st_size,
                  'sha256':hashlib.sha256(OUTPUT.read_bytes()).hexdigest()}))
