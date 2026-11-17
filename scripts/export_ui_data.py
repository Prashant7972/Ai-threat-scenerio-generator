"""Export authoritative benchmark, scenario, corpus, and gate data for the web UI."""
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
if str(root) not in sys.path:
    sys.path.insert(0, str(root))

from src.generator.auto_generator import compile_all_scenarios
from src.proof.proxy import PRICING_REGISTRY


def export_ui_data(root: Path | None = None):
    root = root or Path(__file__).resolve().parent.parent
    gate_path = root / 'reports' / 'release_gate_mock_harness.json'
    if not gate_path.exists():
        gate_path = root / 'reports' / 'release_gate.json'
    gate = json.loads(gate_path.read_text()) if gate_path.exists() else {}

    scenarios = [s.model_dump(mode='json') for s in compile_all_scenarios()]
    corpus_file = root / 'data' / 'litmus' / 'litmus_360.jsonl'
    corpus = []
    if corpus_file.exists():
        with open(corpus_file, encoding='utf-8') as f:
            corpus = [json.loads(line) for line in f]

    # Find latest trial manifests to populate sample manifests
    runs_dir = root / 'reports' / 'runs'
    manifests = {}
    if runs_dir.exists():
        run_dirs = sorted([d for d in runs_dir.iterdir() if d.is_dir()], key=lambda d: d.stat().st_mtime, reverse=True)
        for rd in run_dirs:
            mdir = rd / 'trial_manifests'
            if mdir.exists():
                for p in sorted(mdir.glob('*.json'))[:30]:
                    manifests[p.name] = json.loads(p.read_text())
                if manifests:
                    break

    data = {
        'gate': gate,
        'scenarios': scenarios,
        'corpus_summary': {
            'total': len(corpus),
            'attacks': len([r for r in corpus if r.get('record_type') == 'attacker_injection']),
            'benigns': len([r for r in corpus if 'benign' in str(r.get('record_type')) or 'legitimate' in str(r.get('record_type'))]),
            'canonical': len([r for r in corpus if r.get('split') == 'canonical']),
        },
        'corpus': corpus,
        'manifests': manifests,
        'pricing': PRICING_REGISTRY
    }

    json_str = json.dumps(data, indent=2)
    (root / 'ui' / 'data.json').write_text(json_str, encoding='utf-8')
    with open(root / 'ui' / 'data.js', 'w', encoding='utf-8') as f:
        f.write('window.CONSOLE_DATA = ' + json_str + ';\n')
        f.write('window.BENCHMARK_DATA = window.CONSOLE_DATA;\n')
        f.write('window.ATLAS_DATA = window.CONSOLE_DATA;\n')

    print(f'Exported ui/data.json and ui/data.js: {len(corpus)} corpus items, {len(scenarios)} specs, {len(manifests)} sample manifests')

if __name__ == '__main__':
    export_ui_data()
