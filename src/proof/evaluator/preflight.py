"""Development preflight; does not claim operating-system network isolation."""
from src.generator.auto_generator import load_all_specs
from src.generator.harness_generator import HARNESS_TEMPLATES, SafeHarnessPackage


def run_preflight_checks() -> dict:
    specs = load_all_specs()
    for spec in specs:
        # Template agreement only; real target capability discovery remains a gap.
        SafeHarnessPackage(spec).negotiate_capabilities(HARNESS_TEMPLATES[spec.target_surface]['required_capabilities'])
    return {'status': 'DEVELOPMENT_ONLY', 'network_isolation': 'NOT_VERIFIED_AT_OS_LEVEL',
            'external_api_cost': 'Mock mode: zero provider calls', 'specs_count': len(specs),
            'release_blockers': ['Unverified source catalog', 'Target capability discovery missing',
                                 'Container isolation missing', 'Independent completion assertions incomplete']}


if __name__ == '__main__':
    import json
    print(json.dumps(run_preflight_checks(), indent=2))
