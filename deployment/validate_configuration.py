"""Validate deployment inputs before docker compose. Does not expose secrets."""
import json
import os
import re
from pathlib import Path


def validate(environment):
    image = environment.get('SCENARIO_IMAGE', '')
    if not re.fullmatch(r'[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}', image):
        raise ValueError('SCENARIO_IMAGE must be pinned by a sha256 image digest')
    required = ('GATEWAY_POLICY_PATH', 'GATEWAY_RECEIPTS_PATH', 'PACKAGES_PATH',
                'TRIAL_OUTPUT_PATH', 'PROVIDER_KEY_PATH', 'GATEWAY_TOKEN_PATH')
    paths = {}
    for key in required:
        path = Path(environment.get(key, ''))
        if not environment.get(key) or not path.is_absolute() or not path.exists():
            raise ValueError(f'{key} must name an existing absolute path')
        paths[key] = path.resolve()
    for file_key in ('GATEWAY_POLICY_PATH', 'PROVIDER_KEY_PATH', 'GATEWAY_TOKEN_PATH'):
        if not paths[file_key].is_file(): raise ValueError(f'{file_key} must be a file')
    for dir_key in ('GATEWAY_RECEIPTS_PATH', 'PACKAGES_PATH', 'TRIAL_OUTPUT_PATH'):
        if not paths[dir_key].is_dir(): raise ValueError(f'{dir_key} must be a directory')
    for secret_key in ('PROVIDER_KEY_PATH', 'GATEWAY_TOKEN_PATH'):
        if paths[secret_key].is_relative_to(paths['PACKAGES_PATH']) or paths[secret_key].is_relative_to(paths['TRIAL_OUTPUT_PATH']):
            raise ValueError('Credentials must not be inside mounted packages or trial outputs')
    if any(paths['GATEWAY_RECEIPTS_PATH'].iterdir()):
        raise ValueError('Gateway receipt directory must be new; never discard previous session receipts')
    policy = json.loads(paths['GATEWAY_POLICY_PATH'].read_text())
    if policy.get('review', {}).get('status') != 'approved' or not policy.get('models'):
        raise ValueError('A reviewed model/pricing policy is required')
    return {'image': image, 'configuration_validated': True,
            'runtime_network_isolation_verified': False}


if __name__ == '__main__':
    print(json.dumps(validate(os.environ), indent=2))
