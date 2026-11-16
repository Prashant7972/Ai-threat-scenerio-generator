"""Trial-side model adapter. No provider credential or arbitrary egress URL."""
from pathlib import Path
import json
from urllib.parse import urlparse
from decimal import Decimal
from .proxy import LiveModelProxy, SecurityException
from src.generator.contract import NetworkRequestRecord


class GatewayTransport:
    def __init__(self, model, token, policy):
        self.model, self.token, self.policy = model, token, policy
        self.requests_logged = []
        self.unauthorized_egress_attempts = 0

    def request(self, method, url, headers=None, data=None, timeout=30):
        import httpx
        import hashlib
        import time
        expected = f'https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent'
        if method != 'POST' or url != expected:
            self.unauthorized_egress_attempts += 1
            raise SecurityException('Gateway adapter rejected unsupported upstream operation')
        start = time.monotonic()
        endpoint = 'http://inference-proxy:8080/generate'
        with httpx.Client(follow_redirects=False, trust_env=False, timeout=timeout) as client:
            response = client.post(endpoint, headers={'Authorization': 'Bearer ' + self.token},
                                   json={'model': self.model, 'payload': data})
        record = NetworkRequestRecord(destination_host='inference-proxy', destination_port=8080,
            method='POST', status_code=response.status_code, latency_ms=(time.monotonic()-start)*1000,
            request_bytes=len(json.dumps(data).encode()), response_bytes=len(response.content), sanitized_url=endpoint)
        self.requests_logged.append(record)
        if response.status_code != 200:
            return {'status_code': response.status_code, 'text': '{}', 'record': record}
        body = response.json()
        receipt = body['receipt']
        policy_hash = hashlib.sha256(json.dumps(self.policy, sort_keys=True).encode()).hexdigest()
        if receipt.get('policy_sha256') != policy_hash or receipt.get('model') != self.model:
            raise SecurityException('Gateway policy or model differs from preflight policy')
        return {'status_code': 200, 'text': json.dumps(body['response']), 'record': record, 'gateway_receipt': receipt}


class GatewayModelProxy(LiveModelProxy):
    def __init__(self, policy, model, token):
        if policy.get('review', {}).get('status') != 'approved' or not policy.get('review', {}).get('reviewer'):
            raise ValueError('Gateway policy must be reviewed')
        if model not in policy.get('models', {}): raise ValueError('Model is not in reviewed policy')
        self.policy = policy
        self.model_id = model
        self.api_key = 'managed-by-isolated-gateway'
        rates = policy['models'][model]
        self.provider_info = {'default_host': 'generativelanguage.googleapis.com', 'default_port': 443,
            'input_per_million': rates['input_per_million_usd'], 'output_per_million': rates['output_per_million_usd'],
            'verified_date': rates['pricing_checked_at']}
        self.transport = GatewayTransport(model, token, policy)

    def estimate_cost(self, num_trials, avg_tokens=1500):
        rates = self.provider_info
        bound = Decimal(str(max(rates['input_per_million'], rates['output_per_million']))) * 20000 * num_trials / 1_000_000
        return {'provider': self.model_id, 'mode': 'live_gateway', 'trials': num_trials,
                'upper_bound_cost_usd': str(bound), 'max_trial_tokens': 20000,
                'approved_session_cap_usd': self.policy['max_cost_usd'],
                'pricing_checked_at': rates['verified_date']}
