"""Trial-side model adapter. No provider credential or arbitrary egress URL."""
import json
from decimal import Decimal

from src.generator.contract import NetworkRequestRecord

from .proxy import LiveModelProxy, SecurityException


class GatewayTransport:
    def __init__(self, model, token, policy):
        self.model, self.token, self.policy = model, token, policy
        self.requests_logged = []
        self.unauthorized_egress_attempts = 0

    def request(self, method, url, headers=None, data=None, timeout=30):
        import hashlib
        import os
        import time

        import httpx

        from .inference_gateway import verify_gateway_signature

        expected = f'https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent'
        if method != 'POST' or url != expected:
            self.unauthorized_egress_attempts += 1
            raise SecurityException('Gateway adapter rejected unsupported upstream operation')
        start = time.monotonic()
        endpoint = os.environ.get('GATEWAY_ENDPOINT') or os.environ.get('GATEWAY_URL') or 'http://inference-proxy:8080/generate'
        encoded_data = json.dumps(data, ensure_ascii=False).encode()
        expected_req_sha = hashlib.sha256(encoded_data).hexdigest()

        with httpx.Client(follow_redirects=False, trust_env=False, timeout=timeout) as client:
            response = client.post(endpoint, headers={'Authorization': 'Bearer ' + self.token},
                                   json={'model': self.model, 'payload': data})
        record = NetworkRequestRecord(destination_host='inference-proxy', destination_port=8080,
            method='POST', status_code=response.status_code, latency_ms=(time.monotonic()-start)*1000,
            request_bytes=len(encoded_data), response_bytes=len(response.content), sanitized_url=endpoint)
        self.requests_logged.append(record)
        if response.status_code != 200:
            return {'status_code': response.status_code, 'text': '{}', 'record': record}
        body = response.json()
        receipt = body.get('receipt')
        if not receipt:
            raise SecurityException('Gateway response missing receipt')
        policy_hash = hashlib.sha256(json.dumps(self.policy, sort_keys=True).encode()).hexdigest()
        if receipt.get('policy_sha256') != policy_hash or receipt.get('model') != self.model:
            raise SecurityException('Gateway policy or model differs from preflight policy')
        if receipt.get('request_sha256') != expected_req_sha:
            raise SecurityException(
                f"Gateway receipt request hash mismatch: expected {expected_req_sha}, got {receipt.get('request_sha256')}"
            )
        if not verify_gateway_signature(self.token, receipt):
            raise SecurityException('Gateway receipt HMAC signature verification failed: signature altered or forged')
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
        total_tok = num_trials * avg_tokens
        in_tok = total_tok * 0.75
        out_tok = total_tok * 0.25
        expected = (Decimal(str(in_tok)) / 1_000_000 * Decimal(str(rates['input_per_million']))) + (
            Decimal(str(out_tok)) / 1_000_000 * Decimal(str(rates['output_per_million']))
        )
        return {
            'provider': self.model_id,
            'mode': 'live_gateway',
            'trials': num_trials,
            'upper_bound_cost_usd': str(bound),
            'expected_cost_usd': str(round(expected, 4)),
            'max_trial_tokens': 20000,
            'approved_session_cap_usd': self.policy['max_cost_usd'],
            'pricing_checked_at': rates['verified_date'],
        }
