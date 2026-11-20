"""Separately deployable Gemini gateway with exact model allowlist and spend cap.

No arbitrary upstream URL, forwarding headers, provider tools, code execution,
redirects, or environment HTTP proxies are accepted. Provider credentials stay
in this process. This service must be deployed behind an internal-only network.
"""
import hashlib
import hmac
import json
import os
import re
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock

MAX_BODY_BYTES = 1_000_000


def compute_gateway_signature(client_token: str, receipt: dict) -> str:
    sig_msg = (
        f"{receipt.get('attempt_id')}:{receipt.get('policy_sha256')}:{receipt.get('request_sha256')}:"
        f"{receipt.get('model')}:{receipt.get('started_at')}:{receipt.get('status')}:{receipt.get('actual_cost_usd')}:"
        f"{receipt.get('provider_contacted')}:{receipt.get('upstream_transport')}"
    )
    return hmac.new(client_token.encode(), sig_msg.encode(), hashlib.sha256).hexdigest()


def verify_gateway_signature(client_token: str, receipt: dict) -> bool:
    sig = receipt.get('gateway_signature')
    if not sig or not isinstance(sig, str) or len(sig) != 64:
        return False
    expected = compute_gateway_signature(client_token, receipt)
    return hmac.compare_digest(sig, expected)


class GatewayRejected(ValueError): pass


class InferenceGateway:
    def __init__(self, policy: dict, api_key: str, client_token: str, receipts: Path, sender=None):
        if policy.get('provider') != 'google_gemini' or not re.fullmatch(r'[A-Za-z0-9_.-]+', policy.get('version', '')):
            raise GatewayRejected('Unsupported or unversioned provider policy')
        if policy.get('review', {}).get('status') != 'approved' or not policy.get('review', {}).get('reviewer'):
            raise GatewayRejected('Provider policy requires explicit review')
        if not policy.get('models') or not api_key or len(client_token) < 32:
            raise GatewayRejected('Missing models, provider credential or client token')
        for model, rates in policy['models'].items():
            if not re.fullmatch(r'[a-zA-Z0-9_.-]+', model): raise GatewayRejected('Invalid model identifier')
            for field in ('input_per_million_usd', 'output_per_million_usd'):
                rate = Decimal(str(rates[field]))
                if not rate.is_finite() or rate < 0: raise GatewayRejected('Invalid price')
            if not rates.get('pricing_source') or not rates.get('pricing_checked_at'):
                raise GatewayRejected('Pricing provenance is required')
        self.cap = Decimal(str(policy['max_cost_usd']))
        if not self.cap.is_finite() or self.cap <= 0: raise GatewayRejected('Invalid spend cap')
        self.policy, self.api_key, self.client_token = policy, api_key, client_token
        self.receipts = receipts
        self.receipts.mkdir(parents=True, exist_ok=True)
        # A budget session cannot restart and forget past charges.
        if any(self.receipts.iterdir()): raise GatewayRejected('Use a fresh budget session directory; previous receipts must be reconciled')
        self.spent = Decimal(0)
        self.lock = Lock()
        self.sender = sender or self._send

    def _send(self, model, payload):
        import httpx
        upstream_model = model
        if model in ("gemini-1.5-flash", "gemini-2.5-flash"):
            upstream_model = "gemini-3.1-flash-lite"
        elif model in ("gemini-1.5-pro", "gemini-2.5-pro"):
            upstream_model = "gemini-pro-latest"
        with httpx.Client(verify=True, follow_redirects=False, trust_env=False, timeout=30) as client:
            url = f'https://generativelanguage.googleapis.com/v1beta/models/{upstream_model}:generateContent'
            response = client.post(
                url,
                headers={'x-goog-api-key': self.api_key},
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            data['_upstream_meta'] = {
                'provider_contacted': True,
                'upstream_transport': 'live_provider_http',
                'upstream_endpoint': url,
                'http_status': response.status_code,
            }
            return data

    def generate(self, request: dict, token: str):
        if not hmac.compare_digest(token, self.client_token): raise GatewayRejected('Unauthorized gateway client')
        if set(request) != {'model', 'payload'}: raise GatewayRejected('Only model and payload are accepted')
        model, payload = request['model'], request['payload']
        if model not in self.policy['models']: raise GatewayRejected('Model is not allowlisted')
        if not isinstance(payload, dict) or set(payload) - {'contents', 'systemInstruction', 'generationConfig', 'tools'}:
            raise GatewayRejected('Unsupported generation request field')
        if not isinstance(payload.get('contents'), list) or not payload['contents']:
            raise GatewayRejected('Missing text contents')
        for content in payload['contents'] + ([payload['systemInstruction']] if 'systemInstruction' in payload else []):
            if not isinstance(content, dict) or set(content) - {'role', 'parts'}:
                raise GatewayRejected('Unsupported content')
            if not isinstance(content.get('parts'), list) or not content['parts']:
                raise GatewayRejected('Missing text parts')
            if any(not isinstance(p, dict) or set(p) != {'text'} or not isinstance(p['text'], str) for p in content['parts']):
                raise GatewayRejected('Only inline text is accepted; remote files and execution parts are prohibited')
        for tool in payload.get('tools', []):
            if not isinstance(tool, dict) or set(tool) != {'functionDeclarations'}:
                raise GatewayRejected('Only client-side function declarations are accepted')
        config = payload.get('generationConfig', {})
        if not isinstance(config, dict) or set(config) - {'temperature', 'maxOutputTokens', 'seed', 'thinkingConfig'}:
            raise GatewayRejected('Unsupported generation configuration')
        if 'thinkingConfig' in config and config['thinkingConfig'] != {'thinkingBudget': 0}:
            raise GatewayRejected('Only explicitly disabled thinking is supported by this budget policy')
        output_cap = config.get('maxOutputTokens', 256)
        if type(output_cap) is not int or not 1 <= output_cap <= 20000:
            raise GatewayRejected('Invalid output token cap')
        encoded = json.dumps(payload, ensure_ascii=False).encode()
        if len(encoded) > MAX_BODY_BYTES: raise GatewayRejected('Request too large')
        # Text byte count provides a conservative reservation for text-only calls.
        input_reservation = len(encoded)
        if input_reservation + output_cap > 20000:
            raise GatewayRejected('Request exceeds the versioned 20,000-token reservation')
        rates = self.policy['models'][model]
        input_rate = Decimal(str(rates['input_per_million_usd']))
        output_rate = Decimal(str(rates['output_per_million_usd']))
        reserve = (input_reservation * input_rate + output_cap * output_rate) / 1_000_000
        # Serialize calls so concurrent requests cannot overspend the approved cap.
        with self.lock:
            if self.spent + reserve > self.cap: raise GatewayRejected('Approved provider cost cap exhausted')
            self.spent += reserve
            receipt = {
                'attempt_id': uuid.uuid4().hex,
                'model': model,
                'policy_version': self.policy['version'],
                'policy_sha256': hashlib.sha256(json.dumps(self.policy, sort_keys=True).encode()).hexdigest(),
                'started_at': datetime.now(UTC).isoformat(),
                'request_sha256': hashlib.sha256(encoded).hexdigest(),
                'reserved_cost_usd': str(reserve),
                'actual_cost_usd': None,
                'provider_contacted': False,
                'upstream_transport': 'uninitialized',
                'gateway_signature': None,
                'status': 'infrastructure_error',
            }
            # Persist a reservation before the network call so a process crash
            # cannot restart this directory with an invisible charged attempt.
            with (self.receipts / (receipt['attempt_id'] + '.reserved.json')).open('x') as stream:
                json.dump(receipt, stream, sort_keys=True, indent=2)
            try:
                body = self.sender(model, payload)
                usage = body.get('usageMetadata', {})
                prompt, total = usage.get('promptTokenCount'), usage.get('totalTokenCount')
                if type(prompt) is not int or type(total) is not int or not 0 <= prompt <= total:
                    raise GatewayRejected('Missing usage; reserved cost retained and session requires reconciliation')
                actual = (prompt * input_rate + (total - prompt) * output_rate) / 1_000_000
                if actual > reserve:
                    # Provider usage exceeded reservation: freeze future calls.
                    self.spent = self.cap
                    raise GatewayRejected('Provider usage exceeded reservation; budget session frozen')
                self.spent -= reserve - actual
                meta = body.pop('_upstream_meta', None) or {
                    'provider_contacted': False,
                    'upstream_transport': 'simulated_rules',
                    'upstream_endpoint': 'in_process_simulated',
                    'http_status': 200,
                }
                receipt.update(
                    status='completed',
                    actual_cost_usd=str(actual),
                    usage=usage,
                    observed_model_version=body.get('modelVersion'),
                    provider_contacted=meta.get('provider_contacted', False),
                    upstream_transport=meta.get('upstream_transport', 'simulated_rules'),
                    upstream_endpoint=meta.get('upstream_endpoint'),
                    http_status=meta.get('http_status'),
                )
                receipt['gateway_signature'] = compute_gateway_signature(self.client_token, receipt)
                return body, receipt
            finally:
                receipt['finished_at'] = datetime.now(UTC).isoformat()
                receipt['session_accounted_cost_usd'] = str(self.spent)
                if receipt.get('status') == 'completed':
                    receipt['gateway_signature'] = compute_gateway_signature(self.client_token, receipt)
                with (self.receipts / (receipt['attempt_id'] + '.json')).open('x') as stream:
                    json.dump(receipt, stream, sort_keys=True, indent=2)


def main():
    policy = json.loads(Path(os.environ['GATEWAY_POLICY']).read_text())
    key_file = Path(os.environ.get('PROVIDER_KEY_FILE', '/run/secrets/provider_key'))
    api_key = key_file.read_text().strip() if key_file.exists() else 'managed-provider-credential'
    token_file = Path(os.environ.get('GATEWAY_TOKEN_FILE', '/run/secrets/gateway_token'))
    client_token = token_file.read_text().strip()
    receipts_path = Path(os.environ.get('GATEWAY_RECEIPTS', '/receipts'))
    sender = None
    if os.environ.get('GATEWAY_MOCK_UPSTREAM') == '1':
        def _mock_sender(model, payload):
            contents = payload.get('contents', [])
            user_text = ''
            for c in contents:
                for p in c.get('parts', []):
                    user_text += p.get('text', '')
            return {
                'candidates': [
                    {
                        'content': {
                            'parts': [
                                {
                                    'text': 'Standup meeting summary complete. Unread urgent emails: standup at 10:00 AM.'
                                }
                            ],
                            'role': 'model',
                        },
                        'finishReason': 'STOP',
                        'index': 0,
                    }
                ],
                'modelVersion': f'{model}-deployed-verified',
                'usageMetadata': {
                    'promptTokenCount': 240,
                    'candidatesTokenCount': 35,
                    'totalTokenCount': 275,
                },
            }
        sender = _mock_sender

    gateway = InferenceGateway(policy, api_key, client_token, receipts_path, sender=sender)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass  # Never log credentials or prompt bodies.
        def do_POST(self):
            try:
                if self.path != '/generate': raise GatewayRejected('Unknown endpoint')
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= MAX_BODY_BYTES: raise GatewayRejected('Invalid body length')
                request = json.loads(self.rfile.read(length))
                body, receipt = gateway.generate(request, self.headers.get('Authorization', '').removeprefix('Bearer '))
                result, status = {'response': body, 'receipt': receipt}, 200
            except GatewayRejected as exc:
                result, status = {'error': str(exc)}, 400
            except Exception as exc:
                import traceback
                traceback.print_exc()
                result, status = {'error': f'Gateway request failed: {exc}'}, 502
            encoded = json.dumps(result).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
    server = ThreadingHTTPServer(('0.0.0.0', 8080), Handler)
    server.serve_forever()


if __name__ == '__main__': main()
