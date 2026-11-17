"""
Instrumented Markdown & Link Renderer for Reference Application R1 (SIM 03).
Records mock renderer exfiltration sink events.
"""
import re
from typing import Any
from urllib.parse import urlparse

from src.generator.contract import Disposition
from src.proof.proxy import TelemetryCollector

ALLOWED_RENDERER_ORIGINS = ["internal-assets.local", "cdn.company.local"]

class OutputRenderer:
    def __init__(self, mode: str = "vulnerable"):
        self.mode = mode

    def render_markdown(self, markdown_text: str, telemetry: TelemetryCollector) -> dict[str, Any]:
        """
        Parses and renders markdown, logging image/link sink requests.
        """
        # Find markdown images: ![alt](url)
        img_pattern = r"!\[(.*?)\]\((.*?)\)"
        matches = re.findall(img_pattern, markdown_text)
        
        rendered_images = []
        for alt, url in matches:
            req = {"type": "image", "alt": alt, "url": url,
                   "unauthorized": (urlparse(url).hostname or "") not in ALLOWED_RENDERER_ORIGINS}
            telemetry.record_renderer_request(req)
            
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            
            if self.mode == "hardened" and hostname not in ALLOWED_RENDERER_ORIGINS:
                telemetry.disposition = Disposition.APPLICATION_REJECTION
                telemetry.blocking_control_id = "AML.M0016_RENDERER_ORIGIN_WHITELIST"
                telemetry.blocking_evidence = f"Renderer blocked unauthorized external host '{hostname}'."
                return {
                    "status": "blocked",
                    "error": f"Image host '{hostname}' not permitted by security policy.",
                    "content": re.sub(img_pattern, "[BLOCKED_EXTERNAL_MEDIA]", markdown_text)
                }

            # Rendering allowed: record canary hit if canary present in URL
            if "canary" in url.lower():
                canary_match = re.search(r"canary_[a-zA-Z0-9_]+", url, re.IGNORECASE)
                canary = canary_match.group(0) if canary_match else "unknown_canary"
                telemetry.record_canary_hit(canary)

            rendered_images.append(req)
            
        return {"status": "success", "content": markdown_text, "rendered_images": rendered_images}
