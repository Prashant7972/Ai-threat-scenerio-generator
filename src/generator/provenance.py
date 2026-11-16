"""Conservative change classification and append-only invalidation plans (GEN 05)."""
from typing import Optional, Literal
from enum import Enum
from pathlib import Path
import hashlib
import json
from pydantic import BaseModel


class DiffClassification(str, Enum):
    EDITORIAL = 'editorial'
    MAPPING_ONLY = 'mapping_only'
    MECHANISM_CHANGE = 'mechanism_change'
    MITIGATION_CHANGE = 'mitigation_change'
    WITHDRAWAL = 'withdrawal'


class ProvenanceDiff(BaseModel):
    item_id: str
    item_type: Literal['technique', 'case_study', 'mitigation', 'incident']
    classification: DiffClassification
    details: str
    requires_respecification: bool


def classify_provenance_diff(old_item: dict, new_item: Optional[dict]) -> ProvenanceDiff:
    item_id = str(old_item.get('id') or old_item.get('incident_id', 'UNKNOWN'))
    kind = ('mitigation' if item_id.startswith('AML.M') else 'technique' if item_id.startswith('AML.T')
            else 'case_study' if item_id.startswith('AML.CS') else 'incident')
    changed = {k for k in set(old_item) | set(new_item or {}) if old_item.get(k) != (new_item or {}).get(k)}
    if new_item is None or new_item.get('withdrawn') is True:
        classification = DiffClassification.WITHDRAWAL
    elif changed & {'mitigations', 'mitigation', 'controls'} or (kind == 'mitigation' and changed - {'modified_date', 'revision'}):
        classification = DiffClassification.MITIGATION_CHANGE
    elif changed <= {'techniques', 'atlas_mappings', 'modified_date', 'revision'} and changed & {'techniques', 'atlas_mappings'}:
        classification = DiffClassification.MAPPING_ONLY
    elif changed <= {'title', 'name', 'locator', 'modified_date', 'retrieved_at', 'revision'}:
        classification = DiffClassification.EDITORIAL
    else:
        # A one-character negation can change a mechanism. Length is not evidence.
        classification = DiffClassification.MECHANISM_CHANGE
    invalidates = classification in {DiffClassification.MECHANISM_CHANGE, DiffClassification.MITIGATION_CHANGE, DiffClassification.WITHDRAWAL}
    return ProvenanceDiff(item_id=item_id, item_type=kind, classification=classification,
                          details='Changed fields: ' + ', '.join(sorted(changed)), requires_respecification=invalidates)


def plan_source_change(old_item: dict, new_item: Optional[dict], packages: list[dict]) -> dict:
    diff = classify_provenance_diff(old_item, new_item)
    affected = [p for p in packages if diff.item_id in p['source_ids']]
    withdrawal = diff.classification == DiffClassification.WITHDRAWAL
    return {'diff': diff.model_dump(mode='json'), 'previous_source': old_item, 'new_source': new_item,
            'affected_packages': [p['package_id'] for p in affected],
            'invalidate': [p['package_id'] for p in affected] if diff.requires_respecification else [],
            'successor_candidates': [dict(predecessor=p['package_id'], scenario_id=p['scenario_id'], status='candidate')
                                     for p in affected] if diff.requires_respecification and not withdrawal else [],
            'impacted_tests': sorted({t for p in affected for t in p.get('test_ids', [])}) if diff.requires_respecification else [],
            'analyst_review_required': diff.requires_respecification,
            'regenerate': diff.requires_respecification and not withdrawal}


def save_change_plan(plan: dict, directory: Path) -> Path:
    data = (json.dumps(plan, sort_keys=True, indent=2) + '\n').encode()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (hashlib.sha256(data).hexdigest() + '.json')
    if path.exists():
        if path.read_bytes() != data: raise ValueError('Change history was modified')
        return path
    with path.open('xb') as stream: stream.write(data)
    return path
