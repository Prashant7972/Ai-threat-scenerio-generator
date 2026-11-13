"""
Threat Intelligence Provenance and Diff Classifier (GEN 05).
Classifies upstream updates to MITRE ATLAS YAML or AIID incidents into:
- editorial
- mapping_only
- mechanism_change
- mitigation_change
- withdrawal
"""
from typing import Dict, Any, List, Literal, Optional
from enum import Enum
from pydantic import BaseModel

class DiffClassification(str, Enum):
    EDITORIAL = "editorial"
    MAPPING_ONLY = "mapping_only"
    MECHANISM_CHANGE = "mechanism_change"
    MITIGATION_CHANGE = "mitigation_change"
    WITHDRAWAL = "withdrawal"

class ProvenanceDiff(BaseModel):
    item_id: str
    item_type: Literal["technique", "case_study", "mitigation", "incident"]
    classification: DiffClassification
    details: str
    requires_respecification: bool

def classify_provenance_diff(old_item: Dict[str, Any], new_item: Optional[Dict[str, Any]]) -> ProvenanceDiff:
    item_id = old_item.get("id") or old_item.get("incident_id", "UNKNOWN")
    
    # 1. Item removed / withdrawn
    if new_item is None:
        return ProvenanceDiff(
            item_id=item_id,
            item_type="technique" if "AML.T" in item_id else "incident",
            classification=DiffClassification.WITHDRAWAL,
            details=f"Item {item_id} was withdrawn from upstream catalog.",
            requires_respecification=True,
        )
        
    # 2. Check for mitigation changes
    if item_id.startswith("AML.M"):
        if old_item.get("description") != new_item.get("description"):
            return ProvenanceDiff(
                item_id=item_id,
                item_type="mitigation",
                classification=DiffClassification.MITIGATION_CHANGE,
                details=f"Mitigation definition updated for {item_id}.",
                requires_respecification=True,
            )
            
    # 3. Check for technique mechanism changes
    if item_id.startswith("AML.T"):
        old_desc = old_item.get("description", "").strip()
        new_desc = new_item.get("description", "").strip()
        if old_item.get("tactic") != new_item.get("tactic"):
            return ProvenanceDiff(
                item_id=item_id,
                item_type="technique",
                classification=DiffClassification.MECHANISM_CHANGE,
                details=f"Technique {item_id} tactic shifted from {old_item.get('tactic')} to {new_item.get('tactic')}.",
                requires_respecification=True,
            )
        if old_desc != new_desc:
            if abs(len(old_desc) - len(new_desc)) > 40:
                return ProvenanceDiff(
                    item_id=item_id,
                    item_type="technique",
                    classification=DiffClassification.MECHANISM_CHANGE,
                    details=f"Substantial mechanism change detected in description for {item_id}.",
                    requires_respecification=True,
                )
            else:
                return ProvenanceDiff(
                    item_id=item_id,
                    item_type="technique",
                    classification=DiffClassification.EDITORIAL,
                    details=f"Minor editorial wording update for {item_id}.",
                    requires_respecification=False,
                )
                
    # 4. Check for mapping changes in case studies or AIID
    if "techniques" in old_item and "techniques" in new_item:
        if set(old_item["techniques"]) != set(new_item["techniques"]):
            return ProvenanceDiff(
                item_id=item_id,
                item_type="case_study",
                classification=DiffClassification.MAPPING_ONLY,
                details=f"Case study technique mapping changed for {item_id}.",
                requires_respecification=False,
            )

    return ProvenanceDiff(
        item_id=item_id,
        item_type="technique" if "AML." in item_id else "incident",
        classification=DiffClassification.EDITORIAL,
        details="No structural or mechanism changes detected.",
        requires_respecification=False,
    )
