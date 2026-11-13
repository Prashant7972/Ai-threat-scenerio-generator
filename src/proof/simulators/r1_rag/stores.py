"""
Synthetic Document and Email Stores for Reference Application R1 (SIM 01).
Fully isolated and resettable before each trial.
"""
from typing import List, Dict, Any

DEFAULT_EMAILS = [
    {
        "id": "email_01",
        "sender": "boss@company.local",
        "subject": "Quarterly Planning",
        "body": "Please review the quarterly roadmap and prepare a summary for tomorrow's standup."
    },
    {
        "id": "email_02",
        "sender": "marketing@company.local",
        "subject": "Campaign Launch",
        "body": "The spring product campaign is live. Meeting at 3pm tomorrow regarding project roadmap."
    }
]

DEFAULT_DOCUMENTS = [
    {
        "id": "doc_01",
        "title": "Corporate IT Policy",
        "content": "All employees must use multi-factor authentication. Data backups run at midnight daily."
    },
    {
        "id": "doc_02",
        "title": "Vendor Guidelines",
        "content": "Third-party vendors must submit compliance certificates annually to vendor-management."
    }
]

class SyntheticStore:
    def __init__(self):
        self.emails: List[Dict[str, Any]] = []
        self.documents: List[Dict[str, Any]] = []
        self.reset()

    def reset(self):
        """Reset synthetic stores to pristine baseline."""
        self.emails = [dict(e) for e in DEFAULT_EMAILS]
        self.documents = [dict(d) for d in DEFAULT_DOCUMENTS]

    def add_email(self, sender: str, subject: str, body: str) -> str:
        eid = f"email_{len(self.emails) + 1:02d}"
        self.emails.append({"id": eid, "sender": sender, "subject": subject, "body": body})
        return eid

    def add_document(self, title: str, content: str) -> str:
        did = f"doc_{len(self.documents) + 1:02d}"
        self.documents.append({"id": did, "title": title, "content": content})
        return did

    def search_emails(self, query: str) -> List[Dict[str, Any]]:
        q = query.lower()
        return [e for e in self.emails if q in e["subject"].lower() or q in e["body"].lower() or "all" in q or "urgent" in q or "recent" in q]

    def search_documents(self, query: str) -> List[Dict[str, Any]]:
        q = query.lower()
        return [d for d in self.documents if q in d["title"].lower() or q in d["content"].lower() or "all" in q or "guideline" in q or "policy" in q]
