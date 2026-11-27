"""
Phase 3: the agent's long-term memory.

Every entry records WHAT was saved and WHERE it came from (provenance), even in
setup A. Setup A does not use the provenance to decide anything; it simply saves
whatever the agent asks. Keeping the source on every entry lets us show, in the
results, exactly which alert planted which note.

Entry fields:
  note             text shown to the agent on later alerts
  source_alert_id  alert that produced the entry (or a ticket id for analyst notes)
  channel          "agent_note"  - the agent asked to remember it (untrusted origin)
                   "analyst_ticket" - added by a SOC analyst (trusted channel)
  trusted          True only for the trusted channel
  fields           optional structured facts (used by the memory-write filter, Phase 5)
"""

import json


class Memory:
    def __init__(self, allowlist: dict | None = None):
        self.allowlist = allowlist or {}
        self.entries: list[dict] = []

    # ---- writing ----------------------------------------------------------
    def add(self, note: str, source_alert_id: str, channel: str = "agent_note",
            trusted: bool = False, fields: dict | None = None) -> dict:
        entry = {
            "note": note,
            "source_alert_id": source_alert_id,
            "channel": channel,
            "trusted": trusted,
        }
        if fields:
            entry["fields"] = fields
        self.entries.append(entry)
        return entry

    def add_analyst_note(self, trusted_note: dict) -> dict:
        """Add a note from the trusted analyst channel (legit_memory_sequences.json)."""
        return self.add(
            note=trusted_note["text"],
            source_alert_id=trusted_note.get("ticket", "analyst"),
            channel=trusted_note.get("channel", "analyst_ticket"),
            trusted=bool(trusted_note.get("trusted", True)),
            fields=trusted_note.get("fact"),
        )

    # ---- reading ----------------------------------------------------------
    def for_agent(self) -> list[dict]:
        """What the agent sees on the next alert."""
        return list(self.entries)

    def contains(self, text: str) -> bool:
        """True if any entry mentions `text` (used to check if an attacker's target got in)."""
        return any(text in e["note"] or text in json.dumps(e.get("fields", {})) for e in self.entries)

    def __len__(self):
        return len(self.entries)

    def to_list(self) -> list[dict]:
        """Copy for the run logs."""
        return json.loads(json.dumps(self.entries))
