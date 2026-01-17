# IOC-Matcher
Defensive IOC matcher. Loads threat-intel indicators (hashes, IP/CIDR, domains, URLs, emails), normalizes/validates them, then scans logs or events (JSONL/text) to find matches. Outputs matches with context (type, source, tags, confidence) for alerting, hunting, and incident response. CLI-first, optional API.
