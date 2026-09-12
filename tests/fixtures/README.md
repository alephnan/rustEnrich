# Sanitized provider fixtures

These JSON files are synthetic report examples, not current intelligence or captured
responses from a live provider. They contain no credentials or individual abuse
reports. Tests load them locally and do not spend provider quota.

- `abuseipdb-ip.json` exercises the non-verbose CHECK response, zero scores/counts,
  a nullable flag and an observation timestamp with a UTC offset.
- `virustotal-ip.json` uses the documentation IPv6 range, a signed reputation and
  unknown fields that must survive in raw JSON.
- `virustotal-url.json` uses an illustrative canonical SHA-256 URL ID and the
  provider's hyphenated analysis-statistic keys.
- `virustotal-file.json` uses the public hashes of an empty file, allowing the
  same canonical report to verify MD5, SHA-1 and SHA-256 request identity.

Invalid wrappers, evidence types, identities, timestamps and error responses are
constructed alongside assertions in the provider unit tests.
