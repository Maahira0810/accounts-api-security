# Logging, Audit Integrity, Detection and Incident Response
Addresses T01, T02, T03, T08, T09. Specification only: no application code exists in this repo.

## Logging
- **Structured JSON** to stdout (one event per line) with a fixed schema: `ts, level, service, trace_id, event, actor_id, resource_id, outcome`.
- **Allow-list, not block-list:** the logger accepts only the fields above plus per-event allow-listed extras. Free-form request/response bodies are never logged. Identifiers are opaque IDs (customer ID), never names, emails, phones, IBANs, balances or card digits.
- **Redact before ingestion:** drop/mask at the logger, with a second pass in the log shipper (e.g. Fluent Bit filter) *before* data leaves the cluster. 
- **Regex redaction limits:** regexes miss unusual formats, split or encoded values, and names/addresses. They produce false negatives and are a backstop, not the control. Use periodic sampling of ingested logs for PII and treat a hit as a T01 incident.
- **Retention/access:** log store encrypted with KMS; read access by role, break-glass for raw access, access itself audited.

## Audit logs (T09)
- Separate from debug logs. Written by an identity that can append but not read, modify, or delete.
- Shipped to the log-archive account with S3 Object Lock (compliance mode); CloudTrail log-file validation on; SCP blocks `cloudtrail:StopLogging|DeleteTrail`. Integrity check: scheduled validation of CloudTrail digests; hash-chain application audit records if required by regulation.
- Only Terraform for CloudTrail validation and the deny-delete bucket policy is included here (`terraform/detection_audit.tf`).

## Runtime detection (T02, T03, T08)
GuardDuty EKS Runtime Monitoring (declared in Terraform), plus CloudTrail anomaly alerts and VPC Flow Logs. Alert on: shell spawned in the container, writes outside `/tmp`, unexpected outbound destinations, use of the workload role from outside the cluster, secrets read at unusual rates.

## Response: suspicious process or outbound traffic in an accounts-api pod
1. **Contain:** apply a quarantine NetworkPolicy/label to the pod (deny all) rather than deleting it; cordon the node if escape is suspected. Do not restart yet.
2. **Preserve evidence:** record pod spec, image digest, node; capture logs, `kubectl get events`, flow logs; snapshot the node volume/take a memory capture where the platform allows; export relevant CloudTrail.
3. **Assess credential exposure:** assume the IRSA role session, DB credentials and KYC key are exposed. Review CloudTrail for the role's activity; revoke sessions (attach a deny-before-time policy), rotate DB and KYC secrets.
4. **Investigate lateral movement:** check flow logs for connections to other namespaces/nodes; review other pods on the same node; check whether the image digest differs from the released one (supply chain, T04).
5. **Rebuild:** redeploy from a trusted, digest-pinned image built from a known-good commit; delete the compromised pod/node; verify policy compliance.
6. **Follow-up:** notify per regulatory timelines (data impact assessment), write the post-incident review, and add a permanent fix to the threat model.
