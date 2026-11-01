# Threat model

The CLI checks the Ed25519 signature on the receipt and on the manifest.
The CLI checks the RFC 6962 inclusion proof of the receipt leaf under the manifest Merkle root.
The CLI checks chain consistency. The first batch must carry the genesis previous-manifest hash. A later batch must match the previous manifest hash and the RFC 6962 consistency proof when the package carries that proof.
The CLI checks key state in the trust store embedded in the package: principal type, validity window, and compromised status.

The CLI does not check the truth of data before the gateway.
The CLI does not check how the tool behaves on the tool's own network.
The CLI does not certify SOC 2, HIPAA, GDPR, LGPD, or EU AI Act compliance.

`resource_uri` is the action URI. Structural URI validation and DNS pinning run in the execution engine. That engine does not open a socket to a refused destination, and it does not scan the tool's internal network. This verifier is offline: it opens no database connection and no network socket.

Sheets A, B, C, and D live in the private engine. They are named by `tests/integration/test_idempotency_claim.py`, `tests/integration/test_custody_session.py`, `tests/unit/test_mcp_socket_safety.py`, `tests/integration/test_mcp_client_boundary.py`, and `tests/integration/test_rls_pool_leakage.py`. This tree does not claim to have executed them.
