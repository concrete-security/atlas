# Security Policy

Atlas establishes attested TLS connections to hosts or targets explicitly configured for aTLS only after verifying remote TEE attestation evidence against a caller-supplied policy. Other destinations may use the binding's standard networking fallback and are not attested. Vulnerabilities that weaken the aTLS verification decision can expose every application built on top of the affected binding.

## Supported Versions

Atlas is pre-1.0 and its packages are released independently. Security fixes are provided for the latest version published to each package registry:

| Package | Supported version |
| --- | --- |
| `atlas-rs` | Latest published version |
| `@concrete-security/atlas-node` | Latest published version |
| `@concrete-security/atlas-wasm` | Latest published version |
| `atlas-python` | Latest published version |
| `@concrete-security/private-ai-sdk` | Latest published version |

The platform-specific packages installed by `@concrete-security/atlas-node` are covered by the `atlas-node` entry. Security fixes are not normally backported to older 0.x releases. The `main` branch is development code and is not a supported release.

## Reporting a Vulnerability

Please report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/concrete-security/atlas/security/advisories/new). Do not open a public issue, discussion, or pull request before we have agreed on a disclosure plan.

A useful report includes:

- the affected package, version, or commit;
- the TEE platform and relevant policy configuration;
- the security impact and prerequisites;
- minimal reproduction steps or a proof of concept; and
- any known mitigations or workarounds.

Do not include live credentials, private keys, personal data, or data belonging to another user. We aim to acknowledge reports within three business days and provide an initial assessment within ten business days. Remediation and disclosure timelines depend on severity and release complexity. We will coordinate publication and credit with the reporter.

## System and Scope

This policy covers the Rust verifier and protocol implementation, the Python, Node.js, and browser/WASM bindings, the WebSocket-to-TCP proxy, and all CI, package publication, release, and repository automation workflows maintained in this repository.

Examples of reportable issues include:

- accepting forged, malformed, stale, or policy-incompatible attestation evidence;
- failing to bind verified evidence and the server certificate to the exact TLS session;
- bypassing TCB status, bootchain, OS image, application composition, RTMR replay, hostname, or certificate checks;
- a binding behaving less strictly than the Rust core for an equivalent policy;
- escaping the proxy target allowlist or its default-deny behavior;
- unsafe parsing or denial of service reachable through untrusted protocol inputs; and
- compromising repository credentials, published packages, release provenance, or protected repository content through CI or automation workflows.

## Threat Model and Security Invariants

Remote servers, certificates, quotes, event logs, policies loaded from external data, proxy requests, and protocol bytes are untrusted inputs. Issue, pull request, review, and comment content consumed by repository automation is also untrusted. Atlas relies on the Web PKI and Intel endorsement chain, plus the expected measurements and policy selected by the caller.

The following properties must hold:

- the TLS server name and certificate chain are verified before the connection is returned;
- TDX evidence is cryptographically verified and its TCB status is explicitly allowed by policy;
- the attested certificate and EKM bind the evidence to the current TLS connection and prevent replay across sessions;
- when runtime verification is enabled, expected bootchain measurements, OS image, application composition, and replayed runtime measurements must all match;
- verification failures are fail-closed and never return a usable connection;
- language bindings preserve the core verification result and do not silently weaken policy;
- the proxy rejects every target that is not exactly present in its configured allowlist; and
- CI and automation treat contributor-controlled content as untrusted and do not expose credentials or grant unintended repository or OIDC capabilities.

## Out of Scope and Known Limitations

The following are not vulnerabilities by themselves:

- the documented reduction in assurance when a caller explicitly selects `DstackTdxPolicy::dev()` or sets `disable_runtime_verification: true`;
- an incorrect expected measurement, allowlist, TCB status, or other policy value supplied by the application using Atlas;
- compromise of Web PKI or Intel trust roots without an Atlas-specific flaw;
- vulnerabilities solely in an upstream dependency when Atlas adds no distinct reachability or impact; and
- social engineering, physical attacks, volumetric denial of service, and documentation-only issues without security impact.

A path that activates relaxed verification without explicit caller intent, or that bypasses checks which remain promised in relaxed mode, is in scope. Intel TDX through Dstack is the current production verifier; planned TEE platforms are not security claims until implemented and documented.

Only test systems you own or have explicit permission to test. Do not disrupt services, access other users' data, or test Concrete-operated production infrastructure without prior written authorization.
