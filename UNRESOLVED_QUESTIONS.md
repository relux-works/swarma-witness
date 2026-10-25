# Unresolved questions

No open question below is silently defaulted by the bootstrap. No service or
consumer is activated. References are to the conditional witness-service contract
linked from README; newer accepted consumer decisions need joint reconciliation.

| ID | Owner | Status / required decision |
| --- | --- | --- |
| G01 | Owner | owner decision (2026-10-25): Owner decided Apache-2.0; LICENSE added. First-party test fixtures may be distributed under this license; no third-party data is added. |
| G02 | Contract review | Go 1.26.x accepted. Waggle S5 and its exact registrar CCJ dependency are approved and pinned; see spec/wire-v1.md. No copied verifier. Adapter activation remains separate. |
| G03 | Contract review | This repository owns vector data. Consumers pin immutable commit plus exact manifest digest and take bytes. Closed bootstrap metadata is documented; protocol vectors remain pending. |
| G04 | Contract review | Codec schemas accepted and implemented in wire; provisioning/consent/role enforcement remain S2 gates. |
| G05 | Contract review | Strict pinned Waggle helpers, separate canonical-equality rule, exact enums/nulls and first-party signature vectors implemented. Production custody remains open. |
| G06 | Contract review | Syntax gate closed by registrar spec 3fc31e4 and mandatory-format code 264660e. Codec uses protected profile literals, no registry/Loader import or 40|64 fallback. Candidate-state validation and authenticated append remain later gates. |
| G07 | Owner | Service-wide control-metadata disclosure consent is unapproved. Provisioning stays closed until explicit consent or a separately reviewed isolation design. |
| G08 | Owner and contract review | Pure signed consent/tuple validation implemented; protected storage and durable one-use consumption remain S3/S4. No implicit first use. |
| G09 | Contract review | Pure administrative authorization, policy hashes, null/CAS/replay and transition validation implemented. Record-key rotation remains unavailable (option B); activation/barriers remain S3/S4. |
| G10 | Owner and contract review | Decide separate key custody, initial pins, rotation and lost-key continuity. |
| G11 | Owner and contract review | Pure pinned mTLS/certificate/interval/revocation predicates; proposed digest preimages require confirmation. Production provider, native adapter, CA/reload and handoff remain unqualified. |
| G12 | Contract review | Transport-independent carriers, correlation and byte accounting accepted/implemented. Pure HTTP framing, budget/rate predicates and close-versus-code checks implemented; streaming admission, cancellation and runtime qualification stay open. |
| G13 | Owner and contract review | Local immutable codecs, full file/namespace ordering and atomic root implemented with injected-call tests. Review exact local v1 layout; qualify real device/power-loss durability, protected mount/owner layout and hard reserve. See spec/storage-v1.md. |
| G14 | Owner and contract review | Typed consumer archive interfaces and closed defaults implemented. Provider protocol, independent retention/retrieval, one-use offline approval and fresh-head advancement qualification remain open. Never discard acknowledged evidence. |
| G15 | Contract review | Single local audit/root chain, lock graph, reserve/exhaustion, restricted typed reader rules and independent archive interface implemented. Global reader installation/disclosure and real archive acknowledgement authority remain open. |
| G16 | Owner and contract review | Accepted [WC1 QT-2c profiles](spec/witness-qt2c-profile.md); inactive codecs/window adapters and local S3 WC1TimeUse/1 retention implemented for review. [Six qualification specifications](spec/qualifiedtime-tests.md) remain PENDING: native endpoints/clock/entropy, enforced original post-read bounds, independent use custody, witness, original reader and macOS. No production runtime, null-time authority success or activation. |
| G17 | Owner and contract review | Custodian provider/SLA and typed protocol remain open. No on-node, periodic-only or absent-provider authority fallback. |
| G18 | Owner and contract review | Qualify lifetime exclusion of older serving instances; local locks and append CAS are insufficient. |
| G19 | Owner and contract review | Specify exact pending/control recovery and joint-loss runbook. No receipt regeneration, reset or automatic mode change. |
| G20 | Contract review | Resolve caller-wide budget accounting across RPCs/pages/reconnects; current timeout fields alone do not let the server enforce an unseen whole attempt. |
| G21 | Contract review | Close error precedence and anchor/predecessor/missing-proof behavior. Unknown irreversible work remains fenced. |
| G22 | Contract review | Specify deterministic complete proof partition, historical retrieval ACLs and evidence lifetime. |
| G23 | Owner and contract review | Obtain separate consumer receipt/head/proof, key purpose, egress and provisioning acceptance. |
| G24 | Contract review | Reconcile accepted exact S3/UTC/anchor/checkpoint-fork rules without reopening settled policy. |
| G25 | Owner and contract review | Define independent bridge ownership, complete candidate inventory, actual commit evidence and exclusion access. No writer-supplied validity flag. |
| G26 | Contract review | Accept a complete checkpoint-proof representation fitting wrapper limits, or refuse before intent. No truncation or ad hoc pagination. |
| G27 | Contract review | Specify bounded admission/rate/memory/reserve algorithms and precedence. |
| G28 | Owner and contract review | Define exact qualification identity, acceptance thresholds and isolated fault environment. |
| G29 | Owner and contract review | Decide deployment, custody, readiness and shutdown ownership. Bootstrap authorizes none of these. |
| G30 | Contract review | Align stale references with accepted real-head snapshot reissue and separate idle currentness. S5 helpers are pinned; freshness/currentness adapters remain inactive here. |
| G31 | Contract review | Accept pre-intent genesis and historical-checkpoint verification paths. Existing S3 VerifyJournal expects authenticated witness facts; never fabricate them or weaken its global checks. |
