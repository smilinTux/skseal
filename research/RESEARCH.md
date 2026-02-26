# skseal Research Document
## Sovereign Document Signing Platform — Deep Research & Technical Specification

**Research Date:** February 25, 2026  
**Status:** In Progress  
**Version:** 1.0

---

## Executive Summary

This research document explores the landscape of open-source document signing platforms, with particular focus on DocuSeal as a reference implementation, and outlines the technical architecture for "skseal"—a PGP-based sovereign document signing platform designed to integrate with the SKWorld infrastructure stack. The research encompasses platform architecture analysis, cryptographic signing implementations, legal compliance frameworks, and integration strategies for SKGraph, skref, and skcapstone components.

The fundamental premise of skseal differs from conventional e-signature platforms by prioritizing cryptographic sovereignty over convenience. Where platforms like DocuSeal focus on user experience and form-based workflows, skseal implements cryptographic document sealing using OpenPGP standards, providing verifiable proof of document integrity and signer identity that does not depend on any centralized authority or proprietary verification system.

---

## 1. DocuSeal Deep Dive

### 1.1 Architecture Overview

DocuSeal represents the most comprehensive open-source alternative to commercial e-signature platforms such as DocuSign and PandaDoc. The platform's architecture reflects a modern web application design pattern that balances ease of deployment with robust functionality.

**Backend Technology Stack:** The application is built on Ruby on Rails, leveraging the framework's mature ecosystem for rapid development and maintenance. Rails provides the foundation for the REST API, authentication systems, and database interactions. The framework's convention-over-configuration approach enables a consistent code structure that facilitates community contributions and custom extensions.

The database layer supports multiple relational database management systems, with PostgreSQL being the recommended production choice due to its robust support for JSON data types, advanced indexing capabilities, and strong ACID compliance. For development and small-scale deployments, SQLite provides a zero-configuration alternative, while MySQL remains available for organizations with existing MySQL infrastructure.

The frontend implementation utilizes Vue.js 3, chosen for its progressive nature and component-based architecture. Vue.js enables the creation of dynamic, single-page-application-like experiences within the document builder and signing interfaces. The framework's reactivity system ensures that form field updates and document previews remain synchronized, providing users with immediate feedback as they construct document templates.

**Key Architecture Decisions:** DocuSeal's architecture separates concerns between the API server, file storage, and notification systems. This separation enables horizontal scaling and allows organizations to integrate with existing infrastructure components such as S3-compatible object storage and SMTP email services.

### 1.2 Core Features Analysis

The platform provides a comprehensive feature set that addresses the majority of document signing use cases without requiring commercial licensing for self-hosted deployments.

**Document Template Builder:** The WYSIWYG template builder enables users to convert existing documents into interactive fillable forms without specialized technical knowledge. The builder supports twelve distinct field types, including signature fields, date inputs, file attachments, checkboxes, and text inputs. The drag-and-drop interface allows rapid template creation, while the field properties panel provides granular control over validation rules, required status, and conditional display logic.

**Multi-Signer Workflows:** Documents can specify multiple submitters in configurable sequences. This capability supports real-world business processes where document execution requires sequential signatures from different parties, such as contracts requiring executive approval before client signature. The workflow engine tracks submission status, sends automated reminders for pending signatures, and provides administrators with visibility into overall workflow progress.

**API and Webhook Integration:** A REST API enables programmatic document creation, template management, and submission tracking. The API follows RESTful conventions with JSON request and response bodies, facilitating integration with virtually any programming language or platform. Webhook subscriptions enable event-driven architectures, allowing external systems to receive real-time notifications when documents are viewed, started, or completed.

**File Storage Options:** The platform supports multiple storage backends, including local filesystem storage for self-contained deployments and cloud object storage services including Amazon S3, Google Cloud Storage, and Azure Blob Storage. This flexibility enables organizations to align document storage with existing data governance policies and infrastructure investments.

### 1.3 Self-Hosted Deployment

Docker containerization provides the primary deployment mechanism for self-hosted installations. The official Docker image encapsulates the application and its dependencies, enabling consistent execution across Linux hosts regardless of underlying distribution variations.

**Deployment Architecture:** The standard Docker deployment pattern mounts a host directory for persistent storage, allowing document files and configuration to survive container restarts and updates. For production deployments, Docker Compose orchestrates the application container alongside a PostgreSQL database container, providing a complete, self-contained signing infrastructure.

The deployment supports custom domain configuration with automatic SSL certificate provisioning through Caddy server integration. This capability enables organizations to establish secure, branded signing portals without manual certificate management overhead.

**Resource Requirements:** Minimum deployment specifications include 2 CPU cores, 2GB RAM, and persistent storage appropriate for document volumes. Production deployments with high document throughput benefit from increased memory allocation, enabling the Rails application to maintain larger connection pools and cache more template assets.

### 1.4 Cloud vs. Self-Hosted Feature Comparison

DocuSeal's licensing model distinguishes between the open-source self-hosted offering and the cloud-hosted Pro plan. Understanding these differences clarifies the value proposition of sovereign alternatives.

**Open-Source Features (Self-Hosted):** The AGPL-licensed self-hosted version includes complete template management, multi-signer workflows, the document builder, API access, webhook support, and file storage configuration. Organizations deploying this version gain full control over their document signing infrastructure without per-document or per-user licensing fees.

**Pro Features (Cloud and On-Premises):** The Pro tier adds enterprise features including company branding and white-labeling, role-based access control, SMS-based identity verification, automated reminder scheduling, conditional field logic, bulk document sending via CSV import, and SSO/SAML integration. These features carry a licensing cost of $240 per user per year plus $0.20 per document processed through API or embedding interfaces.

**Sovereign Considerations:** The AGPL license requires that organizations deploying modified versions of DocuSeal make their modifications available under the same open-source terms. This requirement may conflict with organizations seeking to develop proprietary extensions or custom integrations without disclosing implementation details.

### 1.5 Document Format Support and Signing Verification

**Supported Document Formats:** The platform primarily operates with PDF documents, the universal standard for legally-significant documents. PDF format provides the necessary structure for embedding signature fields, maintaining visual fidelity across devices, and supporting digital signature standards. The form builder converts standard PDF documents into fillable forms, preserving original formatting while adding interactive elements.

**Digital Signature Implementation:** DocuSeal applies industry-standard PDF digital signatures to completed documents. These signatures certify that the document has not been modified since the signing event and identify the signing party. PDF signatures can be verified using standard PDF reader applications, providing universal verification capability without requiring DocuSeal platform access.

**Verification Methods:** Document verification operates through the platform's web interface, where users upload signed documents for authenticity checking. The system validates the digital signature, confirms the document has not been altered, and displays signer information. This centralized verification model provides convenience but depends on platform availability for verification operations.

---

## 2. PGP Document Signing Options

### 2.1 OpenPGP.js Implementation

OpenPGP.js represents the most mature and widely-deployed pure JavaScript implementation of the OpenPGP protocol. The library enables cryptographic operations directly within web browsers and Node.js environments without requiring native binary dependencies.

**Protocol Compliance:** The library implements RFC 9580, the updated specification for OpenPGP that supersedes RFC 4880 and the draft RFC 4880bis. This compliance ensures interoperability with other OpenPGP implementations including GnuPG, ProtonMail, and encrypted messaging applications.

**Cryptographic Algorithm Support:** OpenPGP.js supports both traditional RSA keypairs and modern elliptic curve cryptography. ECC options include Curve25519 for key exchange, Ed25519 for digital signatures, and NIST-standard curves (P-256, P-384, P-521) for organizations requiring FIPS-compliant algorithms. Elliptic curve implementations leverage native Web Cryptography API support where available, providing performance characteristics suitable for interactive web applications.

The library implements authenticated encryption modes including AES-GCM, OCB, and EAX as specified in RFC 9580. These AEAD modes provide both confidentiality and integrity verification, with AES-GCM offering the best performance on platforms with native hardware acceleration.

**Browser Integration:** The library functions within secure contexts (HTTPS), utilizing the Web Cryptography API for cryptographic primitives. Modern browser versions (Chrome, Firefox, Edge, Safari 14+) support the required SubtleCrypto interface and Web Streams API for handling large documents through streaming operations.

**Code Example - Document Signing:** The following pattern demonstrates detached signature creation using OpenPGP.js, where the signature is generated separately from the document to avoid modifying the original file.

```javascript
const publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`;
const privateKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`;
const passphrase = 'signer-passphrase';

const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
const privateKey = await openpgp.decryptKey({
    privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
    passphrase
});

const documentData = await fetch(documentUrl).then(r => r.arrayBuffer());
const message = await openpgp.createMessage({ binary: new Uint8Array(documentData) });

const detachedSignature = await openpgp.sign({
    message,
    signingKeys: privateKey,
    detached: true
});
```

**Security Auditing:** OpenPGP.js has undergone two comprehensive security audits performed by Cure53, a respected security consultancy specializing in penetration testing and code review. Audit reports are publicly available, providing transparency regarding identified vulnerabilities and their remediation.

### 2.2 Browser Extension Approaches

**WebPG Extension:** The WebPG project provides a browser extension approach to PGP operations, interfacing with locally-installed GnuPG installations rather than implementing cryptography in JavaScript. This architecture leverages existing GnuPG keyrings and hardware token support while providing a user interface integrated into the browser experience.

The extension architecture consists of several components. The browser extension handles user interface rendering and message passing, while an NPAPI plugin (or native messaging for modern browsers) communicates with the system GnuPG installation. This approach enables access to smartcard-based keys stored on devices, providing hardware token functionality that pure JavaScript implementations cannot access.

However, WebPG development has stalled, with the last significant releases occurring several years ago. Modern browser security restrictions, particularly Chrome's deprecation of NPAPI plugins, have limited the extension's contemporary utility. Organizations evaluating browser-based PGP solutions should consider OpenPGP.js as the more actively maintained and security-audited alternative.

**Native Messaging Architecture:** Modern browser extensions can communicate with external applications through native messaging protocols. This architecture enables browser interfaces to delegate cryptographic operations to trusted local applications while maintaining the user experience benefits of web-based document workflows. The native messaging companion application handles private key operations, receiving signing requests from the browser and returning cryptographic signatures without exposing private key material to the web context.

### 2.3 Hardware Token Support

Hardware security tokens provide the highest assurance for private key protection, ensuring that signing keys cannot be extracted from the device even if the host computer is compromised.

**PKCS#11 Interface:** The PKCS#11 standard defines a cryptographic token interface enabling applications to perform cryptographic operations using keys stored on hardware devices. YubiKey and Nitrokey devices support PKCS#11 access to their OpenPGP smartcard functionality, enabling integration with applications that implement PKCS#11 client code.

**YubiKey Integration:** YubiKey 5 series devices provide OpenPGP smartcard functionality with FIDO2-capable authentication. The devices can store PGP keys and perform signing operations entirely within secure hardware, with private keys never exposed to the host computer. The YubiKey requires physical touch confirmation for signing operations, providing defense against remote attack even if the computer is compromised.

**Nitrokey Options:** Nitrokey offers OpenPGP-capable devices at various price points, from the entry-level Nitrokey Start to the advanced Nitrokey HSM 2. The Nitrokey Start implements the GNUK open-source firmware, providing transparency regarding the device's cryptographic implementation. The Nitrokey Pro and Storage models offer enhanced physical security features including tamper-evident casing and encrypted storage.

**Browser Limitations:** Pure browser-based JavaScript cannot directly access hardware tokens due to browser security sandboxing. Bridging this gap requires either browser extensions with native messaging capabilities or native desktop applications that mediate between the browser and hardware token APIs.

### 2.4 GPGME Bindings

For server-side document signing operations, GPGME (GnuPG Made Easy) provides language bindings for various programming languages, enabling programmatic control over GnuPG operations.

**Language Support:** GPGME provides official bindings for C, Python, and Common Lisp, with third-party bindings available for additional languages. The Python bindings are particularly well-suited for document processing workflows, enabling clean integration with document generation libraries and database systems.

**Use Case Suitability:** GPGME-based solutions are appropriate for automated signing workflows operating on trusted servers. The architecture assumes server-side key storage and processing, which may conflict with sovereignty requirements that mandate signer-side key control.

---

## 3. Trust Architecture

### 3.1 PGP Web of Trust for Identity Verification

The PGP Web of Trust provides a decentralized model for establishing identity trust, complementing the hierarchical certificate authority model used in TLS/X.509 ecosystems.

**Trust Model Fundamentals:** Rather than depending on centralized identity providers, the Web of Trust enables individuals to vouch for each other's identities through digital signatures. When Alice signs Bob's public key after verifying his identity, she creates a binding between Bob's key and his claimed identity. Users who trust Alice's verification practices can extend that trust to Bob's key based on her signature.

**Signature Chains for Document Verification:** Document signature verification in a Web of Trust context involves tracing signature chains from the document signer's key back to trusted introducers. A robust verification system presents users with the complete signature chain, enabling informed trust decisions rather than simple accept/reject outcomes.

**Key Verification Levels:** The Web of Trust supports multiple trust levels, allowing users to express graduated confidence in keyholder identities. A key might be fully trusted for personal communications while receiving marginal trust for organizational purposes. This granularity enables sophisticated trust policies tailored to specific document signing contexts.

**Sovereign Identity Considerations:** The Web of Trust model aligns well with sovereignty objectives by avoiding dependency on centralized identity verification services. Organizations can establish their own trust circles, verifying member identities through in-person checks or other trusted methods and signing keys accordingly.

### 3.2 Timestamping Services

**RFC 3161 Time-Stamp Protocol:** RFC 3161 defines a protocol for obtaining trusted timestamps from Time Stamping Authorities (TSAs). The protocol involves submitting a cryptographic hash of the data to be timestamped, receiving a signed token that certifies the hash existed at a particular time. This mechanism provides non-repudiation by establishing that the signed data predates the timestamp, preventing post-hoc signature creation that could alter legal effect.

TSA responses follow the Cryptographic Message Syntax (CMS) format, embedding the original hash, a serial number, and the TSA's assertion of the signing time within a digitally signed structure. Verifying applications validate both the timestamp signature and confirm the original document hash matches the hash within the timestamp.

**Sigstore Timestamp Authority:** The Sigstore project provides an open-source timestamp authority implementation that integrates with Rekor, the signature transparency log. While originally designed for software supply chain verification, the timestamp authority component provides general-purpose timestamping suitable for document signing applications.

**OpenTimestamps:** OpenTimestamps provides blockchain-based timestamping with a unique economic model. Rather than paying per timestamp, users create an OpenTimestamps proof file that can be upgraded by Bitcoin calendar servers. The initial timestamp is free, while the Bitcoin blockchain commitment requires periodic upgrades. This approach provides long-term timestamp verification without ongoing subscription costs.

**Choosing a Timestamp Strategy:** A robust timestamping architecture should support multiple providers, enabling resilience against individual TSA outages and providing users with provider selection based on their trust preferences. Organizations may operate private TSAs for internal documents while using public services for cross-organizational agreements.

### 3.3 SKGraph for Audit Trails and Relationship Tracking

SKGraph provides relationship tracking infrastructure that complements document signing workflows by maintaining provenance records and audit trails.

**Graph Structure:** SKGraph implements a directed graph data structure where document signing events form nodes connected by edges representing relationships. These relationships capture signer organization hierarchies, document template inheritance, signing sequence dependencies, and cross-reference links between related documents.

**Audit Trail Implementation:** Each signing event generates multiple graph entries, recording the signer's identity (referenced by PGP key fingerprint), timestamp, document hash, and any available contextual information. This immutable record enables complete reconstruction of signing workflows, supporting legal discovery and compliance auditing requirements.

**Relationship Queries:** The graph structure enables powerful relationship queries not possible with traditional relational databases. Organizations can trace all documents signed by a particular key, identify all documents within a workflow sequence, or discover documents that share common templates or workflow configurations.

**Integration Points:** SKGraph connects with skref for document retrieval and with skcapstone for automated workflow execution. The graph provides the contextual backbone that enables these components to understand document relationships and make informed decisions about routing, retention, and access control.

### 3.4 Document Integrity Verification

**Hash-Based Integrity:** Every document processed through skseal generates a SHA-256 hash that serves as its content identifier. This hash appears in graph entries, timestamp requests, and signature structures, enabling detection of any document modification. SHA-256 provides sufficient collision resistance for document signing purposes, with the 256-bit output making accidental collision effectively impossible.

**Multi-Layer Integrity Verification:** The integrity verification architecture operates at multiple layers. The document storage layer maintains hash records for stored files, detecting any storage-system corruption or tampering. The cryptographic layer embeds document hashes within PGP signatures, binding the hash to the signer's key. The timestamp layer provides third-party attestation of the hash value at signing time.

**Verification Workflow:** A complete verification operation checks document hash consistency against stored records, validates the PGP signature against the signer's public key, confirms the timestamp token against the TSA's certificate chain, and traces signature chains through the Web of Trust to establish identity confidence. This layered approach provides defense in depth, where compromise at any single layer does not undermine overall verification confidence.

---

## 4. Real Estate and Legal Requirements

### 4.1 Electronic Signature Legal Framework

**eIDAS Regulation (European Union):** The Electronic Identification, Authentication and trust Services (eIDAS) regulation establishes a harmonized framework for electronic signatures, electronic seals, and trust services across the European Union. The regulation defines three types of electronic signatures with different legal effects.

Simple electronic signatures (Article 3) represent any electronic data attached to or logically associated with other electronic data that the signatory uses to sign. These signatures carry legal effect in most business contexts, with the validity and admissibility left to national law and judicial discretion.

Advanced electronic signatures (Article 3) meet specific requirements including unique identification of the signatory, control exclusively by the signatory, detection of any subsequent data changes, and creation using signature creation data that the signatory can use with high confidence. PGP-based signatures meet many advanced signature requirements, particularly when implemented with hardware tokens.

Qualified electronic signatures (Article 3) provide the highest legal assurance, equivalent to handwritten signatures under EU law. These signatures require qualified electronic signature creation devices and are issued by trust service providers supervised by member states. PGP signatures do not automatically qualify as qualified signatures unless used within a qualified electronic signature scheme.

**ESIGN Act (United States):** The Electronic Signatures in Global and National Commerce (ESIGN) Act establishes that electronic signatures carry the same legal effect as handwritten signatures for interstate and international commerce. The law preempts inconsistent state laws while preserving state-level electronic signature frameworks for certain document types.

The Uniform Electronic Transactions Act (UETA), adopted by most states, provides complementary state-level framework consistency. Together, ESIGN and UETA establish that electronic signatures are legally binding for most commercial documents, with exceptions for wills, certain family law documents, and other specified categories.

**Legal Positioning of PGP Signatures:** PGP signatures provide strong evidentiary support for electronic signature validity. The cryptographic binding between signature and document, combined with signer identity verification through the Web of Trust, satisfies the intent-to-sign requirement central to electronic signature law. Courts have generally recognized digital signatures as valid, with specific outcomes depending on the implementation's ability to demonstrate signer control over signing credentials.

### 4.2 Multi-Party Signing Workflows

**Sequential vs. Parallel Signing:** Real estate transactions and commercial agreements frequently require signatures from multiple parties with complex sequencing requirements. Escrow arrangements, for example, may require buyer signatures, lender signatures, and seller signatures in specific orders with contingency provisions.

**Workflow Architecture Requirements:** A legally-sound multi-party signing system must maintain document integrity throughout the entire workflow. Each signer must receive the document in a state that includes all previous signatures, preventing unauthorized modifications between signing events. The system must detect and prevent attempts to insert or modify document content between signatures.

**Evidence Preservation:** Each signing event should generate comprehensive evidence records including timestamps, IP addresses, browser fingerprints, and any available identity verification data. This evidence supports legal challenges to signature authenticity and enables reconstruction of signing circumstances if disputes arise.

### 4.3 Document Retention Requirements

**Legal Hold Considerations:** Organizations operating in regulated industries face specific document retention requirements that extend beyond general business needs. Financial services firms must retain certain transaction documents under SEC regulations. Healthcare organizations must maintain patient records under HIPAA. Real estate professionals must preserve transaction documents for statutory periods ranging from several years to永久.

**Technical Retention Implementation:** skseal should support configurable retention policies that can enforce document preservation periods, prevent premature deletion, and generate audit trails for retention compliance. Integration with enterprise document management systems enables preservation within existing governance frameworks.

**Format Considerations:** Document retention policies should specify acceptable file formats for long-term storage. PDF/A provides an archival format designed for long-term document preservation, supporting embedded fonts, color profiles, and metadata while prohibiting external dependencies. PGP-signed documents should maintain their signatures during archival, with verification procedures that continue to function as cryptographic algorithms age.

### 4.4 Tamper-Evident Sealing

**Seal Definition:** A document seal binds multiple elements together cryptographically: the document content, all signer signatures, timestamp tokens, and metadata. The seal enables any party to verify that the complete document package remains unmodified from its original creation.

**Implementation Strategy:** The seal operation generates a top-level signature covering all document components. This signature uses a dedicated sealing key, enabling seal verification without requiring access to individual signer keys. The seal operation also generates a comprehensive hash that incorporates all component hashes, creating a merkle-tree-like structure that enables partial verification if needed.

**Verification Simplicity:** Any party with access to the sealed document can verify its integrity without maintaining private keys or external service connections. The seal signature validates against the organization's published verification key, while component hashes confirm individual signatures and timestamps remain consistent.

---

## 5. Integration with SKWorld Stack

### 5.1 skref Integration

skref provides encrypted document storage infrastructure that skseal leverages for document persistence and retrieval.

**Storage Architecture:** skref implements an encrypted object store where documents are encrypted at rest using keys derived from the skref master key. This encryption protects document confidentiality during storage, transmission, and any storage system breaches. The encryption operates transparently to skseal, which receives decrypted document streams for processing.

**Document Addressing:** skref assigns each document a unique reference identifier that enables efficient retrieval without revealing document contents to unauthorized parties. The reference includes versioning information, enabling skseal to work with document revisions while maintaining complete history.

**Encryption Key Management:** For multi-party documents, skref supports encrypted envelopes where documents are encrypted under multiple recipient keys. This capability enables signers to access encrypted documents using their own keys, supporting sovereignty objectives where no single party controls document access.

### 5.2 SKGraph Integration

SKGraph provides the relationship and provenance tracking layer that enables sophisticated document workflows and compliance auditing.

**Signing Event Recording:** Every signing operation generates graph entries recording the event's participants, timing, and document context. These entries form a chain of evidence that supports legal challenges and compliance audits. The graph structure enables queries across the full signing history, identifying all documents in a workflow or all documents signed by a particular key.

**Workflow State Management:** Multi-party workflows track their state through SKGraph, with edges representing transitions between workflow stages. The graph enables workflow execution agents to understand current state, pending actions, and available transitions.

**Relationship Discovery:** Organizations benefit from discovering implicit relationships between documents. Documents created from the same template, signed by parties with common relationships, or part of related transactions can be identified through graph queries. This capability supports due diligence processes and compliance monitoring.

### 5.3 skcapstone Integration

skcapstone provides agent orchestration capabilities that enable automated document workflow execution.

**Workflow Automation:** skcapstone agents monitor SKGraph for workflow state changes, triggering automated actions based on workflow rules. When a document reaches a state requiring specific signatures, skcapstone can initiate reminder notifications, route documents to appropriate signers, or pause workflows pending external events.

**Conditional Signing:** Complex workflows often require conditional logic where later signatures depend on earlier verification outcomes. skcapstone agents can evaluate conditions and route documents accordingly, enabling workflows that reflect real-world business logic.

**Integration Pattern:** skcapstone communicates with skseal through the SKGraph event stream, monitoring workflow states and submitting signing commands when conditions are met. This loose coupling enables independent scaling of workflow automation and document signing components.

### 5.4 Email Integration

Email remains the dominant communication channel for document signing invitations, and skseal integrates with existing email infrastructure to support these workflows.

**Invitation Workflow:** When a document requires external signatures, skseal generates email invitations containing secure signing links. The links include authentication tokens that verify recipient identity without requiring separate accounts, enabling friction-free signing for external parties.

**Notification Delivery:** Signers receive notifications at workflow milestones, including document arrival, signature requests, signing completions, and workflow conclusions. Notification preferences enable customization of timing and content for each signer.

**Security Considerations:** Email invitations must balance security with usability. Tokenized links provide authentication without requiring password authentication, but introduce link sharing risks. Implementing token expiration, link invalidation upon completion, and browser fingerprint verification mitigates these risks while maintaining reasonable usability.

---

## 6. Architecture Comparison

### 6.1 DocuSeal vs. skseal Feature Matrix

| Aspect | DocuSeal | skseal |
|--------|----------|--------|
| **Primary Technology** | Ruby on Rails, Vue.js, PDF forms | Node.js/Go, OpenPGP.js, PGP signatures |
| **Signature Type** | PDF digital signatures | PGP cleartext/detached signatures |
| **Identity Model** | Email-based accounts | PGP Web of Trust |
| **Deployment** | Docker container | Docker container |
| **Storage** | S3-compatible, filesystem | skref integration |
| **Trust Model** | Centralized platform | Decentralized Web of Trust |
| **Legal Compliance** | eIDAS advanced signatures | PGP signatures with timestamping |
| **Audit Trail** | Platform logs | SKGraph relationship graph |
| **Automation** | API, webhooks | skcapstone agent orchestration |
| **Cost Model** | Free (AGPL) / Pro license | Open source |

### 6.2 Architectural Tradeoffs

**User Experience vs. Sovereignty:** DocuSeal prioritizes user experience, providing intuitive form builders and familiar PDF signing paradigms. skseal prioritizes cryptographic sovereignty, accepting greater user friction in exchange for verifiable trust independent of platform providers.

**Convenience vs. Verification:** DocuSeal's PDF signatures can be verified by any PDF reader, providing universal verification capability. skseal verification requires PGP toolchain familiarity or specialized verification tools, limiting verification accessibility.

**Platform Dependency:** DocuSeal requires continued platform operation for complete verification. skseal verification depends only on cryptographic keys and timestamp services, providing verification capability even if the skseal platform becomes unavailable.

---

## 7. Technical Specification for skseal MVP

### 7.1 System Components

**Frontend Application:** A React-based single-page application provides the user interface for document management, template creation, and signing ceremonies. The frontend communicates exclusively through the API layer, never accessing backend systems directly.

**Backend API:** A Node.js API server implementing RESTful endpoints handles document operations, user authentication (for internal users), and workflow management. The API layer integrates with OpenPGP.js for client-side signing operations and with backend services for server-side operations.

**Signing Service:** The signing service handles cryptographic operations that cannot occur in the browser context, including timestamp requests, seal operations, and verification services. The signing service integrates with hardware token infrastructure for organizations requiring hardware key protection.

**Timestamp Authority Client:** The timestamp client interfaces with configured RFC 3161 timestamping authorities, requesting tokens for signed documents and validating tokens during verification operations.

### 7.2 Data Model

**Documents:** Documents represent the primary entities, containing metadata, version history, and references to stored file content. Documents track their current workflow state and maintain pointers to all signatures and timestamps.

**Signatures:** Signature records link documents to signing keys, storing the PGP signature data, signing time, and verification status. Signatures reference Web of Trust certification chains enabling trust analysis.

**Timestamps:** Timestamp records connect documents to TSA responses, storing the timestamp token and associated metadata. Timestamp records enable long-term verification even as cryptographic algorithms age.

**Keys:** Key records store PGP public key metadata and optionally cached public key data. Key records track trust relationships and signature certifications.

### 7.3 API Endpoints

**Document Operations:**
- `POST /documents` — Create new document from uploaded file
- `GET /documents/{id}` — Retrieve document metadata and status
- `GET /documents/{id}/content` — Retrieve current document content
- `POST /documents/{id}/sign` — Initiate signing ceremony
- `GET /documents/{id}/signatures` — List all signatures
- `GET /documents/{id}/verify` — Perform full verification

**Template Operations:**
- `POST /templates` — Create document template
- `GET /templates` — List available templates
- `PUT /templates/{id}` — Update template configuration

**Workflow Operations:**
- `POST /workflows` — Create multi-party workflow
- `GET /workflows/{id}` — Retrieve workflow status
- `PUT /workflows/{id}/advance` — Advance workflow to next state

**Verification Operations:**
- `POST /verify` — Verify document and signature package
- `GET /verify/{id}` — Retrieve verification results

### 7.4 Security Considerations

**Private Key Protection:** The MVP supports three private key protection modes. Software keys are encrypted with user-provided passphrases using OpenPGP's integrated encryption. Browser-based keys are stored in IndexedDB with Web Crypto API protection. Hardware tokens are accessed through native messaging bridges with user confirmation for each operation.

**Session Security:** Authentication uses short-lived JWT tokens with refresh token rotation. All API communication occurs over TLS 1.3, with certificate pinning for mobile clients.

**Audit Logging:** All significant operations generate audit log entries including operation type, timestamp, actor identity, and operation target. Audit logs are append-only and cryptographically hashed to prevent tampering.

---

## 8. Implementation Roadmap

### 8.1 Phase 1: Core Platform (Months 1-3)

The initial phase establishes fundamental document signing capability with simple single-party workflows. Deliverables include the React frontend with document upload and template management, the Node.js API with basic authentication, OpenPGP.js integration for client-side signing, Docker deployment configuration, and basic verification UI.

### 8.2 Phase 2: Multi-Party Workflows (Months 4-6)

The second phase adds workflow orchestration for documents requiring multiple signers. Deliverables include workflow state machine implementation, sequential and parallel signing support, SKGraph integration for audit trails, email notification system, and reminder and timeout handling.

### 8.3 Phase 3: Trust Infrastructure (Months 7-9)

The third phase establishes the trust architecture that differentiates skseal from conventional platforms. Deliverables include Web of Trust key certification UI, RFC 3161 timestamp authority integration, seal operation implementation, trust chain visualization, and advanced verification reporting.

### 8.4 Phase 4: SKWorld Integration (Months 10-12)

The final phase integrates skseal with the broader SKWorld infrastructure. Deliverables include skref storage integration, skcapstone workflow automation, enterprise deployment configuration, compliance reporting tools, and SSO integration support.

---

## 9. Conclusion

This research establishes the technical foundation for skseal, a sovereign document signing platform that prioritizes cryptographic verification and user sovereignty over convenience-focused features. By leveraging OpenPGP.js for browser-based cryptography, the PGP Web of Trust for identity verification, and SKGraph for audit trail maintenance, skseal provides a fundamentally different approach to electronic signing than conventional platforms like DocuSeal.

The platform addresses a specific market segment: organizations and individuals who prioritize verification independence, cryptographic transparency, and freedom from vendor lock-in. While skseal will not match DocuSeal's user experience simplicity, it offers superior properties for legal and compliance contexts where verification capability and sovereign control take precedence.

The integration with existing SKWorld components—skref for encrypted storage, SKGraph for relationship tracking, and skcapstone for workflow automation—leverages existing infrastructure investments while extending their capabilities to document signing workflows. This integration transforms skseal from a standalone tool into a component of a comprehensive sovereign identity and document management ecosystem.

---

## Research Notes

### Sources Consulted

- DocuSeal official documentation and GitHub repository
- OpenPGP.js official documentation and source code
- RFC 3161 Time-Stamp Protocol specification
- eIDAS Regulation (EU) 910/2014
- ESIGN Act (15 U.S.C. § 7001 et seq.)
- Sigstore Timestamp Authority documentation
- YubiKey and Nitrokey integration guides
- WebPG project documentation

### Areas Requiring Further Research

- Specific legal precedent for PGP signature validity in various jurisdictions
- Performance optimization for large document signing workflows
- Mobile application architecture for hardware token access
- Compliance requirements for specific regulated industries
- User experience research for trust visualization and verification

### Document Version History

- 1.0 — Initial research document (February 2026)

---

*Research conducted for SKWorld Infrastructure Development*