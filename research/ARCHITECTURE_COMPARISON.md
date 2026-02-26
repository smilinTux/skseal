# Architecture Comparison: DocuSeal vs skseal
## Technical and Strategic Analysis

**Document Version:** 1.0  
**Date:** February 25, 2026  
**Purpose:** Decision framework for skseal platform architecture

---

## Executive Summary

This document provides a comprehensive architectural comparison between DocuSeal, the leading open-source e-signature platform, and skseal, the proposed PGP-based sovereign document signing platform. The analysis covers technology stacks, security models, deployment approaches, and integration capabilities to inform architectural decisions for skseal development.

The fundamental architectural distinction lies in their trust models: DocuSeal employs a platform-centric model where trust derives from the platform operator, while skseal implements a user-centric model where cryptographic verification depends on signer-controlled PGP keys. This distinction has profound implications for every architectural layer, from database design to API implementation.

---

## 1. Technology Stack Comparison

### 1.1 Backend Architecture

| Aspect | DocuSeal | skseal |
|--------|----------|--------|
| **Primary Framework** | Ruby on Rails 7 | Node.js 20 (Express/Fastify) or Go 1.22 |
| **Database** | PostgreSQL (primary), MySQL, SQLite | PostgreSQL 16+ with pgvector |
| **Cache Layer** | Redis for session storage and queues | Redis for caching, JWT tokens, rate limiting |
| **Message Queue** | Sidekiq (Ruby-based) | BullMQ (Node.js) or NATS (Go) |
| **API Style** | REST with JSON | REST + GraphQL for complex queries |
| **Authentication** | Built-in with JWT tokens | JWT with WebAuthn/FIDO2 support |
| **File Storage** | Local filesystem, S3, GCS, Azure | skref integration, S3-compatible |

### 1.2 Frontend Architecture

| Aspect | DocuSeal | skseal |
|--------|----------|--------|
| **Framework** | Vue.js 3 with Composition API | React 18 with TypeScript |
| **State Management** | Vue Reactivity API + Pinia | Redux Toolkit + React Query |
| **PDF Rendering** | Custom PDF.js integration | pdf-lib + React-PDF |
| **Drag-and-Drop** | Custom Vue components | dnd-kit or react-beautiful-dnd |
| **Build Tool** | Webpack 5 | Vite 5 |
| **CSS Framework** | Custom CSS + Tailwind | Tailwind CSS + shadcn/ui |

### 1.3 Cryptographic Implementation

| Aspect | DocuSeal | skseal |
|--------|----------|--------|
| **Client Crypto** | None (all server-side) | OpenPGP.js for browser operations |
| **Server Crypto** | Ruby OpenSSL bindings | Node.js crypto or Go crypto/tls |
| **Hardware Token** | N/A | PKCS#11 via OpenSC, native messaging |
| **Timestamping** | Built-in digital signatures | RFC 3161 TSA client + OpenTimestamps |
| **Key Management** | Platform-managed keys | User-controlled PGP keys + SKKey Vault |

### 1.4 Containerization and Deployment

| Aspect | DocuSeal | skseal |
|--------|----------|--------|
| **Container Format** | Docker single-container | Docker Compose + Kubernetes manifests |
| **Orchestration** | Docker Compose (basic) | Kustomize for multi-environment |
| **Reverse Proxy** | Caddy (built-in) | Traefik or Nginx |
| **Service Mesh** | N/A | Linkerd for zero-trust networking |
| **Secrets Management** | Environment variables | HashiCorp Vault integration |

---

## 2. Security Architecture Comparison

### 2.1 Trust Models

**DocuSeal Trust Model: Platform-Centric**

```
┌─────────────────────────────────────────────────────────────────┐
│                    DOCUSEAL TRUST MODEL                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│    ┌─────────────────────────────────────────────────────┐       │
│    │              DocuSeal Platform                       │       │
│    │  ┌─────────────────────────────────────────────┐    │       │
│    │  │  Platform Identity (platform SSL/TLS cert)  │    │       │
│    │  │  └── Signs all PDF digital signatures       │    │       │
│    │  └─────────────────────────────────────────────┘    │       │
│    │                          ▲                           │       │
│    │                          │                           │       │
│    │     Users trust platform │                           │       │
│    │     for identity proof   │                           │       │
│    │                          ▼                           │       │
│    │  ┌─────────────────────────────────────────────┐    │       │
│    │  │  User Accounts (email + password)           │    │       │
│    │  │  └── Platform verifies signer identity      │    │       │
│    │  └─────────────────────────────────────────────┘    │       │
│    │                                                  │       │
│    └─────────────────┬───────────────────────────────┘       │
│                      │                                       │
│                      ▼                                       │
│         ┌────────────────────────────┐                       │
│         │   Signed PDF Documents     │                       │
│         │   (Platform verifies       │                       │
│         │    signature validity)     │                       │
│         └────────────────────────────┘                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**skseal Trust Model: User-Centric (Sovereign)**

```
┌─────────────────────────────────────────────────────────────────┐
│                    SKSEAL TRUST MODEL                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│    ┌──────────────────────────────────────────┐                │
│    │     Signer PGP Key (User Controlled)     │                │
│    │  ┌────────────────────────────────────┐  │                │
│    │  │  Private Key (never leaves device)  │  │                │
│    │  │  └── Signs documents locally        │  │                │
│    │  │  Public Key (distributed via WKD)   │  │                │
│    │  └────────────────────────────────────┘  │                │
│    └────────────────────────┬───────────────────┘                │
│                             │                                    │
│                             ▼                                    │
│    ┌──────────────────────────────────────────┐                │
│    │  Web of Trust Chain                      │                │
│    │  • Key signing parties                   │                │
│    │  • Certification paths                   │                │
│    │  • Trust level propagation              │                │
│    └────────────────────────┬───────────────────┘                │
│                             │                                    │
│                             ▼                                    │
│    ┌──────────────────────────────────────────┐                │
│    │  Timestamping Authority (Third Party)    │                │
│    │  • RFC 3161 timestamp tokens             │                │
│    │  • Non-repudiation proof                 │                │
│    └────────────────────────┬───────────────────┘                │
│                             │                                    │
│                             ▼                                    │
│    ┌──────────────────────────────────────────┐                │
│    │   SKGraph Audit Trail                    │                │
│    │   • Signing event provenance             │                │
│    │   • Relationship tracking                │                │
│    │   • Compliance documentation            │                │
│    └──────────────────────────────────────────┘                │
│                                                                  │
│    NO PLATFORM TRUST REQUIRED - User verifies independently      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Identity Verification Comparison

| Verification Method | DocuSeal | skseal |
|--------------------|----------|--------|
| **Email Verification** | ✓ Built-in | ✓ Email link + PGP key binding |
| **SMS 2FA** | Pro feature | Optional via Twilio/SMS APIs |
| **Knowledge-Based Auth** | Pro feature | Optional integration |
| **Web of Trust** | ✗ | ✓ Primary identity mechanism |
| **Hardware Tokens** | ✗ | ✓ YubiKey, NitroKey, HSM |
| **Government ID** | Pro feature | Future integration (onboarding) |
| **Biometric** | ✗ | Browser WebAuthn/FIDO2 |

### 2.3 Cryptographic Signing Comparison

| Aspect | DocuSeal | skseal |
|--------|----------|--------|
| **Signature Format** | PDF digital signature (PKCS#7/CMS) | PGP cleartext/detached signature |
| **Algorithm Support** | RSA, ECDSA (native to PDF library) | RSA, ECC (OpenPGP standard) |
| **Key Storage** | Server-side, platform-managed | Client-side, user-controlled |
| **Hardware Security** | HSM for enterprise (Pro) | PKCS#11 tokens, smart cards |
| **Timestamp** | Built-in document timestamps | RFC 3161 + OpenTimestamps |
| **Long-Term Validation** | Document-level only | Timestamp + signature chain |
| **Verification** | Platform-dependent | Universal (GnuPG, etc.) |

### 2.4 Data Protection Comparison

| Protection Type | DocuSeal | skseal |
|-----------------|----------|--------|
| **In Transit** | TLS 1.3 | TLS 1.3 + mTLS for services |
| **At Rest** | Database encryption (configurable) | skref encrypted storage |
| **Field-Level** | ✗ | PGP encrypted field values |
| **Access Control** | Role-based (admin, user) | Role-based + PGP key-based |
| **Audit Logging** | ✓ Built-in | ✓ Enhanced via SKGraph |
| **Data Sovereignty** | Server location-dependent | Client-side encryption ensures sovereignty |

---

## 3. Feature Comparison Matrix

### 3.1 Core Document Features

| Feature | DocuSeal | skseal | Notes |
|---------|----------|--------|-------|
| **PDF Upload** | ✓ | ✓ | Both support drag-and-drop |
| **Multi-Page Docs** | ✓ | ✓ | Both support multi-page PDFs |
| **Template Storage** | ✓ | ✓ | Both support template libraries |
| **Template Versioning** | ✓ Clone only | ✓ Git-style versioning | skseal advantage |
| **Template Import/Export** | JSON | JSON + PGP-signed bundles | skseal advantage |
| **Bulk Send** | Pro feature | Via API + skcapstone | Similar capability |
| **Document Merge** | ✓ | ✓ | Both support merging |
| **Blank Page Add** | ✓ | ✓ | Both support this |

### 3.2 Form Builder Features

| Feature | DocuSeal | skseal | Notes |
|---------|----------|--------|-------|
| **Drag-and-Drop Fields** | ✓ | ✓ | Core UX feature |
| **Field Types** | 18 types | 12 types + PGP-specific | DocuSeal advantage |
| **WYSIWYG Editor** | ✓ | ✓ | Both excellent |
| **Field Validation** | ✓ | ✓ | Both comprehensive |
| **Conditional Logic** | Pro feature | Via SKGraph rules | Similar capability |
| **Auto-Field Detection** | AI-powered | Future ML integration | Both advancing |
| **Form Prefill** | ✓ | ✓ | Both support |
| **Multi-Signer Roles** | ✓ | ✓ | Both support |

### 3.3 PGP-Specific Features (skseal Only)

| Feature | Description | Value Proposition |
|---------|-------------|-------------------|
| **Web of Trust Key Import** | Import keys with trust signatures | Sovereign identity |
| **Key Signing Ceremonies** | Schedule and conduct key signing events | Build trust network |
| **Signature Transparency** | Log signatures to SKGraph | Auditability |
| **Detached Signatures** | Separate .sig files for documents | Verification flexibility |
| **Timestamp Tokens** | RFC 3161 tokens with signatures | Non-repudiation |
| **Hardware Token Flow** | Browser → Native App → Token | Highest security |
| **Key Revocation Tracking** | Monitor key status via SKGraph | Security assurance |
| **Trust Path Visualization** | Show certification chains | Identity confidence |

---

## 4. Deployment Comparison

### 4.1 Self-Hosted Deployment

| Aspect | DocuSeal | skseal |
|--------|----------|--------|
| **Docker Image** | Single image (official) | Multi-container stack |
| **Docker Compose** | ✓ Official support | ✓ Compose + K8s manifests |
| **Kubernetes** | Community examples | Full manifests with operators |
| **Resource Requirements** | 2 CPU, 2GB RAM minimum | Similar baseline |
| **Database Options** | PostgreSQL, MySQL, SQLite | PostgreSQL only |
| **Object Storage** | S3, GCS, Azure, local | S3-compatible via skref |
| **Email (SMTP)** | Built-in | SMTP + Sendmail integration |
| **SSL Certificates** | Automatic via Caddy | cert-manager integration |
| **Updates** | Docker image refresh | Rolling updates with canary |

### 4.2 Cloud Deployment

| Aspect | DocuSeal | skseal |
|--------|----------|--------|
| **Official Cloud** | ✓ DocuSeal Cloud | Not planned (sovereign focus) |
| **Heroku** | ✓ One-click deploy | Via Docker |
| **DigitalOcean** | ✓ App Platform | ✓ Droplets + Docker |
| **AWS** | ✓ Elastic Beanstalk | ✓ ECS/EKS |
| **GCP** | ✓ Cloud Run | ✓ GKE |
| **Azure** | ✓ Container Apps | ✓ AKS |

### 4.3 Enterprise Features

| Feature | DocuSeal (Pro) | skseal |
|---------|---------------|--------|
| **SSO/SAML** | ✓ | ✓ Keycloak integration |
| **Audit Reports** | ✓ | ✓ Enhanced via SKGraph |
| **Custom Branding** | ✓ | ✓ Theming system |
| **SLA Guarantees** | Cloud only | N/A (self-hosted focus) |
| **Support Channels** | Email, Discord | Community + enterprise contracts |
| **HIPAA Compliance** | ✓ | ✓ BAA available |
| **SOC 2** | ✓ | Attestation in progress |

---

## 5. API and Integration Comparison

### 5.1 API Architecture

| Aspect | DocuSeal | skseal |
|--------|----------|--------|
| **REST Endpoints** | ~50 endpoints | ~60 endpoints + GraphQL |
| **Authentication** | API key (header) | JWT tokens + API keys |
| **Rate Limiting** | Platform-dependent | Configurable per tenant |
| **Webhooks** | ✓ Built-in | ✓ Event-driven via NATS |
| **SDKs** | JS, React, Vue, Angular | JS/TS, Python, Go |
| **OpenAPI Spec** | ✓ Full specification | ✓ OpenAPI 3.1 + GraphQL SDL |
| **API Versioning** | URL path (/v1/) | Header-based + URL |

### 5.2 Key API Endpoints Comparison

| Function | DocuSeal Endpoint | skseal Endpoint |
|----------|-------------------|-----------------|
| **Create Template** | POST /templates/pdf | POST /api/v1/templates |
| **List Templates** | GET /templates | GET /api/v1/templates |
| **Create Submission** | POST /submissions | POST /api/v1/workflows |
| **Submitter Status** | GET /submissions/{id} | GET /api/v1/workflows/{id} |
| **Download Signed** | GET /submissions/{id}/documents | GET /api/v1/documents/{id}/signed |
| **Verify Signature** | Platform UI only | GET /api/v1/verify/{id} |
| **Key Management** | N/A | GET/POST /api/v1/keys |
| **Timestamp Request** | N/A | POST /api/v1/timestamp |

### 5.3 Integration with SKWorld (skseal Advantage)

| SKWorld Component | DocuSeal | skseal |
|-------------------|----------|--------|
| **skref Storage** | ✗ | ✓ Native integration |
| **SKGraph Audit** | ✗ | ✓ Native graph events |
| **skcapstone Workflow** | ✗ | ✓ Agent orchestration |
| **SKAuth Identity** | ✗ | ✓ PGP key integration |
| **SKKey Vault** | ✗ | ✓ Key ceremony support |
| **SKNotify** | Via SMTP | ✓ Unified notification |

### 5.4 Third-Party Integrations

| Integration Type | DocuSeal | skseal |
|-----------------|----------|--------|
| **CRM Systems** | Zapier, custom API | Zapier + n8n |
| **Storage** | S3, GCS, Azure | S3-compatible + skref |
| **Authentication** | SAML, SSO | SAML + Keycloak + WebAuthn |
| **Payment** | Stripe (Pro) | Stripe integration planned |
| **eIDAS/QES** | ✓ Qualified signatures | Future integration |
| **Salesforce** | AppExchange app | Custom integration |

---

## 6. Performance Characteristics

### 6.1 Document Processing

| Metric | DocuSeal | skseal |
|--------|----------|--------|
| **PDF Upload** | 10 MB/s typical | Similar + client-side validation |
| **Template Render** | <500ms for 10-page doc | Similar with caching |
| **Signature Generation** | Server-side, ~200ms | Client-side (OpenPGP.js) |
| **Verification** | Server API call | Client-side possible |
| **Concurrent Users** | ~500/user (per instance) | Similar + horizontal scaling |
| **Documents/Day** | Unlimited (self-hosted) | Unlimited + PGP processing |

### 6.2 Scalability Architecture

| Aspect | DocuSeal | skseal |
|--------|----------|--------|
| **Horizontal Scaling** | Load balancer + multiple instances | Same + service mesh |
| **Stateless Design** | Partial (sessions in Redis) | Fully stateless API |
| **Database Scaling** | Read replicas supported | Read replicas + pgvector |
| **Cache Strategy** | Redis for sessions | Multi-layer (CDN, Redis, local) |
| **CDN Integration** | Asset CDN only | Full document CDN via skref |

---

## 7. Cost Analysis Comparison

### 7.1 Self-Hosted TCO (Annual, ~1000 documents/month)

| Cost Component | DocuSeal | skseal |
|----------------|----------|--------|
| **Software License** | Free (AGPL) | Free (AGPL) |
| **Infrastructure** | $600-1,200/year (VPS) | Similar |
| **Database** | Included in VPS | Similar |
| **SSL Certificates** | Included (Caddy) | cert-manager (free) |
| **Maintenance Hours** | ~20 hours/year | ~30 hours/year (PGP complexity) |
| **Support** | Community (free) | Community (free) |
| **Total Annual TCO** | $600-1,200 | $800-1,500 |

### 7.2 Key Cost Differentiators

| Factor | DocuSeal | skseal |
|--------|----------|--------|
| **Per-Document Fees** | $0.20 (API/Embedding Pro) | None |
| **User Seat Fees** | $240/year (Pro) | None |
| **Enterprise Support** | ~$5,000+/year | Similar tiers |
| **Custom Development** | Available | Available |
| **Training** | Documentation + guides | Documentation + PKI training |

---

## 8. Risk Assessment

### 8.1 DocuSeal Risk Factors

| Risk | Severity | Mitigation |
|------|----------|------------|
| **AGPL License** | Medium | Review compliance requirements |
| **Single Vendor** | Medium | Fork if needed (AGPL allows) |
| **Ruby Ecosystem** | Low | Mature, stable, well-supported |
| **PDF Processing** | Low | Multiple open-source options |
| **Cloud Lock-in** | Low | Self-hosted, open formats |

### 8.2 skseal Risk Factors

| Risk | Severity | Mitigation |
|------|----------|------------|
| **User Complexity** | High | Excellent UX, onboarding flows |
| **Key Management** | High | Guided ceremonies, recovery flows |
| **WOT Adoption** | Medium | Bootstrap with organizational keys |
| **Browser Limitations** | Medium | Native apps for advanced features |
| **Legal Recognition** | Low | PGP signatures recognized broadly |

### 8.3 Comparative Risk Summary

| Dimension | DocuSeal | skseal |
|-----------|----------|--------|
| **User Adoption Barrier** | Low | Medium-High |
| **Sovereign Control** | Low (platform trust) | High (user keys) |
| **Vendor Dependency** | Medium (DocuSeal LLC) | Low (open source) |
| **Cryptographic Future-Proofing** | Medium | High (standard protocols) |
| **Compliance Path** | Documented (eIDAS, ESIGN) | Requires legal review |

---

## 9. Migration Considerations

### 9.1 DocuSeal to skseal Migration Path

| Component | Migration Approach | Complexity |
|-----------|-------------------|------------|
| **Templates** | Export JSON, convert field types | Medium |
| **Documents** | Re-sign with PGP required | High |
| **Users** | New accounts, import keys | Medium |
| **Audit History** | Partial import via SKGraph | Medium |
| **Integrations** | API endpoint mapping | Low |

### 9.2 Template Conversion Mapping

| DocuSeal Field | skseal Equivalent | Notes |
|----------------|-------------------|-------|
| Signature | PGP Signature | Draw/upload → Key selection |
| Initials | Initials + PGP | Similar UX |
| Text | Text | Same |
| Date | Date | Same |
| Checkbox | Checkbox | Same |
| Number | Number | Same |
| Select | Select | Same |
| File | File Attach | Same |
| Image | Image | Same |
| Heading | Heading | Same |
| Payment | Payment | Skip (not PGP-focused) |
| Verification | 2FA + Key | Enhanced with PGP |
| KBA | KBA | Same |
| Phone | Phone | Same |

---

## 10. Recommendations

### 10.1 When to Choose DocuSeal

DocuSeal remains the optimal choice for organizations prioritizing user experience and rapid deployment over cryptographic sovereignty. The platform excels in scenarios including general business contracts, sales agreements, employee onboarding, and any context where document signing convenience outweighs verification independence.

Organizations should choose DocuSeal when their signing participants are not technically sophisticated, when they already operate within a trusted platform environment, and when regulatory requirements align with DocuSeal's documented compliance framework.

### 10.2 When to Choose skseal

skseal serves organizations requiring cryptographic independence, sovereign identity verification, and long-term document verification without platform dependency. Key adoption scenarios include government agencies, legal practitioners handling sensitive documents, human rights organizations, financial services operating under strict data sovereignty requirements, and any context where document integrity verification must function without platform access.

Organizations should choose skseal when they possess or can develop PGP expertise, when signing participants include technically capable users, and when long-term verification independence justifies increased initial complexity.

### 10.3 Hybrid Architecture Option

For organizations transitioning from DocuSeal to skseal, or operating in mixed-trust environments, a hybrid architecture enables coexistence:

```
┌─────────────────────────────────────────────────────────────────┐
│                   HYBRID ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────────┐      ┌─────────────────┐                  │
│   │   DocuSeal      │      │    skseal       │                  │
│   │   (Convenience) │◄────►│   (Sovereign)   │                  │
│   └────────┬────────┘      └────────┬────────┘                  │
│            │                        │                            │
│            │    ┌───────────────────┘                            │
│            │    │                                                │
│            ▼    ▼                                                │
│   ┌─────────────────────────────┐                               │
│   │     Document Bridge         │                               │
│   │  • Import DocuSeal docs     │                               │
│   │  • Convert to PGP signed    │                               │
│   │  • Sync status via webhooks │                               │
│   └─────────────────────────────┘                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Conclusion

DocuSeal and skseal serve complementary market segments. DocuSeal excels in user experience and rapid deployment, making it the default choice for organizations prioritizing convenience. skseal addresses the sovereignty-focused segment where cryptographic verification independence justifies increased complexity.

The architectural comparison demonstrates that skseal's sovereign approach requires tradeoffs in user experience complexity and initial onboarding effort. However, for organizations where these costs are acceptable, skseal provides verification capabilities and user control that platform-centric solutions cannot match.

**Decision Framework:**

| Priority | Recommended Platform |
|----------|---------------------|
| User simplicity | DocuSeal |
| Quick deployment | DocuSeal |
| Sovereign identity | skseal |
| Long-term verification | skseal |
| Regulatory compliance | Evaluate both |
| Cost (high volume) | skseal (no per-document fees) |
| Technical capacity available | skseal |

---

**Document Version:** 1.0  
**Analysis Date:** February 25, 2026  
**Next Review:** Upon skseal MVP completion