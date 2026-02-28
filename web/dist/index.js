var Ke = Object.defineProperty;
var Ue = (d, t, n) => t in d ? Ke(d, t, { enumerable: !0, configurable: !0, writable: !0, value: n }) : d[t] = n;
var L = (d, t, n) => Ue(d, typeof t != "symbol" ? t + "" : t, n);
import * as P from "openpgp";
import { defineComponent as ue, ref as w, computed as G, watch as ie, onMounted as ce, openBlock as y, createElementBlock as g, createElementVNode as r, withDirectives as C, vModelText as W, toDisplayString as k, Fragment as I, renderList as E, normalizeClass as X, normalizeStyle as Z, withModifiers as Pe, vModelSelect as Q, vModelCheckbox as le, createTextVNode as ee, createCommentVNode as H, withKeys as $e, vModelDynamic as Ce } from "vue";
async function Te(d, t, n) {
  const { privateKey: i, publicKey: s } = await P.generateKey({
    type: "curve25519",
    userIDs: [{ name: d, email: t }],
    passphrase: n,
    format: "armored"
  });
  return {
    fingerprint: (await P.readKey({ armoredKey: s })).getFingerprint().toUpperCase(),
    publicKeyArmor: s,
    privateKeyArmor: i,
    name: d,
    email: t,
    createdAt: /* @__PURE__ */ new Date()
  };
}
async function Ae(d) {
  const t = await P.readPrivateKey({ armoredKey: d }), n = t.getFingerprint().toUpperCase(), s = (await t.getPrimaryUser()).user.userID;
  return {
    fingerprint: n,
    name: (s == null ? void 0 : s.name) ?? "",
    email: (s == null ? void 0 : s.email) ?? "",
    publicKeyArmor: t.toPublic().armor()
  };
}
async function It(d) {
  const t = await P.readKey({ armoredKey: d }), n = t.getFingerprint().toUpperCase(), s = (await t.getPrimaryUser()).user.userID;
  return {
    fingerprint: n,
    name: (s == null ? void 0 : s.name) ?? "",
    email: (s == null ? void 0 : s.email) ?? ""
  };
}
async function te(d) {
  const t = await crypto.subtle.digest("SHA-256", d);
  return Array.from(new Uint8Array(t)).map((n) => n.toString(16).padStart(2, "0")).join("");
}
async function Me(d, t, n) {
  const i = await te(d), s = await P.readPrivateKey({
    armoredKey: t
  }), o = await P.decryptKey({
    privateKey: s,
    passphrase: n
  }), p = await P.createMessage({
    binary: new TextEncoder().encode(i)
  }), v = await P.sign({
    message: p,
    signingKeys: o
  }), h = o.getFingerprint().toUpperCase();
  return {
    signatureArmor: v,
    documentHash: i,
    fingerprint: h,
    signedAt: /* @__PURE__ */ new Date()
  };
}
async function Et(d, t, n) {
  const i = await P.readPrivateKey({
    armoredKey: t
  }), s = await P.decryptKey({
    privateKey: i,
    passphrase: n
  }), o = await P.createMessage({ binary: d });
  return await P.sign({ message: o, signingKeys: s });
}
async function Fe(d, t, n, i) {
  var s;
  try {
    const o = await P.readKey({ armoredKey: n }), p = await P.readMessage({ armoredMessage: t }), v = o.getFingerprint().toUpperCase(), h = await P.verify({
      message: p,
      verificationKeys: o
    }), { verified: b, signature: _ } = h.signatures[0];
    if (await b, d !== null) {
      const x = await te(d), M = h.data;
      if ((typeof M == "string" ? M : new TextDecoder().decode(M)) !== x)
        return {
          valid: !1,
          fingerprint: v,
          error: "Document has been modified since signing"
        };
    }
    if (i) {
      const x = h.data;
      if ((typeof x == "string" ? x : new TextDecoder().decode(x)) !== i)
        return {
          valid: !1,
          fingerprint: v,
          error: "Hash mismatch with expected document hash"
        };
    }
    const A = (s = (await _).packets) != null && s[0] ? /* @__PURE__ */ new Date() : void 0;
    return { valid: !0, fingerprint: v, signedAt: A };
  } catch (o) {
    return {
      valid: !1,
      fingerprint: "",
      error: o instanceof Error ? o.message : String(o)
    };
  }
}
async function Ot(d) {
  try {
    return (await P.readKey({ armoredKey: d })).getFingerprint().toUpperCase();
  } catch {
    return (await P.readPrivateKey({ armoredKey: d })).getFingerprint().toUpperCase();
  }
}
const Ve = "skseal-keys", He = 1, F = "keys";
function q() {
  return new Promise((d, t) => {
    const n = indexedDB.open(Ve, He);
    n.onupgradeneeded = () => {
      const i = n.result;
      i.objectStoreNames.contains(F) || i.createObjectStore(F, { keyPath: "fingerprint" });
    }, n.onsuccess = () => d(n.result), n.onerror = () => t(n.error);
  });
}
function z() {
  return typeof indexedDB < "u";
}
const J = /* @__PURE__ */ new Map();
class Ne {
  /**
   * Store a key pair in the browser's IndexedDB.
   *
   * The private key MUST be passphrase-protected before calling this.
   * This method does NOT encrypt — it stores whatever you give it.
   *
   * @param key - Key to store (fingerprint, armored keys, metadata)
   */
  async store(t) {
    if (!z()) {
      J.set(t.fingerprint, t);
      return;
    }
    const n = await q();
    return new Promise((i, s) => {
      const o = n.transaction(F, "readwrite");
      o.objectStore(F).put(t), o.oncomplete = () => {
        n.close(), i();
      }, o.onerror = () => {
        n.close(), s(o.error);
      };
    });
  }
  /**
   * Retrieve a key by fingerprint.
   *
   * @param fingerprint - 40-char hex PGP fingerprint (case-insensitive)
   * @returns Stored key or null if not found
   */
  async get(t) {
    const n = t.toUpperCase();
    if (!z())
      return J.get(n) ?? null;
    const i = await q();
    return new Promise((s, o) => {
      const v = i.transaction(F, "readonly").objectStore(F).get(n);
      v.onsuccess = () => {
        i.close(), s(v.result ?? null);
      }, v.onerror = () => {
        i.close(), o(v.error);
      };
    });
  }
  /**
   * List all stored keys (metadata only — no private key material in logs).
   *
   * @returns Array of stored keys
   */
  async list() {
    if (!z())
      return Array.from(J.values());
    const t = await q();
    return new Promise((n, i) => {
      const o = t.transaction(F, "readonly").objectStore(F).getAll();
      o.onsuccess = () => {
        t.close(), n(o.result);
      }, o.onerror = () => {
        t.close(), i(o.error);
      };
    });
  }
  /**
   * Delete a key by fingerprint.
   *
   * @param fingerprint - Key to remove
   * @returns true if the key existed and was deleted
   */
  async delete(t) {
    const n = t.toUpperCase();
    if (!z())
      return J.delete(n);
    if (!await this.get(n)) return !1;
    const s = await q();
    return new Promise((o, p) => {
      const v = s.transaction(F, "readwrite");
      v.objectStore(F).delete(n), v.oncomplete = () => {
        s.close(), o(!0);
      }, v.onerror = () => {
        s.close(), p(v.error);
      };
    });
  }
  /**
   * Check if a key exists in the store.
   *
   * @param fingerprint - Key fingerprint to check
   */
  async has(t) {
    return await this.get(t) !== null;
  }
  /**
   * Clear all keys from the store.
   *
   * Destructive operation — use with caution.
   */
  async clear() {
    if (!z()) {
      J.clear();
      return;
    }
    const t = await q();
    return new Promise((n, i) => {
      const s = t.transaction(F, "readwrite");
      s.objectStore(F).clear(), s.oncomplete = () => {
        t.close(), n();
      }, s.onerror = () => {
        t.close(), i(s.error);
      };
    });
  }
}
class Ie {
  constructor(t) {
    L(this, "baseUrl");
    L(this, "authToken");
    this.baseUrl = t.baseUrl.replace(/\/$/, ""), this.authToken = t.authToken;
  }
  // -----------------------------------------------------------------------
  // Internal
  // -----------------------------------------------------------------------
  async request(t, n) {
    const i = {
      "Content-Type": "application/json",
      ...this.authToken ? { Authorization: `Bearer ${this.authToken}` } : {}
    }, s = await fetch(`${this.baseUrl}${t}`, {
      ...n,
      headers: { ...i, ...n == null ? void 0 : n.headers }
    });
    if (!s.ok) {
      const o = await s.text();
      throw new Error(`SKSeal API error ${s.status}: ${o}`);
    }
    return s.json();
  }
  // -----------------------------------------------------------------------
  // Templates
  // -----------------------------------------------------------------------
  /** List all document templates. */
  async listTemplates() {
    return this.request("/api/templates");
  }
  /** Get a template by ID. */
  async getTemplate(t) {
    return this.request(`/api/templates/${t}`);
  }
  // -----------------------------------------------------------------------
  // Documents
  // -----------------------------------------------------------------------
  /** List documents, optionally filtered by status. */
  async listDocuments(t) {
    const n = t ? `?status=${encodeURIComponent(t)}` : "";
    return this.request(`/api/documents${n}`);
  }
  /** Get a document by ID. */
  async getDocument(t) {
    return this.request(`/api/documents/${t}`);
  }
  /** Download the source PDF for a document as ArrayBuffer. */
  async downloadPdf(t) {
    const n = this.authToken ? { Authorization: `Bearer ${this.authToken}` } : {}, i = await fetch(
      `${this.baseUrl}/api/documents/${t}/pdf`,
      { headers: n }
    );
    if (!i.ok)
      throw new Error(`Failed to download PDF: ${i.status}`);
    return i.arrayBuffer();
  }
  /** Get the audit trail for a document. */
  async getAuditTrail(t) {
    return this.request(
      `/api/documents/${t}/audit`
    );
  }
  // -----------------------------------------------------------------------
  // Client-side signing submission
  // -----------------------------------------------------------------------
  /**
   * Submit a client-side signature to the server.
   *
   * This is the key endpoint for the client-side signing flow:
   * 1. Client downloads PDF from server
   * 2. Client signs hash locally with OpenPGP.js (keys never leave browser)
   * 3. Client submits the signature + hash to this endpoint
   * 4. Server verifies the signature and records it
   *
   * NOTE: This endpoint needs to be added to the Python API.
   * Until then, this method prepares the payload for manual integration.
   */
  async submitClientSignature(t) {
    return this.request(
      `/api/documents/${t.documentId}/sign-client`,
      {
        method: "POST",
        body: JSON.stringify({
          signer_id: t.signerId,
          signature_armor: t.signatureArmor,
          document_hash: t.documentHash,
          fingerprint: t.fingerprint,
          field_values: t.fieldValues ?? {}
        })
      }
    );
  }
  // -----------------------------------------------------------------------
  // Key management
  // -----------------------------------------------------------------------
  /**
   * Upload a public key to the server's key cache.
   *
   * The server needs public keys to verify signatures. This uploads
   * the public key (never the private key) for future verification.
   */
  async uploadPublicKey(t, n) {
    await this.request("/api/keys", {
      method: "POST",
      body: JSON.stringify({ fingerprint: t, armor: n })
    });
  }
  // -----------------------------------------------------------------------
  // Verification
  // -----------------------------------------------------------------------
  /** Request server-side verification of a document's signatures. */
  async verifyDocument(t, n) {
    return this.request(
      `/api/documents/${t}/verify`,
      {
        method: "POST",
        body: JSON.stringify({ public_keys: n ?? {} })
      }
    );
  }
}
class Ee {
  constructor(t) {
    L(this, "keyStore");
    L(this, "client");
    this.keyStore = new Ne(), this.client = new Ie({
      baseUrl: t.apiUrl,
      authToken: t.authToken
    });
  }
  // -----------------------------------------------------------------------
  // Key management
  // -----------------------------------------------------------------------
  /**
   * Generate a new signing key pair and store it in the browser.
   *
   * The private key is passphrase-protected and stored in IndexedDB.
   * The public key is also uploaded to the SKSeal server for verification.
   *
   * @param name - Signer's display name
   * @param email - Signer's email
   * @param passphrase - Passphrase to protect the private key
   * @returns The generated key pair metadata
   */
  async generateKey(t, n, i) {
    const s = await Te(t, n, i);
    return await this.keyStore.store({
      fingerprint: s.fingerprint,
      publicKeyArmor: s.publicKeyArmor,
      privateKeyArmor: s.privateKeyArmor,
      name: s.name,
      email: s.email,
      createdAt: s.createdAt.toISOString()
    }), await this.client.uploadPublicKey(
      s.fingerprint,
      s.publicKeyArmor
    ), s;
  }
  /**
   * Import an existing PGP private key into the browser key store.
   *
   * @param armoredPrivateKey - ASCII-armored private key (passphrase-protected)
   * @returns Imported key metadata
   */
  async importKey(t) {
    const n = await Ae(t), i = {
      fingerprint: n.fingerprint,
      publicKeyArmor: n.publicKeyArmor,
      privateKeyArmor: t,
      name: n.name,
      email: n.email,
      createdAt: (/* @__PURE__ */ new Date()).toISOString()
    };
    return await this.keyStore.store(i), await this.client.uploadPublicKey(n.fingerprint, n.publicKeyArmor), i;
  }
  /** List all keys stored in the browser. */
  async listKeys() {
    return this.keyStore.list();
  }
  // -----------------------------------------------------------------------
  // Signing
  // -----------------------------------------------------------------------
  /**
   * Sign a document — the full client-side flow.
   *
   * 1. Fetches the document metadata and PDF from the server
   * 2. Locates the signer by fingerprint match
   * 3. Loads the private key from IndexedDB
   * 4. Signs the PDF hash with OpenPGP.js (key stays in browser)
   * 5. Submits the signature to the server
   * 6. Returns the updated document
   *
   * @param documentId - ID of the document to sign
   * @param fingerprint - PGP fingerprint of the signing key
   * @param passphrase - Passphrase to unlock the private key
   * @param fieldValues - Optional field values filled by the signer
   * @returns Updated document with the new signature
   */
  async sign(t, n, i, s) {
    const o = await this.client.getDocument(t), p = n.toUpperCase(), v = o.signers.find(
      (A) => A.fingerprint.toUpperCase().startsWith(p) || p.startsWith(A.fingerprint.toUpperCase())
    );
    if (!v)
      throw new Error(`No signer with fingerprint ${p} found in document`);
    const h = await this.keyStore.get(p);
    if (!h)
      throw new Error(
        `Private key ${p.slice(0, 16)}... not found in browser key store`
      );
    const b = await this.client.downloadPdf(t), _ = await Me(
      b,
      h.privateKeyArmor,
      i
    );
    return { document: await this.client.submitClientSignature({
      documentId: t,
      signerId: v.signer_id,
      signatureArmor: _.signatureArmor,
      documentHash: _.documentHash,
      fingerprint: _.fingerprint,
      fieldValues: s
    }), signingResult: _ };
  }
  // -----------------------------------------------------------------------
  // Verification
  // -----------------------------------------------------------------------
  /**
   * Verify a document's signatures locally using OpenPGP.js.
   *
   * Downloads the PDF and verifies each signature against the
   * signer's public key without sending anything to the server.
   *
   * @param documentId - ID of the document to verify
   * @returns Per-signer verification results
   */
  async verifyLocally(t) {
    const n = await this.client.getDocument(t), i = await this.client.downloadPdf(t), s = /* @__PURE__ */ new Map();
    for (const o of n.signatures) {
      const p = await this.keyStore.get(o.fingerprint), v = n.signers.find(
        (_) => _.signer_id === o.signer_id
      ), h = (p == null ? void 0 : p.publicKeyArmor) ?? (v == null ? void 0 : v.public_key_armor);
      if (!h) {
        s.set(o.signer_id, {
          valid: !1,
          fingerprint: o.fingerprint,
          error: `No public key for fingerprint ${o.fingerprint.slice(0, 16)}...`
        });
        continue;
      }
      const b = await Fe(
        i,
        o.signature_armor,
        h,
        o.document_hash
      );
      s.set(o.signer_id, b);
    }
    return s;
  }
  /**
   * Get the SHA-256 hash of a document's PDF.
   *
   * Useful for verifying document integrity before signing.
   *
   * @param documentId - Document ID
   * @returns Hex-encoded SHA-256 hash
   */
  async getDocumentHash(t) {
    const n = await this.client.downloadPdf(t);
    return te(n);
  }
}
const Oe = { class: "skseal-builder" }, Re = { class: "builder-toolbar" }, We = { class: "page-nav" }, Be = ["disabled"], je = ["disabled"], Le = { class: "builder-body" }, qe = { class: "field-palette" }, ze = ["onDragstart"], Je = { class: "palette-icon" }, Ye = { class: "palette-label" }, Ge = ["onClick"], Xe = { class: "field-list-name" }, Qe = { class: "field-list-type" }, Ze = ["onClick"], et = ["onMousedown"], tt = { class: "field-label" }, nt = ["onMousedown"], at = {
  key: 0,
  class: "properties-panel"
}, st = ["value"], rt = ["value"], ot = { class: "checkbox-row" }, it = { key: 0 }, lt = ["value"], ut = { class: "field-actions" }, ct = /* @__PURE__ */ ue({
  __name: "TemplateBuilder",
  props: {
    pdfUrl: {},
    template: {},
    roles: { default: () => ["Signer", "Cosigner", "Witness"] }
  },
  emits: ["save", "field-select"],
  setup(d, { emit: t }) {
    var ae, se, re, oe;
    const n = d, i = t, s = w(null), o = w(null), p = w(1), v = w(1), h = w(0), b = w(0), _ = w(
      ((se = (ae = n.template) == null ? void 0 : ae.documents[0]) == null ? void 0 : se.fields) ?? []
    ), V = w(((re = n.template) == null ? void 0 : re.name) ?? "New Template"), A = w(((oe = n.template) == null ? void 0 : oe.description) ?? ""), x = w(null), M = w(!1), O = w(!1), B = w({ x: 0, y: 0 });
    let R = null;
    const S = [
      { type: "text", label: "Text", icon: "T", defaultW: 0.25, defaultH: 0.025 },
      { type: "signature", label: "Signature", icon: "S", defaultW: 0.3, defaultH: 0.06 },
      { type: "initials", label: "Initials", icon: "I", defaultW: 0.08, defaultH: 0.03 },
      { type: "date", label: "Date", icon: "D", defaultW: 0.2, defaultH: 0.025 },
      { type: "datenow", label: "Date Now", icon: "DN", defaultW: 0.2, defaultH: 0.025 },
      { type: "number", label: "Number", icon: "#", defaultW: 0.15, defaultH: 0.025 },
      { type: "checkbox", label: "Checkbox", icon: "C", defaultW: 0.025, defaultH: 0.025 },
      { type: "radio", label: "Radio", icon: "R", defaultW: 0.025, defaultH: 0.025 },
      { type: "select", label: "Dropdown", icon: "V", defaultW: 0.25, defaultH: 0.025 },
      { type: "image", label: "Image", icon: "IMG", defaultW: 0.2, defaultH: 0.15 },
      { type: "pgp_signature", label: "PGP Sig", icon: "PGP", defaultW: 0.35, defaultH: 0.06 },
      { type: "fingerprint", label: "Fingerprint", icon: "FP", defaultW: 0.4, defaultH: 0.025 }
    ], m = G(
      () => _.value.filter(
        (c) => c.areas.some((a) => a.page === p.value)
      )
    ), u = G(
      () => _.value.find((c) => c.uuid === x.value) ?? null
    );
    async function l(c) {
      if (!R || !s.value) return;
      const a = await R.getPage(c), e = a.getViewport({ scale: 1.5 }), f = s.value;
      f.width = e.width, f.height = e.height, h.value = e.width, b.value = e.height;
      const D = f.getContext("2d");
      await a.render({ canvasContext: D, viewport: e }).promise;
    }
    async function K() {
      const c = window.pdfjsLib;
      if (!c) {
        console.error("pdf.js not loaded — add <script src='pdf.min.js'> to host page");
        return;
      }
      R = await c.getDocument(n.pdfUrl).promise, v.value = R.numPages, await l(p.value);
    }
    ie(p, (c) => l(c)), ie(() => n.pdfUrl, K), ce(K);
    function pe(c, a) {
      return {
        x: c / h.value,
        y: a / b.value
      };
    }
    function ve(c, a) {
      return {
        x: c * h.value,
        y: a * b.value
      };
    }
    function ye(c, a) {
      var e;
      (e = c.dataTransfer) == null || e.setData("fieldType", JSON.stringify(a));
    }
    function ge(c) {
      var N, j;
      c.preventDefault();
      const a = (N = c.dataTransfer) == null ? void 0 : N.getData("fieldType");
      if (!a) return;
      const e = JSON.parse(a), f = (j = o.value) == null ? void 0 : j.getBoundingClientRect();
      if (!f) return;
      const D = c.clientX - f.left, T = c.clientY - f.top, $ = pe(D, T), U = {
        uuid: crypto.randomUUID(),
        name: `field_${Date.now()}`,
        type: e.type,
        role: n.roles[0],
        areas: [
          {
            page: p.value,
            x: Math.max(0, Math.min($.x, 1 - e.defaultW)),
            y: Math.max(0, Math.min($.y, 1 - e.defaultH)),
            w: e.defaultW,
            h: e.defaultH
          }
        ],
        required: !0,
        readonly: !1,
        default_value: null,
        options: [],
        title: "",
        description: "",
        preferences: {
          font_size: 12,
          font_type: "normal",
          font: "Helvetica",
          color: "black",
          background: "white",
          align: "left",
          valign: "center"
        },
        validation: null
      };
      _.value.push(U), x.value = U.uuid, i("field-select", U);
    }
    function me(c) {
      c.preventDefault();
    }
    function fe(c, a) {
      var U;
      c.stopPropagation(), x.value = a.uuid, i("field-select", a);
      const e = a.areas.find((N) => N.page === p.value);
      if (!e) return;
      const f = ve(e.x, e.y), D = (U = o.value) == null ? void 0 : U.getBoundingClientRect();
      if (!D) return;
      B.value = {
        x: c.clientX - D.left - f.x,
        y: c.clientY - D.top - f.y
      }, M.value = !0;
      const T = (N) => {
        if (!M.value || !D) return;
        const j = (N.clientX - D.left - B.value.x) / h.value, Se = (N.clientY - D.top - B.value.y) / b.value;
        e.x = Math.max(0, Math.min(j, 1 - e.w)), e.y = Math.max(0, Math.min(Se, 1 - e.h));
      }, $ = () => {
        M.value = !1, document.removeEventListener("mousemove", T), document.removeEventListener("mouseup", $);
      };
      document.addEventListener("mousemove", T), document.addEventListener("mouseup", $);
    }
    function he(c, a) {
      var $;
      c.stopPropagation();
      const e = a.areas.find((U) => U.page === p.value);
      if (!e) return;
      O.value = !0;
      const f = ($ = o.value) == null ? void 0 : $.getBoundingClientRect(), D = (U) => {
        if (!O.value || !f) return;
        const N = (U.clientX - f.left) / h.value, j = (U.clientY - f.top) / b.value;
        e.w = Math.max(0.02, Math.min(N - e.x, 1 - e.x)), e.h = Math.max(0.015, Math.min(j - e.y, 1 - e.y));
      }, T = () => {
        O.value = !1, document.removeEventListener("mousemove", D), document.removeEventListener("mouseup", T);
      };
      document.addEventListener("mousemove", D), document.addEventListener("mouseup", T);
    }
    function ne(c) {
      _.value = _.value.filter((a) => a.uuid !== c), x.value === c && (x.value = null, i("field-select", null));
    }
    function be(c) {
      const a = JSON.parse(JSON.stringify(c));
      a.uuid = crypto.randomUUID(), a.name = `${c.name}_copy`;
      for (const e of a.areas)
        e.x = Math.min(e.x + 0.02, 1 - e.w), e.y = Math.min(e.y + 0.02, 1 - e.h);
      _.value.push(a), x.value = a.uuid;
    }
    function we() {
      x.value = null, i("field-select", null);
    }
    function ke() {
      p.value > 1 && p.value--;
    }
    function _e() {
      p.value < v.value && p.value++;
    }
    function xe() {
      var a, e, f, D, T;
      const c = {
        template_id: ((a = n.template) == null ? void 0 : a.template_id) ?? crypto.randomUUID(),
        name: V.value,
        description: A.value,
        folder_name: ((e = n.template) == null ? void 0 : e.folder_name) ?? "",
        documents: [
          {
            name: V.value,
            attachment_uuid: null,
            fields: _.value
          }
        ],
        submitters: [...new Set(_.value.map(($) => $.role))].map(
          ($, U) => ({
            role: $,
            name: "",
            email: "",
            order: U
          })
        ),
        tags: ((f = n.template) == null ? void 0 : f.tags) ?? [],
        version: (((D = n.template) == null ? void 0 : D.version) ?? 0) + 1,
        created_at: ((T = n.template) == null ? void 0 : T.created_at) ?? (/* @__PURE__ */ new Date()).toISOString()
      };
      i("save", c);
    }
    const De = {
      Signer: "#3b82f6",
      Cosigner: "#8b5cf6",
      Witness: "#f59e0b",
      Notary: "#ef4444",
      Steward: "#10b981",
      Trustee: "#6366f1",
      Discloser: "#3b82f6",
      Recipient: "#8b5cf6",
      Requestor: "#3b82f6"
    };
    function Y(c) {
      return De[c] ?? "#6b7280";
    }
    return (c, a) => (y(), g("div", Oe, [
      r("div", Re, [
        C(r("input", {
          "onUpdate:modelValue": a[0] || (a[0] = (e) => V.value = e),
          class: "template-name",
          placeholder: "Template Name"
        }, null, 512), [
          [W, V.value]
        ]),
        r("div", We, [
          r("button", {
            disabled: p.value <= 1,
            onClick: ke
          }, "<", 8, Be),
          r("span", null, "Page " + k(p.value) + " / " + k(v.value), 1),
          r("button", {
            disabled: p.value >= v.value,
            onClick: _e
          }, ">", 8, je)
        ]),
        r("button", {
          class: "save-btn",
          onClick: xe
        }, "Save Template")
      ]),
      r("div", Le, [
        r("div", qe, [
          a[12] || (a[12] = r("h3", null, "Fields", -1)),
          (y(), g(I, null, E(S, (e) => r("div", {
            key: e.type,
            class: "palette-item",
            draggable: "true",
            onDragstart: (f) => ye(f, e)
          }, [
            r("span", Je, k(e.icon), 1),
            r("span", Ye, k(e.label), 1)
          ], 40, ze)), 64)),
          a[13] || (a[13] = r("h3", { style: { "margin-top": "16px" } }, "Placed Fields", -1)),
          (y(!0), g(I, null, E(m.value, (e) => (y(), g("div", {
            key: e.uuid,
            class: X(["field-list-item", { selected: e.uuid === x.value }]),
            onClick: (f) => {
              x.value = e.uuid, i("field-select", e);
            }
          }, [
            r("span", {
              class: "role-dot",
              style: Z({ background: Y(e.role) })
            }, null, 4),
            r("span", Xe, k(e.title || e.name), 1),
            r("span", Qe, k(e.type), 1),
            r("button", {
              class: "del-btn",
              onClick: Pe((f) => ne(e.uuid), ["stop"])
            }, "x", 8, Ze)
          ], 10, Ge))), 128))
        ]),
        r("div", {
          ref_key: "containerRef",
          ref: o,
          class: "canvas-container",
          onDrop: ge,
          onDragover: me,
          onClick: we
        }, [
          r("canvas", {
            ref_key: "canvasRef",
            ref: s
          }, null, 512),
          (y(!0), g(I, null, E(m.value, (e) => {
            var f, D, T, $;
            return y(), g("div", {
              key: e.uuid,
              class: X(["field-overlay", {
                selected: e.uuid === x.value,
                signature: e.type === "signature" || e.type === "pgp_signature"
              }]),
              style: Z({
                left: (((f = e.areas[0]) == null ? void 0 : f.x) ?? 0) * h.value + "px",
                top: (((D = e.areas[0]) == null ? void 0 : D.y) ?? 0) * b.value + "px",
                width: (((T = e.areas[0]) == null ? void 0 : T.w) ?? 0.2) * h.value + "px",
                height: ((($ = e.areas[0]) == null ? void 0 : $.h) ?? 0.025) * b.value + "px",
                borderColor: Y(e.role),
                background: Y(e.role) + "20"
              }),
              onMousedown: (U) => fe(U, e)
            }, [
              r("span", tt, k(e.title || e.name), 1),
              r("span", {
                class: "field-role-tag",
                style: Z({ background: Y(e.role) })
              }, k(e.role), 5),
              r("div", {
                class: "resize-handle",
                onMousedown: (U) => he(U, e)
              }, null, 40, nt)
            ], 46, et);
          }), 128))
        ], 544),
        u.value ? (y(), g("div", at, [
          a[16] || (a[16] = r("h3", null, "Field Properties", -1)),
          a[17] || (a[17] = r("label", null, "Name", -1)),
          C(r("input", {
            "onUpdate:modelValue": a[1] || (a[1] = (e) => u.value.name = e)
          }, null, 512), [
            [W, u.value.name]
          ]),
          a[18] || (a[18] = r("label", null, "Title", -1)),
          C(r("input", {
            "onUpdate:modelValue": a[2] || (a[2] = (e) => u.value.title = e)
          }, null, 512), [
            [W, u.value.title]
          ]),
          a[19] || (a[19] = r("label", null, "Description", -1)),
          C(r("textarea", {
            "onUpdate:modelValue": a[3] || (a[3] = (e) => u.value.description = e),
            rows: "2"
          }, null, 512), [
            [W, u.value.description]
          ]),
          a[20] || (a[20] = r("label", null, "Role", -1)),
          C(r("select", {
            "onUpdate:modelValue": a[4] || (a[4] = (e) => u.value.role = e)
          }, [
            (y(!0), g(I, null, E(d.roles, (e) => (y(), g("option", {
              key: e,
              value: e
            }, k(e), 9, st))), 128))
          ], 512), [
            [Q, u.value.role]
          ]),
          a[21] || (a[21] = r("label", null, "Type", -1)),
          C(r("select", {
            "onUpdate:modelValue": a[5] || (a[5] = (e) => u.value.type = e)
          }, [
            (y(), g(I, null, E(S, (e) => r("option", {
              key: e.type,
              value: e.type
            }, k(e.label), 9, rt)), 64))
          ], 512), [
            [Q, u.value.type]
          ]),
          r("div", ot, [
            r("label", null, [
              C(r("input", {
                type: "checkbox",
                "onUpdate:modelValue": a[6] || (a[6] = (e) => u.value.required = e)
              }, null, 512), [
                [le, u.value.required]
              ]),
              a[14] || (a[14] = ee(" Required ", -1))
            ]),
            r("label", null, [
              C(r("input", {
                type: "checkbox",
                "onUpdate:modelValue": a[7] || (a[7] = (e) => u.value.readonly = e)
              }, null, 512), [
                [le, u.value.readonly]
              ]),
              a[15] || (a[15] = ee(" Read-only ", -1))
            ])
          ]),
          a[22] || (a[22] = r("label", null, "Default Value", -1)),
          C(r("input", {
            "onUpdate:modelValue": a[8] || (a[8] = (e) => u.value.default_value = e)
          }, null, 512), [
            [W, u.value.default_value]
          ]),
          u.value.type === "select" || u.value.type === "radio" ? (y(), g("label", it, " Options (comma-separated) ")) : H("", !0),
          u.value.type === "select" || u.value.type === "radio" ? (y(), g("input", {
            key: 1,
            value: u.value.options.join(", "),
            onInput: a[9] || (a[9] = (e) => u.value.options = e.target.value.split(",").map((f) => f.trim()).filter(Boolean))
          }, null, 40, lt)) : H("", !0),
          r("div", ut, [
            r("button", {
              onClick: a[10] || (a[10] = (e) => be(u.value))
            }, "Duplicate"),
            r("button", {
              class: "danger",
              onClick: a[11] || (a[11] = (e) => ne(u.value.uuid))
            }, "Delete")
          ])
        ])) : H("", !0)
      ])
    ]));
  }
}), de = (d, t) => {
  const n = d.__vccOpts || d;
  for (const [i, s] of t)
    n[i] = s;
  return n;
}, Rt = /* @__PURE__ */ de(ct, [["__scopeId", "data-v-a524cec7"]]), dt = { class: "signing-view" }, pt = {
  key: 0,
  class: "loading"
}, vt = {
  key: 1,
  class: "error-banner"
}, yt = {
  key: 2,
  class: "success-banner"
}, gt = {
  key: 3,
  class: "doc-header"
}, mt = {
  key: 4,
  class: "signing-body"
}, ft = { class: "pdf-preview" }, ht = ["src"], bt = {
  key: 1,
  class: "no-pdf"
}, wt = { class: "signing-panel" }, kt = ["value"], _t = {
  key: 0,
  class: "field-section"
}, xt = ["onUpdate:modelValue", "type", "placeholder"], Dt = ["onUpdate:modelValue"], St = ["onUpdate:modelValue"], Kt = ["value"], Ut = {
  key: 3,
  class: "checkbox-label"
}, Pt = ["checked", "onChange"], $t = { class: "signers-section" }, Ct = { class: "signer-name" }, Tt = { class: "signer-role" }, At = ["disabled"], Mt = { key: 0 }, Ft = { key: 1 }, Vt = /* @__PURE__ */ ue({
  __name: "SigningView",
  props: {
    documentId: {},
    apiUrl: {},
    authToken: {}
  },
  emits: ["signed", "error"],
  setup(d, { emit: t }) {
    const n = d, i = t, s = new Ee({
      apiUrl: n.apiUrl,
      authToken: n.authToken
    }), o = w(null), p = w([]), v = w(""), h = w(""), b = w({}), _ = w(!0), V = w(!1), A = w(null), x = w(!1), M = w(null), O = G(() => {
      if (!o.value) return [];
      if (!p.value.find((u) => u.fingerprint === v.value)) return [];
      const m = o.value.signers.find(
        (u) => u.fingerprint.toUpperCase().startsWith(v.value.toUpperCase())
      );
      return m ? o.value.fields.filter(
        (u) => u.role === m.role && u.type !== "signature" && u.type !== "pgp_signature"
      ) : [];
    }), B = G(() => v.value && h.value && !V.value);
    ce(async () => {
      try {
        o.value = await s.client.getDocument(n.documentId), p.value = await s.listKeys();
        for (const u of p.value) {
          const l = o.value.signers.find(
            (K) => K.fingerprint.toUpperCase().startsWith(u.fingerprint) || u.fingerprint.startsWith(K.fingerprint.toUpperCase())
          );
          if (l && l.status === "pending") {
            v.value = u.fingerprint;
            break;
          }
        }
        const S = await s.client.downloadPdf(n.documentId), m = new Blob([S], { type: "application/pdf" });
        M.value = URL.createObjectURL(m);
      } catch (S) {
        A.value = S instanceof Error ? S.message : String(S);
      } finally {
        _.value = !1;
      }
    });
    async function R() {
      if (B.value) {
        V.value = !0, A.value = null;
        try {
          const { document: S } = await s.sign(
            n.documentId,
            v.value,
            h.value,
            Object.keys(b.value).length > 0 ? b.value : void 0
          );
          o.value = S, x.value = !0, i("signed", S);
        } catch (S) {
          const m = S instanceof Error ? S.message : String(S);
          A.value = m, i("error", m);
        } finally {
          V.value = !1, h.value = "";
        }
      }
    }
    return (S, m) => {
      var u;
      return y(), g("div", dt, [
        _.value ? (y(), g("div", pt, "Loading document...")) : H("", !0),
        A.value ? (y(), g("div", vt, k(A.value), 1)) : H("", !0),
        x.value ? (y(), g("div", yt, " Document signed successfully! Status: " + k((u = o.value) == null ? void 0 : u.status), 1)) : H("", !0),
        o.value && !_.value ? (y(), g("div", gt, [
          r("h2", null, k(o.value.title), 1),
          r("span", {
            class: X(["status-badge", o.value.status])
          }, k(o.value.status), 3)
        ])) : H("", !0),
        o.value && !_.value && !x.value ? (y(), g("div", mt, [
          r("div", ft, [
            M.value ? (y(), g("iframe", {
              key: 0,
              src: M.value,
              class: "pdf-iframe",
              title: "Document PDF"
            }, null, 8, ht)) : (y(), g("div", bt, "No PDF available"))
          ]),
          r("div", wt, [
            m[5] || (m[5] = r("h3", null, "Sign Document", -1)),
            m[6] || (m[6] = r("label", null, "Signing Key", -1)),
            C(r("select", {
              "onUpdate:modelValue": m[0] || (m[0] = (l) => v.value = l)
            }, [
              m[2] || (m[2] = r("option", { value: "" }, "Select a key...", -1)),
              (y(!0), g(I, null, E(p.value, (l) => (y(), g("option", {
                key: l.fingerprint,
                value: l.fingerprint
              }, k(l.name) + " (" + k(l.fingerprint.slice(0, 16)) + "...) ", 9, kt))), 128))
            ], 512), [
              [Q, v.value]
            ]),
            m[7] || (m[7] = r("label", null, "Passphrase", -1)),
            C(r("input", {
              "onUpdate:modelValue": m[1] || (m[1] = (l) => h.value = l),
              type: "password",
              placeholder: "Enter key passphrase",
              onKeyup: $e(R, ["enter"])
            }, null, 544), [
              [W, h.value]
            ]),
            O.value.length > 0 ? (y(), g("div", _t, [
              m[3] || (m[3] = r("h4", null, "Fill Fields", -1)),
              (y(!0), g(I, null, E(O.value, (l) => (y(), g("div", {
                key: l.uuid,
                class: "fill-field"
              }, [
                r("label", null, k(l.title || l.name) + k(l.required ? " *" : ""), 1),
                l.type === "text" || l.type === "number" || l.type === "phone" ? C((y(), g("input", {
                  key: 0,
                  "onUpdate:modelValue": (K) => b.value[l.uuid] = K,
                  type: l.type === "number" ? "number" : "text",
                  placeholder: l.description
                }, null, 8, xt)), [
                  [Ce, b.value[l.uuid]]
                ]) : l.type === "date" ? C((y(), g("input", {
                  key: 1,
                  "onUpdate:modelValue": (K) => b.value[l.uuid] = K,
                  type: "date"
                }, null, 8, Dt)), [
                  [W, b.value[l.uuid]]
                ]) : l.type === "select" ? C((y(), g("select", {
                  key: 2,
                  "onUpdate:modelValue": (K) => b.value[l.uuid] = K
                }, [
                  (y(!0), g(I, null, E(l.options, (K) => (y(), g("option", {
                    key: K,
                    value: K
                  }, k(K), 9, Kt))), 128))
                ], 8, St)), [
                  [Q, b.value[l.uuid]]
                ]) : l.type === "checkbox" ? (y(), g("label", Ut, [
                  r("input", {
                    type: "checkbox",
                    checked: b.value[l.uuid] === "true",
                    onChange: (K) => b.value[l.uuid] = K.target.checked ? "true" : "false"
                  }, null, 40, Pt),
                  ee(" " + k(l.description), 1)
                ])) : H("", !0)
              ]))), 128))
            ])) : H("", !0),
            r("div", $t, [
              m[4] || (m[4] = r("h4", null, "Signers", -1)),
              (y(!0), g(I, null, E(o.value.signers, (l) => (y(), g("div", {
                key: l.signer_id,
                class: "signer-row"
              }, [
                r("span", Ct, k(l.name), 1),
                r("span", Tt, k(l.role), 1),
                r("span", {
                  class: X(["signer-status", l.status])
                }, k(l.status), 3)
              ]))), 128))
            ]),
            r("button", {
              class: "sign-btn",
              disabled: !B.value,
              onClick: R
            }, [
              V.value ? (y(), g("span", Mt, "Signing...")) : (y(), g("span", Ft, "Sign with PGP Key"))
            ], 8, At),
            m[8] || (m[8] = r("p", { class: "security-note" }, " Your private key never leaves this browser. Only the cryptographic signature is sent to the server. ", -1))
          ])
        ])) : H("", !0)
      ]);
    };
  }
}), Wt = /* @__PURE__ */ de(Vt, [["__scopeId", "data-v-c294747d"]]);
export {
  Ne as KeyStore,
  Ie as SealClient,
  Ee as SigningSession,
  Wt as SigningView,
  Rt as TemplateBuilder,
  Ot as extractFingerprint,
  Te as generateKeyPair,
  te as hashBytes,
  Ae as importPrivateKey,
  It as importPublicKey,
  Et as signBytes,
  Me as signDocument,
  Fe as verifySignature
};
//# sourceMappingURL=index.js.map
