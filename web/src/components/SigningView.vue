<script setup lang="ts">
/**
 * SKSeal Signing View — document signing ceremony in the browser.
 *
 * Displays the document PDF with fields to fill, then signs with
 * the user's local PGP key via OpenPGP.js. Private keys never
 * leave the browser.
 *
 * Props:
 *   documentId — SKSeal document ID to sign
 *   apiUrl — SKSeal API base URL
 *   authToken — Optional auth token
 *
 * Emits:
 *   signed — Emitted after successful signing with the updated document
 *   error — Emitted on signing failure
 */

import { ref, computed, onMounted } from "vue";
import { SigningSession } from "../signing-session.js";
import type { Document, StoredKey, DocumentField } from "../types.js";

interface Props {
  documentId: string;
  apiUrl: string;
  authToken?: string;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  signed: [document: Document];
  error: [message: string];
}>();

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const session = new SigningSession({
  apiUrl: props.apiUrl,
  authToken: props.authToken,
});

const doc = ref<Document | null>(null);
const keys = ref<StoredKey[]>([]);
const selectedKeyFp = ref<string>("");
const passphrase = ref("");
const fieldValues = ref<Record<string, string>>({});

const loading = ref(true);
const signing = ref(false);
const error = ref<string | null>(null);
const success = ref(false);

const pdfUrl = ref<string | null>(null);

// ---------------------------------------------------------------------------
// Computed
// ---------------------------------------------------------------------------

const myFields = computed<DocumentField[]>(() => {
  if (!doc.value) return [];
  const selectedKey = keys.value.find((k) => k.fingerprint === selectedKeyFp.value);
  if (!selectedKey) return [];

  // Find the signer matching this key
  const signer = doc.value.signers.find(
    (s) => s.fingerprint.toUpperCase().startsWith(selectedKeyFp.value.toUpperCase()),
  );
  if (!signer) return [];

  // Return fields assigned to this signer's role
  return doc.value.fields.filter(
    (f) => f.role === signer.role && f.type !== "signature" && f.type !== "pgp_signature",
  );
});

const canSign = computed(() => {
  return selectedKeyFp.value && passphrase.value && !signing.value;
});

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

onMounted(async () => {
  try {
    doc.value = await session.client.getDocument(props.documentId);
    keys.value = await session.listKeys();

    // Auto-select key if only one matches a signer
    for (const key of keys.value) {
      const match = doc.value.signers.find(
        (s) =>
          s.fingerprint.toUpperCase().startsWith(key.fingerprint) ||
          key.fingerprint.startsWith(s.fingerprint.toUpperCase()),
      );
      if (match && match.status === "pending") {
        selectedKeyFp.value = key.fingerprint;
        break;
      }
    }

    // Load PDF for display
    const pdfData = await session.client.downloadPdf(props.documentId);
    const blob = new Blob([pdfData], { type: "application/pdf" });
    pdfUrl.value = URL.createObjectURL(blob);
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
});

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

async function signDocument() {
  if (!canSign.value) return;

  signing.value = true;
  error.value = null;

  try {
    const { document: updatedDoc } = await session.sign(
      props.documentId,
      selectedKeyFp.value,
      passphrase.value,
      Object.keys(fieldValues.value).length > 0 ? fieldValues.value : undefined,
    );

    doc.value = updatedDoc;
    success.value = true;
    emit("signed", updatedDoc);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    error.value = msg;
    emit("error", msg);
  } finally {
    signing.value = false;
    passphrase.value = "";
  }
}
</script>

<template>
  <div class="signing-view">
    <!-- Loading -->
    <div v-if="loading" class="loading">Loading document...</div>

    <!-- Error -->
    <div v-if="error" class="error-banner">{{ error }}</div>

    <!-- Success -->
    <div v-if="success" class="success-banner">
      Document signed successfully! Status: {{ doc?.status }}
    </div>

    <!-- Document info -->
    <div v-if="doc && !loading" class="doc-header">
      <h2>{{ doc.title }}</h2>
      <span class="status-badge" :class="doc.status">{{ doc.status }}</span>
    </div>

    <div v-if="doc && !loading && !success" class="signing-body">
      <!-- PDF preview -->
      <div class="pdf-preview">
        <iframe
          v-if="pdfUrl"
          :src="pdfUrl"
          class="pdf-iframe"
          title="Document PDF"
        />
        <div v-else class="no-pdf">No PDF available</div>
      </div>

      <!-- Signing panel -->
      <div class="signing-panel">
        <h3>Sign Document</h3>

        <!-- Key selection -->
        <label>Signing Key</label>
        <select v-model="selectedKeyFp">
          <option value="">Select a key...</option>
          <option v-for="key in keys" :key="key.fingerprint" :value="key.fingerprint">
            {{ key.name }} ({{ key.fingerprint.slice(0, 16) }}...)
          </option>
        </select>

        <!-- Passphrase -->
        <label>Passphrase</label>
        <input
          v-model="passphrase"
          type="password"
          placeholder="Enter key passphrase"
          @keyup.enter="signDocument"
        />

        <!-- Fillable fields for this signer -->
        <div v-if="myFields.length > 0" class="field-section">
          <h4>Fill Fields</h4>
          <div v-for="field in myFields" :key="field.uuid" class="fill-field">
            <label>{{ field.title || field.name }}{{ field.required ? ' *' : '' }}</label>
            <input
              v-if="field.type === 'text' || field.type === 'number' || field.type === 'phone'"
              v-model="fieldValues[field.uuid]"
              :type="field.type === 'number' ? 'number' : 'text'"
              :placeholder="field.description"
            />
            <input
              v-else-if="field.type === 'date'"
              v-model="fieldValues[field.uuid]"
              type="date"
            />
            <select
              v-else-if="field.type === 'select'"
              v-model="fieldValues[field.uuid]"
            >
              <option v-for="opt in field.options" :key="opt" :value="opt">
                {{ opt }}
              </option>
            </select>
            <label v-else-if="field.type === 'checkbox'" class="checkbox-label">
              <input
                type="checkbox"
                :checked="fieldValues[field.uuid] === 'true'"
                @change="fieldValues[field.uuid] = ($event.target as HTMLInputElement).checked ? 'true' : 'false'"
              />
              {{ field.description }}
            </label>
          </div>
        </div>

        <!-- Signers status -->
        <div class="signers-section">
          <h4>Signers</h4>
          <div v-for="signer in doc.signers" :key="signer.signer_id" class="signer-row">
            <span class="signer-name">{{ signer.name }}</span>
            <span class="signer-role">{{ signer.role }}</span>
            <span class="signer-status" :class="signer.status">
              {{ signer.status }}
            </span>
          </div>
        </div>

        <!-- Sign button -->
        <button
          class="sign-btn"
          :disabled="!canSign"
          @click="signDocument"
        >
          <span v-if="signing">Signing...</span>
          <span v-else>Sign with PGP Key</span>
        </button>

        <p class="security-note">
          Your private key never leaves this browser. Only the cryptographic
          signature is sent to the server.
        </p>
      </div>
    </div>
  </div>
</template>

<style scoped>
.signing-view {
  font-family: system-ui, -apple-system, sans-serif;
  color: #1a1a2e;
  max-width: 1200px;
  margin: 0 auto;
}

.loading {
  text-align: center;
  padding: 40px;
  color: #6b7280;
}

.error-banner {
  background: #fef2f2;
  border: 1px solid #fca5a5;
  color: #dc2626;
  padding: 12px 16px;
  border-radius: 8px;
  margin: 12px 0;
}

.success-banner {
  background: #f0fdf4;
  border: 1px solid #86efac;
  color: #16a34a;
  padding: 12px 16px;
  border-radius: 8px;
  margin: 12px 0;
  font-weight: 600;
}

.doc-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px 0;
  border-bottom: 1px solid #e5e7eb;
}
.doc-header h2 {
  margin: 0;
  font-size: 20px;
}

.status-badge {
  padding: 3px 10px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
}
.status-badge.draft { background: #f3f4f6; color: #6b7280; }
.status-badge.pending { background: #fef3c7; color: #d97706; }
.status-badge.partially_signed { background: #dbeafe; color: #2563eb; }
.status-badge.completed { background: #dcfce7; color: #16a34a; }

.signing-body {
  display: flex;
  gap: 24px;
  padding: 16px 0;
}

.pdf-preview {
  flex: 1;
  min-height: 600px;
}
.pdf-iframe {
  width: 100%;
  height: 600px;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
}
.no-pdf {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 400px;
  background: #f9fafb;
  border: 1px dashed #d1d5db;
  border-radius: 8px;
  color: #9ca3af;
}

.signing-panel {
  width: 320px;
  flex-shrink: 0;
}
.signing-panel h3 {
  margin: 0 0 16px;
  font-size: 16px;
}
.signing-panel label {
  display: block;
  font-size: 12px;
  color: #6b7280;
  margin: 12px 0 4px;
}
.signing-panel input,
.signing-panel select {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  font-size: 14px;
  box-sizing: border-box;
}

.field-section h4,
.signers-section h4 {
  font-size: 13px;
  margin: 16px 0 8px;
  color: #374151;
}

.fill-field {
  margin-bottom: 8px;
}

.signer-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 0;
  font-size: 13px;
}
.signer-name { flex: 1; font-weight: 500; }
.signer-role { color: #6b7280; }
.signer-status {
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
}
.signer-status.pending { background: #fef3c7; color: #d97706; }
.signer-status.signed { background: #dcfce7; color: #16a34a; }
.signer-status.declined { background: #fef2f2; color: #dc2626; }

.sign-btn {
  width: 100%;
  margin-top: 20px;
  padding: 12px;
  background: #16a34a;
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 15px;
  font-weight: 600;
  cursor: pointer;
}
.sign-btn:hover:not(:disabled) {
  background: #15803d;
}
.sign-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.security-note {
  margin-top: 12px;
  font-size: 11px;
  color: #9ca3af;
  text-align: center;
  line-height: 1.4;
}

.checkbox-label {
  display: flex !important;
  align-items: center;
  gap: 6px;
  font-size: 13px !important;
  color: #374151 !important;
}
</style>
