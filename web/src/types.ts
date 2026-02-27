/**
 * TypeScript types for SKSeal — mirrors the Python Pydantic models.
 *
 * These types define the contract between the browser-side signing SDK
 * and the SKSeal backend API. Field names match the Python models'
 * serialized JSON output for seamless interchange.
 */

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export type FieldType =
  | "heading"
  | "text"
  | "signature"
  | "initials"
  | "date"
  | "datenow"
  | "number"
  | "image"
  | "checkbox"
  | "multiple"
  | "file"
  | "radio"
  | "select"
  | "cells"
  | "stamp"
  | "payment"
  | "phone"
  | "verification"
  | "kba"
  | "strikethrough"
  | "pgp_signature"
  | "fingerprint";

export type DocumentStatus =
  | "draft"
  | "pending"
  | "partially_signed"
  | "completed"
  | "voided"
  | "expired";

export type SignerRole =
  | "signer"
  | "cosigner"
  | "witness"
  | "notary"
  | "steward"
  | "trustee";

export type SignerStatus =
  | "pending"
  | "viewed"
  | "signed"
  | "declined"
  | "expired";

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

export interface FieldPlacement {
  page: number;
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface FieldPreferences {
  font_size: number;
  font_type: string;
  font: string;
  color: string;
  background: string;
  align: string;
  valign: string;
}

export interface FieldValidation {
  pattern: string | null;
  message: string;
  min: number | null;
  max: number | null;
}

export interface DocumentField {
  uuid: string;
  name: string;
  type: FieldType;
  role: string;
  areas: FieldPlacement[];
  required: boolean;
  readonly: boolean;
  default_value: string | null;
  options: string[];
  title: string;
  description: string;
  preferences: FieldPreferences;
  validation: FieldValidation | null;
}

export interface Signer {
  signer_id: string;
  name: string;
  fingerprint: string;
  email?: string;
  role: SignerRole;
  status: SignerStatus;
  public_key_armor?: string;
  signed_at?: string;
  order: number;
}

export interface SignatureRecord {
  record_id: string;
  document_id: string;
  signer_id: string;
  fingerprint: string;
  document_hash: string;
  signature_armor: string;
  signed_at: string;
  field_values: Record<string, string>;
}

export interface AuditEntry {
  entry_id: string;
  document_id: string;
  action: string;
  actor_fingerprint?: string;
  actor_name?: string;
  timestamp: string;
  details: string;
}

export interface Document {
  document_id: string;
  title: string;
  description: string;
  status: DocumentStatus;
  template_id?: string;
  pdf_path?: string;
  pdf_hash?: string;
  fields: DocumentField[];
  signers: Signer[];
  signatures: SignatureRecord[];
  audit_trail: AuditEntry[];
  created_at: string;
  created_by?: string;
  completed_at?: string;
  expires_at?: string;
  metadata: Record<string, string>;
}

export interface Template {
  template_id: string;
  name: string;
  description: string;
  folder_name: string;
  documents: Array<{
    name: string;
    attachment_uuid: string | null;
    fields: DocumentField[];
  }>;
  submitters: Array<{
    role: string;
    name: string;
    email: string;
    order: number;
  }>;
  tags: string[];
  version: number;
  created_at: string;
}

// ---------------------------------------------------------------------------
// SDK-specific types
// ---------------------------------------------------------------------------

export interface KeyPair {
  fingerprint: string;
  publicKeyArmor: string;
  privateKeyArmor: string;
  name: string;
  email: string;
  createdAt: Date;
}

export interface StoredKey {
  fingerprint: string;
  publicKeyArmor: string;
  /** Encrypted private key — passphrase-protected, never stored in plaintext. */
  privateKeyArmor: string;
  name: string;
  email: string;
  createdAt: string;
}

export interface SigningResult {
  signatureArmor: string;
  documentHash: string;
  fingerprint: string;
  signedAt: Date;
}

export interface VerificationResult {
  valid: boolean;
  fingerprint: string;
  signedAt?: Date;
  error?: string;
}

export interface ClientSignRequest {
  documentId: string;
  signerId: string;
  signatureArmor: string;
  documentHash: string;
  fingerprint: string;
  fieldValues?: Record<string, string>;
}
