<script setup lang="ts">
/**
 * SKSeal Template Builder — drag-and-drop field placement on PDF.
 *
 * Renders PDF pages using pdf.js and lets users place, resize, and
 * configure document fields (signature, text, date, checkbox, etc.)
 * by dragging them onto the page canvas.
 *
 * Field coordinates use normalized 0-1 scale matching the SKSeal
 * backend model (DocuSeal-compatible).
 *
 * Props:
 *   pdfUrl — URL or data URL of the PDF to render
 *   template — Optional existing template to load fields from
 *   roles — Available signer roles for field assignment
 *
 * Emits:
 *   save — Emitted with the complete template JSON when user saves
 *   field-select — Emitted when a field is clicked for property editing
 */

import { ref, computed, watch, onMounted, nextTick } from "vue";
import type {
  DocumentField,
  FieldPlacement,
  FieldType,
  Template,
} from "../types.js";

// ---------------------------------------------------------------------------
// Props & emits
// ---------------------------------------------------------------------------

interface Props {
  pdfUrl: string;
  template?: Template;
  roles?: string[];
}

const props = withDefaults(defineProps<Props>(), {
  roles: () => ["Signer", "Cosigner", "Witness"],
});

const emit = defineEmits<{
  save: [template: Template];
  "field-select": [field: DocumentField | null];
}>();

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const canvasRef = ref<HTMLCanvasElement | null>(null);
const containerRef = ref<HTMLDivElement | null>(null);

const currentPage = ref(1);
const totalPages = ref(1);
const pageWidth = ref(0);
const pageHeight = ref(0);

const fields = ref<DocumentField[]>(
  props.template?.documents[0]?.fields ?? [],
);
const templateName = ref(props.template?.name ?? "New Template");
const templateDescription = ref(props.template?.description ?? "");

const selectedFieldId = ref<string | null>(null);
const isDragging = ref(false);
const isResizing = ref(false);
const dragOffset = ref({ x: 0, y: 0 });

// PDF.js state
let pdfDoc: any = null;

// ---------------------------------------------------------------------------
// Field type palette
// ---------------------------------------------------------------------------

interface FieldTypeOption {
  type: FieldType;
  label: string;
  icon: string;
  defaultW: number;
  defaultH: number;
}

const fieldTypes: FieldTypeOption[] = [
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
  { type: "fingerprint", label: "Fingerprint", icon: "FP", defaultW: 0.4, defaultH: 0.025 },
];

// ---------------------------------------------------------------------------
// Computed
// ---------------------------------------------------------------------------

const currentPageFields = computed(() =>
  fields.value.filter((f) =>
    f.areas.some((a) => a.page === currentPage.value),
  ),
);

const selectedField = computed(() =>
  fields.value.find((f) => f.uuid === selectedFieldId.value) ?? null,
);

// ---------------------------------------------------------------------------
// PDF rendering
// ---------------------------------------------------------------------------

async function renderPage(pageNum: number) {
  if (!pdfDoc || !canvasRef.value) return;

  const page = await pdfDoc.getPage(pageNum);
  const viewport = page.getViewport({ scale: 1.5 });

  const canvas = canvasRef.value;
  canvas.width = viewport.width;
  canvas.height = viewport.height;
  pageWidth.value = viewport.width;
  pageHeight.value = viewport.height;

  const ctx = canvas.getContext("2d")!;
  await page.render({ canvasContext: ctx, viewport }).promise;
}

async function loadPdf() {
  // pdf.js is loaded via CDN <script> tag in the host page
  const pdfjsLib = (window as any).pdfjsLib;
  if (!pdfjsLib) {
    console.error("pdf.js not loaded — add <script src='pdf.min.js'> to host page");
    return;
  }

  pdfDoc = await pdfjsLib.getDocument(props.pdfUrl).promise;
  totalPages.value = pdfDoc.numPages;
  await renderPage(currentPage.value);
}

watch(currentPage, (page) => renderPage(page));
watch(() => props.pdfUrl, loadPdf);

onMounted(loadPdf);

// ---------------------------------------------------------------------------
// Coordinate conversion (pixel ↔ normalized)
// ---------------------------------------------------------------------------

function toNormalized(px: number, py: number): { x: number; y: number } {
  return {
    x: px / pageWidth.value,
    y: py / pageHeight.value,
  };
}

function toPixels(nx: number, ny: number): { x: number; y: number } {
  return {
    x: nx * pageWidth.value,
    y: ny * pageHeight.value,
  };
}

// ---------------------------------------------------------------------------
// Drag & drop — add new field from palette
// ---------------------------------------------------------------------------

function onDragStart(e: DragEvent, fieldType: FieldTypeOption) {
  e.dataTransfer?.setData("fieldType", JSON.stringify(fieldType));
}

function onDrop(e: DragEvent) {
  e.preventDefault();
  const data = e.dataTransfer?.getData("fieldType");
  if (!data) return;

  const fieldType: FieldTypeOption = JSON.parse(data);
  const rect = containerRef.value?.getBoundingClientRect();
  if (!rect) return;

  const px = e.clientX - rect.left;
  const py = e.clientY - rect.top;
  const norm = toNormalized(px, py);

  const newField: DocumentField = {
    uuid: crypto.randomUUID(),
    name: `field_${Date.now()}`,
    type: fieldType.type,
    role: props.roles[0],
    areas: [
      {
        page: currentPage.value,
        x: Math.max(0, Math.min(norm.x, 1 - fieldType.defaultW)),
        y: Math.max(0, Math.min(norm.y, 1 - fieldType.defaultH)),
        w: fieldType.defaultW,
        h: fieldType.defaultH,
      },
    ],
    required: true,
    readonly: false,
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
      valign: "center",
    },
    validation: null,
  };

  fields.value.push(newField);
  selectedFieldId.value = newField.uuid;
  emit("field-select", newField);
}

function onDragOver(e: DragEvent) {
  e.preventDefault();
}

// ---------------------------------------------------------------------------
// Field dragging (move existing field)
// ---------------------------------------------------------------------------

function onFieldMouseDown(e: MouseEvent, field: DocumentField) {
  e.stopPropagation();
  selectedFieldId.value = field.uuid;
  emit("field-select", field);

  const area = field.areas.find((a) => a.page === currentPage.value);
  if (!area) return;

  const px = toPixels(area.x, area.y);
  const rect = containerRef.value?.getBoundingClientRect();
  if (!rect) return;

  dragOffset.value = {
    x: e.clientX - rect.left - px.x,
    y: e.clientY - rect.top - px.y,
  };
  isDragging.value = true;

  const onMove = (me: MouseEvent) => {
    if (!isDragging.value || !rect) return;
    const nx = (me.clientX - rect.left - dragOffset.value.x) / pageWidth.value;
    const ny = (me.clientY - rect.top - dragOffset.value.y) / pageHeight.value;
    area.x = Math.max(0, Math.min(nx, 1 - area.w));
    area.y = Math.max(0, Math.min(ny, 1 - area.h));
  };

  const onUp = () => {
    isDragging.value = false;
    document.removeEventListener("mousemove", onMove);
    document.removeEventListener("mouseup", onUp);
  };

  document.addEventListener("mousemove", onMove);
  document.addEventListener("mouseup", onUp);
}

// ---------------------------------------------------------------------------
// Field resize handle
// ---------------------------------------------------------------------------

function onResizeMouseDown(e: MouseEvent, field: DocumentField) {
  e.stopPropagation();
  const area = field.areas.find((a) => a.page === currentPage.value);
  if (!area) return;

  isResizing.value = true;
  const rect = containerRef.value?.getBoundingClientRect();

  const onMove = (me: MouseEvent) => {
    if (!isResizing.value || !rect) return;
    const nx = (me.clientX - rect.left) / pageWidth.value;
    const ny = (me.clientY - rect.top) / pageHeight.value;
    area.w = Math.max(0.02, Math.min(nx - area.x, 1 - area.x));
    area.h = Math.max(0.015, Math.min(ny - area.y, 1 - area.y));
  };

  const onUp = () => {
    isResizing.value = false;
    document.removeEventListener("mousemove", onMove);
    document.removeEventListener("mouseup", onUp);
  };

  document.addEventListener("mousemove", onMove);
  document.addEventListener("mouseup", onUp);
}

// ---------------------------------------------------------------------------
// Field actions
// ---------------------------------------------------------------------------

function deleteField(uuid: string) {
  fields.value = fields.value.filter((f) => f.uuid !== uuid);
  if (selectedFieldId.value === uuid) {
    selectedFieldId.value = null;
    emit("field-select", null);
  }
}

function duplicateField(field: DocumentField) {
  const clone: DocumentField = JSON.parse(JSON.stringify(field));
  clone.uuid = crypto.randomUUID();
  clone.name = `${field.name}_copy`;
  // Offset slightly so it's visible
  for (const area of clone.areas) {
    area.x = Math.min(area.x + 0.02, 1 - area.w);
    area.y = Math.min(area.y + 0.02, 1 - area.h);
  }
  fields.value.push(clone);
  selectedFieldId.value = clone.uuid;
}

function deselectAll() {
  selectedFieldId.value = null;
  emit("field-select", null);
}

// ---------------------------------------------------------------------------
// Page navigation
// ---------------------------------------------------------------------------

function prevPage() {
  if (currentPage.value > 1) currentPage.value--;
}
function nextPage() {
  if (currentPage.value < totalPages.value) currentPage.value++;
}

// ---------------------------------------------------------------------------
// Save
// ---------------------------------------------------------------------------

function save() {
  const template: Template = {
    template_id: props.template?.template_id ?? crypto.randomUUID(),
    name: templateName.value,
    description: templateDescription.value,
    folder_name: props.template?.folder_name ?? "",
    documents: [
      {
        name: templateName.value,
        attachment_uuid: null,
        fields: fields.value,
      },
    ],
    submitters: [...new Set(fields.value.map((f) => f.role))].map(
      (role, idx) => ({
        role,
        name: "",
        email: "",
        order: idx,
      }),
    ),
    tags: props.template?.tags ?? [],
    version: (props.template?.version ?? 0) + 1,
    created_at: props.template?.created_at ?? new Date().toISOString(),
  };
  emit("save", template);
}

// ---------------------------------------------------------------------------
// Role colors (for visual distinction)
// ---------------------------------------------------------------------------

const roleColors: Record<string, string> = {
  Signer: "#3b82f6",
  Cosigner: "#8b5cf6",
  Witness: "#f59e0b",
  Notary: "#ef4444",
  Steward: "#10b981",
  Trustee: "#6366f1",
  Discloser: "#3b82f6",
  Recipient: "#8b5cf6",
  Requestor: "#3b82f6",
};

function getRoleColor(role: string): string {
  return roleColors[role] ?? "#6b7280";
}
</script>

<template>
  <div class="skseal-builder">
    <!-- Toolbar -->
    <div class="builder-toolbar">
      <input
        v-model="templateName"
        class="template-name"
        placeholder="Template Name"
      />
      <div class="page-nav">
        <button :disabled="currentPage <= 1" @click="prevPage">&lt;</button>
        <span>Page {{ currentPage }} / {{ totalPages }}</span>
        <button :disabled="currentPage >= totalPages" @click="nextPage">&gt;</button>
      </div>
      <button class="save-btn" @click="save">Save Template</button>
    </div>

    <div class="builder-body">
      <!-- Field palette (drag source) -->
      <div class="field-palette">
        <h3>Fields</h3>
        <div
          v-for="ft in fieldTypes"
          :key="ft.type"
          class="palette-item"
          draggable="true"
          @dragstart="onDragStart($event, ft)"
        >
          <span class="palette-icon">{{ ft.icon }}</span>
          <span class="palette-label">{{ ft.label }}</span>
        </div>

        <!-- Field list for current page -->
        <h3 style="margin-top: 16px">Placed Fields</h3>
        <div
          v-for="f in currentPageFields"
          :key="f.uuid"
          class="field-list-item"
          :class="{ selected: f.uuid === selectedFieldId }"
          @click="selectedFieldId = f.uuid; emit('field-select', f)"
        >
          <span
            class="role-dot"
            :style="{ background: getRoleColor(f.role) }"
          />
          <span class="field-list-name">{{ f.title || f.name }}</span>
          <span class="field-list-type">{{ f.type }}</span>
          <button class="del-btn" @click.stop="deleteField(f.uuid)">x</button>
        </div>
      </div>

      <!-- PDF canvas with field overlays -->
      <div
        ref="containerRef"
        class="canvas-container"
        @drop="onDrop"
        @dragover="onDragOver"
        @click="deselectAll"
      >
        <canvas ref="canvasRef" />

        <!-- Field overlays -->
        <div
          v-for="field in currentPageFields"
          :key="field.uuid"
          class="field-overlay"
          :class="{
            selected: field.uuid === selectedFieldId,
            signature: field.type === 'signature' || field.type === 'pgp_signature',
          }"
          :style="{
            left: (field.areas[0]?.x ?? 0) * pageWidth + 'px',
            top: (field.areas[0]?.y ?? 0) * pageHeight + 'px',
            width: (field.areas[0]?.w ?? 0.2) * pageWidth + 'px',
            height: (field.areas[0]?.h ?? 0.025) * pageHeight + 'px',
            borderColor: getRoleColor(field.role),
            background: getRoleColor(field.role) + '20',
          }"
          @mousedown="onFieldMouseDown($event, field)"
        >
          <span class="field-label">
            {{ field.title || field.name }}
          </span>
          <span class="field-role-tag" :style="{ background: getRoleColor(field.role) }">
            {{ field.role }}
          </span>

          <!-- Resize handle -->
          <div
            class="resize-handle"
            @mousedown="onResizeMouseDown($event, field)"
          />
        </div>
      </div>

      <!-- Properties panel -->
      <div class="properties-panel" v-if="selectedField">
        <h3>Field Properties</h3>

        <label>Name</label>
        <input v-model="selectedField.name" />

        <label>Title</label>
        <input v-model="selectedField.title" />

        <label>Description</label>
        <textarea v-model="selectedField.description" rows="2" />

        <label>Role</label>
        <select v-model="selectedField.role">
          <option v-for="r in roles" :key="r" :value="r">{{ r }}</option>
        </select>

        <label>Type</label>
        <select v-model="selectedField.type">
          <option v-for="ft in fieldTypes" :key="ft.type" :value="ft.type">
            {{ ft.label }}
          </option>
        </select>

        <div class="checkbox-row">
          <label>
            <input type="checkbox" v-model="selectedField.required" />
            Required
          </label>
          <label>
            <input type="checkbox" v-model="selectedField.readonly" />
            Read-only
          </label>
        </div>

        <label>Default Value</label>
        <input v-model="selectedField.default_value" />

        <label v-if="selectedField.type === 'select' || selectedField.type === 'radio'">
          Options (comma-separated)
        </label>
        <input
          v-if="selectedField.type === 'select' || selectedField.type === 'radio'"
          :value="selectedField.options.join(', ')"
          @input="selectedField.options = ($event.target as HTMLInputElement).value.split(',').map(s => s.trim()).filter(Boolean)"
        />

        <div class="field-actions">
          <button @click="duplicateField(selectedField!)">Duplicate</button>
          <button class="danger" @click="deleteField(selectedField!.uuid)">Delete</button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.skseal-builder {
  display: flex;
  flex-direction: column;
  height: 100%;
  font-family: system-ui, -apple-system, sans-serif;
  color: #1a1a2e;
}

.builder-toolbar {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 8px 16px;
  background: #f8f9fa;
  border-bottom: 1px solid #e0e0e0;
}

.template-name {
  font-size: 16px;
  font-weight: 600;
  border: 1px solid transparent;
  padding: 4px 8px;
  border-radius: 4px;
  flex: 1;
}
.template-name:focus {
  border-color: #3b82f6;
  outline: none;
}

.page-nav {
  display: flex;
  align-items: center;
  gap: 8px;
}
.page-nav button {
  padding: 4px 10px;
  border: 1px solid #d0d0d0;
  border-radius: 4px;
  background: white;
  cursor: pointer;
}
.page-nav button:disabled {
  opacity: 0.4;
  cursor: default;
}

.save-btn {
  padding: 6px 20px;
  background: #3b82f6;
  color: white;
  border: none;
  border-radius: 6px;
  font-weight: 600;
  cursor: pointer;
}
.save-btn:hover {
  background: #2563eb;
}

.builder-body {
  display: flex;
  flex: 1;
  overflow: hidden;
}

/* Field palette */
.field-palette {
  width: 200px;
  padding: 12px;
  background: #f8f9fa;
  border-right: 1px solid #e0e0e0;
  overflow-y: auto;
}
.field-palette h3 {
  font-size: 12px;
  text-transform: uppercase;
  color: #6b7280;
  margin: 0 0 8px;
}

.palette-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 8px;
  margin-bottom: 4px;
  border: 1px solid #d0d0d0;
  border-radius: 4px;
  background: white;
  cursor: grab;
  font-size: 13px;
}
.palette-item:active {
  cursor: grabbing;
}
.palette-icon {
  width: 24px;
  height: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #e8ecf0;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  color: #4b5563;
}

.field-list-item {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 6px;
  border-radius: 4px;
  font-size: 12px;
  cursor: pointer;
}
.field-list-item:hover,
.field-list-item.selected {
  background: #e0e7ff;
}
.role-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.field-list-name {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.field-list-type {
  color: #9ca3af;
  font-size: 10px;
}
.del-btn {
  background: none;
  border: none;
  color: #ef4444;
  cursor: pointer;
  font-size: 12px;
  padding: 0 4px;
}

/* Canvas */
.canvas-container {
  flex: 1;
  position: relative;
  overflow: auto;
  background: #e5e7eb;
  display: flex;
  justify-content: center;
  padding: 20px;
}
.canvas-container canvas {
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.15);
  background: white;
}

/* Field overlays */
.field-overlay {
  position: absolute;
  border: 2px solid;
  border-radius: 2px;
  cursor: move;
  display: flex;
  align-items: center;
  padding: 0 4px;
  box-sizing: border-box;
  transition: box-shadow 0.1s;
  font-size: 11px;
}
.field-overlay.selected {
  box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.5);
  z-index: 10;
}
.field-overlay.signature {
  border-style: dashed;
}

.field-label {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
  color: #374151;
  font-size: 10px;
}

.field-role-tag {
  font-size: 9px;
  color: white;
  padding: 1px 4px;
  border-radius: 2px;
  flex-shrink: 0;
}

.resize-handle {
  position: absolute;
  right: -4px;
  bottom: -4px;
  width: 10px;
  height: 10px;
  background: white;
  border: 2px solid #3b82f6;
  border-radius: 2px;
  cursor: se-resize;
  display: none;
}
.field-overlay.selected .resize-handle {
  display: block;
}

/* Properties panel */
.properties-panel {
  width: 240px;
  padding: 12px;
  background: #f8f9fa;
  border-left: 1px solid #e0e0e0;
  overflow-y: auto;
}
.properties-panel h3 {
  font-size: 13px;
  margin: 0 0 12px;
}
.properties-panel label {
  display: block;
  font-size: 11px;
  color: #6b7280;
  margin: 8px 0 2px;
}
.properties-panel input,
.properties-panel select,
.properties-panel textarea {
  width: 100%;
  padding: 4px 8px;
  border: 1px solid #d0d0d0;
  border-radius: 4px;
  font-size: 13px;
  box-sizing: border-box;
}

.checkbox-row {
  display: flex;
  gap: 12px;
  margin: 8px 0;
}
.checkbox-row label {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 13px;
  color: #374151;
}

.field-actions {
  display: flex;
  gap: 8px;
  margin-top: 16px;
}
.field-actions button {
  flex: 1;
  padding: 6px;
  border: 1px solid #d0d0d0;
  border-radius: 4px;
  background: white;
  cursor: pointer;
  font-size: 12px;
}
.field-actions button.danger {
  color: #ef4444;
  border-color: #fca5a5;
}
.field-actions button.danger:hover {
  background: #fef2f2;
}
</style>
