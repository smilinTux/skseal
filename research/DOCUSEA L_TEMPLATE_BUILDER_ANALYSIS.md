# DocuSeal Template Builder Analysis
## skseal UX Research Supplement

**Date:** February 25, 2026  
**Focus:** Template Maker UX/UI Analysis  
**Status:** Complete

---

## 1. Template Builder Architecture

### 1.1 Technology Stack

The DocuSeal template builder represents a sophisticated single-page application built on modern web technologies:

**Frontend Framework:** Vue.js 3 with Composition API
- Component-based architecture enabling modular field palette and document canvas
- Reactive data binding for real-time template preview
- Virtual DOM optimization for handling complex multi-page documents

**State Management:** Vue reactive stores
- Centralized template state (fields, documents, submitters, settings)
- Undo/redo history management
- Autosave state persistence

**PDF Rendering:** Custom PDF.js integration
- Canvas-based document rendering for field placement
- Layer management for document content vs. interactive fields
- Zoom and pan controls for precise field positioning

### 1.2 Core Components

**Document Canvas:**
- Main workspace displaying uploaded PDF documents
- Coordinate system mapped to PDF page geometry
- Field overlay rendering with visual indicators
- Multi-page navigation with thumbnail sidebar

**Field Palette (Right Panel):**
- Draggable field type icons
- Field categories: Input, Signature, Validation, System
- Search/filter capability for complex templates
- Recent fields quick-access

**Properties Panel:**
- Context-aware configuration for selected field
- Common properties: name, required, readonly, validation
- Role assignment for multi-signer workflows
- Style preferences: fonts, colors, alignment

**Document Sidebar (Left Panel):**
- Multi-document template management
- Page navigation and thumbnail preview
- Drag-to-reorder document pages
- Add blank page functionality

---

## 2. Field Type Catalog

### 2.1 Input Fields

| Field Type | Icon | Purpose | Configuration Options |
|------------|------|---------|----------------------|
| **Text** | [T] | Single-line text input | Max length, pattern validation, placeholder, mask |
| **Number** | [#] | Numeric input with formatting | Decimal precision, currency format (USD/EUR/GBP), min/max |
| **Date** | [📅] | Date picker | Format patterns (MM/DD/YYYY, DD/MM/YYYY), date range validation |
| **DateNow** | [⚡] | Auto-insert current date | Read-only, format customization |
| **Checkbox** | [☑] | Boolean toggle | Checkbox group support, required checked state |
| **Radio** | [◉] | Single-choice selection | Option labels, default selection, required |
| **Multiple** | [☐] | Multi-select checkbox group | Option configuration, select all/none toggle |
| **Select** | [▼] | Dropdown selection | Dynamic options, search enabled, placeholder |
| **Cells** | [⊞] | Spreadsheet-like grid | Rows/columns, cell formatting, formulas |
| **Image** | [🖼] | Image upload/placement | Aspect ratio, dimensions, default image |
| **File** | [📎] | Document attachment upload | Allowed file types, max size, multiple files |
| **Phone** | [📞] | Phone number input | Format validation, country code, SMS capable |

### 2.2 Signature Fields

| Field Type | Icon | Purpose | Configuration Options |
|------------|------|---------|----------------------|
| **Signature** | [✍] | E-signature capture | Drawn, typed, upload, drawn_or_typed modes |
| **Initials** | [🆔] | Initials capture | Auto-generate from name field, style preferences |
| **Stamp** | [🔏] | Seal/stamp image | Upload custom stamp, pre-defined templates |
| **Strikethrough** | [̶S̶] | Strikethrough content | Line style, color, position relative to text |

### 2.3 System Fields

| Field Type | Icon | Purpose | Configuration Options |
|------------|------|---------|----------------------|
| **Heading** | [H] | Section labels | Rich text support, styling |
| **Verification** | [✓] | Identity verification | SMS, email 2FA, knowledge-based auth (KBA) |
| **Payment** | [💳] | Payment collection | Amount, currency, payment processor integration |

---

## 3. Drag-and-Drop UX Flow

### 3.1 Field Placement Process

```
┌─────────────────────────────────────────────────────────────────┐
│                    TEMPLATE BUILDER FLOW                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. UPLOAD          2. FIELD PALETTE        3. CANVAS DROP       │
│  ┌─────────┐        ┌────────────────┐       ┌───────────────┐   │
│  │  PDF    │───────>│  [Signature]   │──────>│  [PDF Preview]│   │
│  │ Upload  │        │  [Text]        │       │   + Field     │   │
│  └─────────┘        │  [Date]        │       │   + Overlay   │   │
│                     │  [Checkbox]    │       └───────────────┘   │
│                     └────────────────┘                           │
│                           │                                      │
│                           v                                      │
│  4. PROPERTIES      5. ROLE BINDING       6. VALIDATION          │
│  ┌─────────────┐     ┌─────────────┐       ┌─────────────┐      │
│  │ Field Name  │     │ Signer A    │       │ Required?   │      │
│  │ Required ✓  │     │ Signer B    │       │ Pattern     │      │
│  │ Pattern...  │     │ Signer C    │       │ Min/Max     │      │
│  └─────────────┘     └─────────────┘       └─────────────┘      │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Interaction Patterns

**Direct Drag:**
1. Click and hold field icon from palette
2. Drag to target position on document
3. Release to place field at coordinates
4. Field automatically sizes to reasonable default

**Click-to-Place:**
1. Click field type in palette
2. Cursor changes to field preview
3. Click on document to place
4. Drag to adjust position after placement

**Draw Mode:**
1. Click signature/initials field
2. Click and drag to define field area
3. Precise control over field dimensions
4. Visual feedback during sizing

**Selection & Drag:**
1. Click existing field to select
2. Drag handles appear at corners
3. Resize without affecting document content
4. Arrow keys for pixel-perfect positioning

### 3.3 Visual Feedback System

**Field States:**
- **Default:** Light highlight on hover, shows field name/type icon
- **Selected:** Bold border, resize handles visible
- **Filled:** Indicates signer has completed this field
- **Required:** Subtle indicator (asterisk or color) when incomplete
- **Error:** Red border with validation message on invalid input

**Placement Aids:**
- Snap-to-grid (8px increments)
- Smart guides showing alignment with other fields
- Collision detection prevents overlapping fields
- Page boundary indicators prevent off-canvas placement

---

## 4. Template Data Model

### 4.1 JSON Schema Structure

DocuSeal templates are stored as structured JSON documents defining all aspects of the template:

```json
{
  "template_id": 1000001,
  "name": "Real Estate Purchase Agreement",
  "external_id": "RE-2026-001",
  "folder_name": "Real Estate",
  
  "documents": [
    {
      "name": "Purchase Agreement",
      "attachment_uuid": "uuid-reference",
      "fields": [
        {
          "uuid": "field-uuid",
          "name": "Buyer Full Name",
          "type": "text",
          "role": "Buyer",
          "required": true,
          "readonly": false,
          "areas": [
            {
              "page": 1,
              "x": 0.15,
              "y": 0.35,
              "w": 0.35,
              "h": 0.025
            }
          ],
          "preferences": {
            "font_size": 12,
            "font_type": "bold",
            "font": "Helvetica",
            "color": "black",
            "background": "white",
            "align": "left",
            "valign": "center"
          },
          "validation": {
            "pattern": "^[A-Za-z\\s]+$",
            "message": "Please enter a valid name",
            "min": 2,
            "max": 100
          },
          "title": "Full Legal Name",
          "description": "Enter your full legal name as it appears on ID"
        }
      ]
    }
  ],
  
  "submitters": [
    {
      "role": "Buyer",
      "email": "buyer@example.com",
      "name": "Buyer Name",
      "order": 0
    },
    {
      "role": "Seller",
      "email": "seller@example.com",
      "name": "Seller Name", 
      "order": 1
    }
  ],
  
  "settings": {
    "expire_after_days": 30,
    "reminder_days": 7,
    "allow_decline": true,
    "allow_forwarding": false
  }
}
```

### 4.2 Coordinate System

Fields are positioned using **normalized coordinates** (0.0-1.0) rather than absolute pixels:

```typescript
interface FieldArea {
  page: number;           // 1-indexed page number
  x: number;              // Horizontal position (0.0 = left, 1.0 = right)
  y: number;              // Vertical position (0.0 = top, 1.0 = bottom)
  w: number;              // Field width as fraction of page width
  h: number;              // Field height as fraction of page height
}

// Benefits of normalized coordinates:
// - Resolution independent
// - PDF page size changes don't break positioning
// - Easy to calculate responsive canvas positions
```

### 4.3 Field Type Enumeration

```typescript
enum FieldType {
  HEADING = 'heading',
  TEXT = 'text',
  SIGNATURE = 'signature',
  INITIALS = 'initials',
  DATE = 'date',
  DATENOW = 'datenow',
  NUMBER = 'number',
  IMAGE = 'image',
  CHECKBOX = 'checkbox',
  MULTIPLE = 'multiple',
  FILE = 'file',
  RADIO = 'radio',
  SELECT = 'select',
  CELLS = 'cells',
  STAMP = 'stamp',
  PAYMENT = 'payment',
  PHONE = 'phone',
  VERIFICATION = 'verification',
  KBA = 'kba',
  STRIKETHROUGH = 'strikethrough'
}
```

---

## 5. Multi-Signer Workflow Visualization

### 5.1 Role-Based Field Assignment

Fields are bound to specific signer roles, enabling complex multi-party workflows:

```
┌─────────────────────────────────────────────────────────────┐
│                    DOCUMENT WORKFLOW                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────┐       ┌──────────────────┐            │
│  │   PAGE 1         │       │   PAGE 2         │            │
│  │                  │       │                  │            │
│  │  [Buyer Name]    │       │  [Seller Sig]    │            │
│  │  role: Buyer     │       │  role: Seller    │            │
│  │  required: true  │       │  required: true  │            │
│  │                  │       │                  │            │
│  │  [Buyer Address] │       │  [Witness Sig]   │            │
│  │  role: Buyer     │       │  role: Witness   │            │
│  │                  │       │                  │            │
│  └──────────────────┘       └──────────────────┘            │
│                                                              │
│  WORKFLOW SEQUENCE:                                           │
│  ┌──────────────────────────────────────────────────┐       │
│  │  1. Buyer completes fields                        │       │
│  │     → Submit                                      │       │
│  │                                                  │       │
│  │  2. Seller reviews buyer's entries               │       │
│  │     → Signs at designated location               │       │
│  │                                                  │       │
│  │  3. Witness provides acknowledgment             │       │
│  │     → Final verification                         │       │
│  └──────────────────────────────────────────────────┘       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Workflow Configuration Options

| Configuration | Description | Use Case |
|---------------|-------------|----------|
| **Preserved Order** | Submitters sign in specified sequence | Standard contracts, legal documents |
| **Random Order** | All parties receive requests simultaneously | Collaborative forms, internal approvals |
| **Order Groups** | Multiple signers with same order sign together | Joint ownership, co-borrowers |
| **Invite By** | Previous signer invites next party | Referral workflows, agent chains |

---

## 6. API Integration Patterns

### 6.1 Template CRUD Operations

**Create Template from PDF:**
```bash
POST /api/templates/pdf
Content-Type: multipart/form-data

- file: PDF document
- name: Template name
- fields: JSON array of field configurations
```

**Retrieve Template:**
```bash
GET /api/templates/{id}
X-Auth-Token: {API_KEY}

Response includes complete template structure with all fields
```

**Update Template:**
```bash
PUT /api/templates/{id}
X-Auth-Token: {API_KEY}
Content-Type: application/json

{
  "name": "Updated Template Name",
  "fields": [updated field configurations]
}
```

**Clone Template:**
```bash
POST /api/templates/{id}/clone
X-Auth-Token: {API_KEY}

Creates copy with new template_id for versioning
```

### 6.2 Embedded Builder Integration

The template builder can be embedded in third-party applications:

```html
<!-- JavaScript SDK Integration -->
<script src="https://cdn.docuseal.com/js/builder.js"></script>

<docuseal-builder
  data-token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  data-name="New Template"
  document_urls='["https://example.com/document.pdf"]'
  data-roles="Buyer,Seller,Agent"
  data-field-types="text,signature,date"
>
</docuseal-builder>
```

**React Component:**
```jsx
import { DocusealBuilder } from '@docuseal/react';

<DocusealBuilder
  token={authToken}
  name="Contract Template"
  document_urls={['https://example.com/contract.pdf']}
  roles={['Party A', 'Party B']}
  onSave={(template) => console.log('Saved:', template)}
/>
```

### 6.3 Template Export/Import

Templates can be exported as JSON for backup or migration:

```json
// template-export.json
{
  "export_version": "1.0",
  "exported_at": "2026-02-25T20:30:00Z",
  "template": { /* full template JSON */ },
  "metadata": {
    "source_version": "DocuSeal 2.x",
    "field_count": 24,
    "page_count": 4
  }
}
```

---

## 7. skseal Template Builder Recommendations

### 7.1 Key Features to Replicate

| Feature | DocuSeal Approach | skseal Implementation |
|---------|-------------------|----------------------|
| **Drag-and-Drop** | Vue.js draggable components | React DnD or react-beautiful-dnd |
| **PDF Rendering** | PDF.js canvas layer | pdf-lib + canvas rendering |
| **Field Palette** | Vue component with icons | Material-UI icons + custom |
| **Properties Panel** | Reactive form controls | React Hook Form + Zod |
| **Multi-Page** | Thumbnail navigation | Custom thumbnail component |
| **Autosave** | Local storage + debounce | IndexedDB + React Query |
| **Undo/Redo** | History stack | Redux Toolkit undo/redo |

### 7.2 skseal Differentiators

While replicating DocuSeal's excellent UX, skseal should enhance with PGP-specific features:

**PGP Key Integration:**
- Drag PGP key rings to signature fields
- Auto-populate signer fields from Web of Trust
- Signature verification status indicators
- Key fingerprint display on signatures

**Cryptographic Field Types:**
- PGP signature capture (detached sig generation)
- Timestamp request button
- Document hash verification display
- Signing key selector modal

**Trust Visualization:**
- Signer key trust level indicators
- Web of Trust path display
- Certification chain browser
- Key expiration warnings

### 7.3 Implementation Priority

**Phase 1 (MVP):**
- Basic PDF upload and display
- Signature field placement
- Simple text input fields
- Save/load template functionality

**Phase 2 (Enhanced UX):**
- Full field type palette
- Drag-and-drop with snap-to-grid
- Properties panel for field configuration
- Multi-document templates

**Phase 3 (skseal Integration):**
- PGP key integration
- Web of Trust visualization
- Timestamp authority integration
- Cryptographic seal generation

---

## 8. Database Schema for Templates

### 8.1 Core Tables

```sql
-- Templates table
CREATE TABLE templates (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    external_id VARCHAR(255),
    folder_name VARCHAR(100),
    user_id BIGINT REFERENCES users(id),
    settings JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Documents within templates
CREATE TABLE template_documents (
    id BIGSERIAL PRIMARY KEY,
    template_id BIGINT REFERENCES templates(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    file_uuid UUID NOT NULL,
    position INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Fields within documents
CREATE TABLE template_fields (
    id BIGSERIAL PRIMARY KEY,
    document_id BIGINT REFERENCES template_documents(id) ON DELETE CASCADE,
    uuid UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    role VARCHAR(100),
    required BOOLEAN DEFAULT FALSE,
    readonly BOOLEAN DEFAULT FALSE,
    default_value TEXT,
    title VARCHAR(255),
    description TEXT,
    preferences JSONB DEFAULT '{}'::jsonb,
    validation JSONB DEFAULT '{}'::jsonb,
    options JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Field area positions (can have multiple areas for same field)
CREATE TABLE field_areas (
    id BIGSERIAL PRIMARY KEY,
    field_id BIGINT REFERENCES template_fields(id) ON DELETE CASCADE,
    page INTEGER NOT NULL,
    x NUMERIC(5,4) NOT NULL,
    y NUMERIC(5,4) NOT NULL,
    w NUMERIC(5,4) NOT NULL,
    h NUMERIC(5,4) NOT NULL
);

-- Template submitters (roles)
CREATE TABLE template_submitters (
    id BIGSERIAL PRIMARY KEY,
    template_id BIGINT REFERENCES templates(id) ON DELETE CASCADE,
    role VARCHAR(100) NOT NULL,
    email VARCHAR(255),
    name VARCHAR(255),
    order_index INTEGER DEFAULT 0,
    UNIQUE(template_id, role)
);

-- Indexes for performance
CREATE INDEX idx_templates_user ON templates(user_id);
CREATE INDEX idx_fields_document ON template_fields(document_id);
CREATE INDEX idx_areas_field ON field_areas(field_id);
CREATE INDEX idx_submitters_template ON template_submitters(template_id);
```

---

## 9. Performance Considerations

### 9.1 Rendering Optimization

**Large Document Handling:**
- Lazy load pages beyond visible viewport
- Virtual scrolling for documents with 50+ pages
- Debounce field selection for complex templates
- Web Workers for PDF text extraction

**Field Rendering:**
- Canvas-based field overlay instead of DOM elements
- CSS transform for positioning (GPU acceleration)
- RequestAnimationFrame for smooth drag operations
- Throttle resize events during field manipulation

### 9.2 Autosave Strategy

**Save Points:**
- Field placement complete
- Properties panel close
- Document/page change
- Debounced (1000ms) typing in properties

**Storage:**
- IndexedDB for local draft storage
- Compress template JSON before save
- Background sync to server
- Conflict resolution on concurrent edits

---

## 10. Security Considerations

### 10.1 Template Access Control

- JWT-based authentication for embedded builder
- Role-based permission checks
- Template ownership validation
- Audit log for template modifications

### 10.2 Document Security

- PDF upload validation (type, size, malware scan)
- Secure file storage (encrypted at rest)
- Signed template bundles
- Revocation list for compromised templates

---

## Conclusion

DocuSeal's template builder represents the gold standard for document signing UX. The drag-and-drop interface, comprehensive field types, and intuitive workflow configuration enable rapid template creation without specialized training. For skseal, replicating this UX foundation while adding PGP-specific features creates a unique value proposition: user-friendly document signing with sovereign cryptographic verification.

The key to successful implementation lies in separating the template data model (which should be highly compatible with DocuSeal) from the signing mechanism (which uses PGP instead of PDF digital signatures). This separation enables template interchange while maintaining skseal's sovereign architecture.

---

**Document Version:** 1.0  
**Research Completed:** February 25, 2026  
**Next Step:** Begin prototype development