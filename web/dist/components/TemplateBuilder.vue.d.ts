import type { DocumentField, Template } from "../types.js";
interface Props {
    pdfUrl: string;
    template?: Template;
    roles?: string[];
}
declare const _default: import("vue").DefineComponent<Props, {}, {}, {}, {}, import("vue").ComponentOptionsMixin, import("vue").ComponentOptionsMixin, {
    save: (template: Template) => any;
    "field-select": (field: DocumentField | null) => any;
}, string, import("vue").PublicProps, Readonly<Props> & Readonly<{
    onSave?: ((template: Template) => any) | undefined;
    "onField-select"?: ((field: DocumentField | null) => any) | undefined;
}>, {
    roles: string[];
}, {}, {}, {}, string, import("vue").ComponentProvideOptions, false, {}, any>;
export default _default;
//# sourceMappingURL=TemplateBuilder.vue.d.ts.map