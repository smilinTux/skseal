import type { Document } from "../types.js";
interface Props {
    documentId: string;
    apiUrl: string;
    authToken?: string;
}
declare const _default: import("vue").DefineComponent<Props, {}, {}, {}, {}, import("vue").ComponentOptionsMixin, import("vue").ComponentOptionsMixin, {
    signed: (document: Document) => any;
    error: (message: string) => any;
}, string, import("vue").PublicProps, Readonly<Props> & Readonly<{
    onSigned?: ((document: Document) => any) | undefined;
    onError?: ((message: string) => any) | undefined;
}>, {}, {}, {}, {}, string, import("vue").ComponentProvideOptions, false, {}, any>;
export default _default;
//# sourceMappingURL=SigningView.vue.d.ts.map