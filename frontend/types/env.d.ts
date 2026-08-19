declare module "*.vue" {
  import { defineComponent } from "vue";
  const Component: ReturnType<typeof defineComponent>;
  export default Component;
}

interface ImportMetaEnv {
  readonly VITE_ENABLE_REPORT_SCORING?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

