import tailwindcss from "@tailwindcss/vite";

// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: "2025-07-15",
  css: ["~/assets/css/main.css"],
  modules: ["shadcn-nuxt", "@nuxtjs/color-mode", "@nuxt/image"],
  colorMode: {
    classSuffix: "",
  },
  shadcn: {
    /**
     * Prefix for all the imported component
     */
    prefix: "",
    /**
     * Directory that the component lives in.
     * @default "./components/ui"
     */
    componentDir: "./components/ui",
  },
  vite: { plugins: [tailwindcss()] },
  devtools: { enabled: true },

  runtimeConfig: {
    mongoUrl: "",
    jwtSecret: "",
    public: {},
  },
});
