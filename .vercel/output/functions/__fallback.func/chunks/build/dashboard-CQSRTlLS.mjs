import { u as useColorMode, _ as _sfc_main$1, l as logo, a as __nuxt_component_1, b as _sfc_main$2 } from './composables-BQ3d7Hqn.mjs';
import { defineComponent, unref, useSSRContext } from 'vue';
import { ssrRenderAttrs, ssrRenderComponent, ssrRenderAttr, ssrRenderSlot } from 'vue/server-renderer';
import { u as useAuth } from './useAuth-Bban5XjU.mjs';
import '../nitro/nitro.mjs';
import 'node:os';
import 'node:tty';
import 'node:fs';
import 'node:path';
import 'node:crypto';
import 'node:child_process';
import 'node:fs/promises';
import 'node:util';
import 'node:process';
import 'node:async_hooks';
import 'node:events';
import 'path';
import 'fs';
import 'node:http';
import 'node:https';
import 'node:buffer';
import 'jose';
import 'node:url';
import 'ipx';
import './server.mjs';
import 'vue-router';
import '../routes/renderer.mjs';
import 'vue-bundle-renderer/runtime';
import 'unhead/server';
import 'devalue';
import 'unhead/utils';
import 'unhead/plugins';
import 'vue-sonner';

const avatar = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAYGBgYHBgcICAcKCwoLCg8ODAwODxYQERAREBYiFRkVFRkVIh4kHhweJB42KiYmKjY+NDI0PkxERExfWl98fKcBBgYGBgcGBwgIBwoLCgsKDw4MDA4PFhAREBEQFiIVGRUVGRUiHiQeHB4kHjYqJiYqNj40MjQ+TERETF9aX3x8p//CABEIAFAAUAMBIgACEQEDEQH/xAAcAAABBAMBAAAAAAAAAAAAAAAAAgMHCAEEBQb/2gAIAQEAAAAAsvkyGTAk1IO8pJ8tBhGYhrh6vnW47oNlcPGu9+fPSA2efrf0OPbDaBkIkqptX02jLJiM6WIkCw8o7yTl1Di5Ww9tWam+LKq8VkEPyNdCifkVIU2jYkr/xAAZAQACAwEAAAAAAAAAAAAAAAACAwABBAX/2gAIAQIQAAAAblTvhcgesRZ83QhRDSoKpn//xAAaAQABBQEAAAAAAAAAAAAAAAACAAEDBAUG/9oACAEDEAAAAKWpbwkHVFzMcd69ioFKDJ3cP//EADUQAAEDAwIEBAMFCQAAAAAAAAECAwQABREGEgchMUEQE1FxIzJhFCAigaEkMENSYnORsbL/2gAIAQEAAT8A/eTp8aBEdlSF7W2xkn/QFXriPcH3HExlllvshPzfmaY13dobu5qepPqCdwNaZ4msznUMT0NpJwA810yf5k/f4s3dDEOFCC8KUovL9hyFIdm3WZ9mhgD1UegFRNFQXE4euRW73DbiautkXYyJUO5Jd8oBa2s/FQM/MMVpe5quunrXOUQVPR0lR9VDkfvcb25qrnaW2W8+ewUJP1SasVuet1sC2GQ6+vkSe1RLROnX6O624UNJKC6Rke4qXo2UxdX2ypZZfcKvPIBBZUMFs9wa0fZzZNM2m3KcC1MMAKUOhKiVeOazWa1LZGL1bVMLbSpxCgtonsodsnsakOXiwXh+NObLe7C8HBGFHqCKmasb+xurYkojObCGso3FSu5AqxaucDq0Trm+4XEpShK8FvJ9qgn9iif2G/8AkVnwzWazWa4vWVcuwi6R0ZfhfP8AVldIuKFv71gZCAlKlDcE889KTdhsIW+F5UMI8tKR16jFQZMeTDjPx3EOMuNJLa0HKSMdq3Vms1nw51xafksaOkOMTksEPIyg/wAcd26ccUtRJAHtSeorSOvNQ6cfZTHlLciJXlcRZ+GoVY+MmnZ6g3NYehLPc/ERUK526e0HIcxh9J7oWFeG2sVd71bLLDVKnyUMtjpnqo+iR3NcR9cPaqmseW2WokbcGW+53dVqojn0oJ6ZpKsdKRILfTmfWmZslpYcQ6pKwchQPMVwo17NvK3bTcnvNfbb3sOn5lpHVKvDiLxERphCIcNKVz3UZ59GkHuau1/ud3kqfnTHX3PVZzj6CiaV1A8CcAn0oHn+VJVXCt5aNcWbb3cWD7FB8NbXc3PU13lbypCpSw2f6EnaK3/qa71nK/BR/CaTkmh+grhQnOubR7un/DZr/8QAIBEAAgICAgIDAAAAAAAAAAAAAQIAEQMEEDEhQRMgcf/aAAgBAgEBPwCbO3jwUDZY+hMO/jyEBlKEn6Z0HzO7Vd+IgtqJBFRRSj85za6vZ9zHrhDK5PUqKZ4PU6swknle5//EACARAAICAgEFAQAAAAAAAAAAAAECABEDBAUQICExQWH/2gAIAQMBAT8AnH8Vs71lKVB7Y+pt8Ds4AWTIuVQPNe+zU2GGpgwYiQtEu36fkZnVbUENMpByuQPp6XNXcfFSfLmTfLi7A8QmyZfQWDLldtQz/9k=";
const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "dashboard",
  __ssrInlineRender: true,
  setup(__props) {
    useColorMode();
    const { user, isLoading } = useAuth();
    return (_ctx, _push, _parent, _attrs) => {
      const _component_NuxtImg = _sfc_main$1;
      const _component_ClientOnly = __nuxt_component_1;
      _push(`<div${ssrRenderAttrs(_attrs)}>`);
      if (unref(isLoading)) {
        _push(`<div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-[#0c0e16]"><div class="text-center"><div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mx-auto mb-4"></div><p class="text-gray-600 dark:text-gray-300">Loading...</p></div></div>`);
      } else if (unref(user)) {
        _push(`<div class="flex h-screen overflow-hidden"><aside class="w-[7%] bg-[#373b53] h-full overflow-hidden rounded-r-4xl flex flex-col"><div>`);
        _push(ssrRenderComponent(_component_NuxtImg, {
          src: unref(logo),
          alt: "",
          class: "w-full"
        }, null, _parent));
        _push(`</div><div class="mt-auto mb-10"><div class="flex items-center justify-center">`);
        _push(ssrRenderComponent(_component_ClientOnly, null, {}, _parent));
        _push(`</div></div><hr class="dark:border-white border-gray-600"><div class="flex items-center justify-center py-8"><img${ssrRenderAttr("src", unref(avatar))} alt="Avatar" class="size-12 rounded-full object-cover"></div></aside><main class="flex-1 overflow-y-auto p-5 dark:bg-[#0c0e16] bg-white pt-12 w-full mx-auto flex items-center justify-center"><div class="flex-1 max-w-xl">`);
        ssrRenderSlot(_ctx.$slots, "default", {}, null, _push, _parent);
        _push(ssrRenderComponent(unref(_sfc_main$2), null, null, _parent));
        _push(`</div></main></div>`);
      } else {
        _push(`<!---->`);
      }
      _push(`</div>`);
    };
  }
});
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("layouts/dashboard.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};

export { _sfc_main as default };
//# sourceMappingURL=dashboard-CQSRTlLS.mjs.map
