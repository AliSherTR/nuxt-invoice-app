import { _ as _sfc_main$1 } from './index-BOrwQv3i.mjs';
import { defineComponent, unref, withCtx, createTextVNode, useSSRContext } from 'vue';
import { ssrRenderAttrs, ssrRenderComponent, ssrInterpolate } from 'vue/server-renderer';
import { toast } from 'vue-sonner';
import { u as useAuth } from './useAuth-Bban5XjU.mjs';
import 'reka-ui';
import 'clsx';
import 'tailwind-merge';
import 'class-variance-authority';
import './server.mjs';
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
import 'vue-router';
import '../routes/renderer.mjs';
import 'vue-bundle-renderer/runtime';
import 'unhead/server';
import 'devalue';
import 'unhead/utils';
import 'unhead/plugins';

const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "dashboard",
  __ssrInlineRender: true,
  setup(__props) {
    const { user } = useAuth();
    return (_ctx, _push, _parent, _attrs) => {
      var _a, _b, _c;
      const _component_Button = _sfc_main$1;
      _push(`<div${ssrRenderAttrs(_attrs)}><h1 class="text-2xl font-bold text-gray-900 dark:text-white mb-6"> Dashboard </h1>`);
      _push(ssrRenderComponent(_component_Button, {
        variant: "outline",
        onClick: () => {
          unref(toast)("Event has been created", {
            description: "Sunday, December 03, 2023 at 9:00 AM",
            action: {
              label: "Undo",
              onClick: () => console.log("Undo")
            }
          });
        }
      }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(` Add to calendar `);
          } else {
            return [
              createTextVNode(" Add to calendar ")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`<div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6"><h2 class="text-lg font-semibold mb-4 dark:text-white"> Welcome back, ${ssrInterpolate((_a = unref(user)) == null ? void 0 : _a.name)}! </h2><div class="space-y-2 text-sm text-gray-600 dark:text-gray-300"><p><span class="font-medium">Email:</span> ${ssrInterpolate((_b = unref(user)) == null ? void 0 : _b.email)}</p><p><span class="font-medium">User ID:</span> ${ssrInterpolate((_c = unref(user)) == null ? void 0 : _c.id)}</p></div></div></div>`);
    };
  }
});
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("pages/dashboard.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};

export { _sfc_main as default };
//# sourceMappingURL=dashboard-mUJRM8Y-.mjs.map
