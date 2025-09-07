import { defineComponent, ref, unref, withCtx, createTextVNode, mergeProps, createVNode, withModifiers, createBlock, openBlock, toDisplayString, useSSRContext } from 'vue';
import { ssrRenderComponent, ssrRenderAttrs, ssrInterpolate } from 'vue/server-renderer';
import { _ as __nuxt_component_0 } from './nuxt-link-Fe0MeZIi.mjs';
import { EyeOff, Eye } from 'lucide-vue-next';
import { useForm, Field } from 'vee-validate';
import { S as SignUpFormSchema, _ as _sfc_main$4, a as _sfc_main$2, b as _sfc_main$5, c as _sfc_main$3, d as _sfc_main$1$1 } from './Input-DU6TCW-2.mjs';
import { _ as _sfc_main$6 } from './index-BOrwQv3i.mjs';
import { toast } from 'vue-sonner';
import { u as useAuth } from './useAuth-Bban5XjU.mjs';
import { u as useHead } from './server.mjs';
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
import 'reka-ui';
import '@vueuse/core';
import 'zod';
import '@vee-validate/zod';
import 'clsx';
import 'tailwind-merge';
import 'class-variance-authority';
import 'vue-router';
import '../routes/renderer.mjs';
import 'vue-bundle-renderer/runtime';
import 'unhead/server';
import 'devalue';
import 'unhead/utils';
import 'unhead/plugins';

const _sfc_main$1 = /* @__PURE__ */ defineComponent({
  __name: "SignUpForm",
  __ssrInlineRender: true,
  setup(__props) {
    const { register, isLoading } = useAuth();
    const form = useForm({
      validationSchema: SignUpFormSchema
    });
    const isPasswordVisible = ref(false);
    const isConfirmPasswordVisible = ref(false);
    const togglePassword = () => {
      isPasswordVisible.value = !isPasswordVisible.value;
    };
    const toggleConfirmPassword = () => {
      isConfirmPasswordVisible.value = !isConfirmPasswordVisible.value;
    };
    form.handleSubmit(async (values) => {
      const res = await register(values);
      if (res.success) {
        toast.success(res.message, {
          style: {
            background: "green",
            border: "1px solid green",
            color: "white"
          }
        });
      } else {
        toast.error(res.message, {
          style: {
            background: "red",
            border: "1px solid red",
            color: "white"
          }
        });
      }
    });
    return (_ctx, _push, _parent, _attrs) => {
      const _component_NuxtLink = __nuxt_component_0;
      _push(`<div${ssrRenderAttrs(_attrs)}><div><h1 class="text-2xl font-semibold mb-4">Invoicify</h1><p class="text-sm dark:text-gray-300 text-black mb-6"> Enter your details to Sign Up. </p><form class="space-y-4">`);
      _push(ssrRenderComponent(unref(Field), { name: "name" }, {
        default: withCtx(({ componentField }, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(ssrRenderComponent(unref(_sfc_main$4), null, {
              default: withCtx((_, _push3, _parent3, _scopeId2) => {
                if (_push3) {
                  _push3(ssrRenderComponent(unref(_sfc_main$2), null, {
                    default: withCtx((_2, _push4, _parent4, _scopeId3) => {
                      if (_push4) {
                        _push4(`Name`);
                      } else {
                        return [
                          createTextVNode("Name")
                        ];
                      }
                    }),
                    _: 2
                  }, _parent3, _scopeId2));
                  _push3(ssrRenderComponent(unref(_sfc_main$5), null, {
                    default: withCtx((_2, _push4, _parent4, _scopeId3) => {
                      if (_push4) {
                        _push4(ssrRenderComponent(unref(_sfc_main$3), mergeProps({
                          type: "text",
                          placeholder: "John Doe"
                        }, componentField), null, _parent4, _scopeId3));
                      } else {
                        return [
                          createVNode(unref(_sfc_main$3), mergeProps({
                            type: "text",
                            placeholder: "John Doe"
                          }, componentField), null, 16)
                        ];
                      }
                    }),
                    _: 2
                  }, _parent3, _scopeId2));
                  _push3(ssrRenderComponent(unref(_sfc_main$1$1), null, null, _parent3, _scopeId2));
                } else {
                  return [
                    createVNode(unref(_sfc_main$2), null, {
                      default: withCtx(() => [
                        createTextVNode("Name")
                      ]),
                      _: 1
                    }),
                    createVNode(unref(_sfc_main$5), null, {
                      default: withCtx(() => [
                        createVNode(unref(_sfc_main$3), mergeProps({
                          type: "text",
                          placeholder: "John Doe"
                        }, componentField), null, 16)
                      ]),
                      _: 2
                    }, 1024),
                    createVNode(unref(_sfc_main$1$1))
                  ];
                }
              }),
              _: 2
            }, _parent2, _scopeId));
          } else {
            return [
              createVNode(unref(_sfc_main$4), null, {
                default: withCtx(() => [
                  createVNode(unref(_sfc_main$2), null, {
                    default: withCtx(() => [
                      createTextVNode("Name")
                    ]),
                    _: 1
                  }),
                  createVNode(unref(_sfc_main$5), null, {
                    default: withCtx(() => [
                      createVNode(unref(_sfc_main$3), mergeProps({
                        type: "text",
                        placeholder: "John Doe"
                      }, componentField), null, 16)
                    ]),
                    _: 2
                  }, 1024),
                  createVNode(unref(_sfc_main$1$1))
                ]),
                _: 2
              }, 1024)
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(ssrRenderComponent(unref(Field), { name: "email" }, {
        default: withCtx(({ componentField }, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(ssrRenderComponent(unref(_sfc_main$4), null, {
              default: withCtx((_, _push3, _parent3, _scopeId2) => {
                if (_push3) {
                  _push3(ssrRenderComponent(unref(_sfc_main$2), null, {
                    default: withCtx((_2, _push4, _parent4, _scopeId3) => {
                      if (_push4) {
                        _push4(`Email`);
                      } else {
                        return [
                          createTextVNode("Email")
                        ];
                      }
                    }),
                    _: 2
                  }, _parent3, _scopeId2));
                  _push3(ssrRenderComponent(unref(_sfc_main$5), null, {
                    default: withCtx((_2, _push4, _parent4, _scopeId3) => {
                      if (_push4) {
                        _push4(ssrRenderComponent(unref(_sfc_main$3), mergeProps({
                          type: "email",
                          placeholder: "johnDoe@example.com"
                        }, componentField), null, _parent4, _scopeId3));
                      } else {
                        return [
                          createVNode(unref(_sfc_main$3), mergeProps({
                            type: "email",
                            placeholder: "johnDoe@example.com"
                          }, componentField), null, 16)
                        ];
                      }
                    }),
                    _: 2
                  }, _parent3, _scopeId2));
                  _push3(ssrRenderComponent(unref(_sfc_main$1$1), null, null, _parent3, _scopeId2));
                } else {
                  return [
                    createVNode(unref(_sfc_main$2), null, {
                      default: withCtx(() => [
                        createTextVNode("Email")
                      ]),
                      _: 1
                    }),
                    createVNode(unref(_sfc_main$5), null, {
                      default: withCtx(() => [
                        createVNode(unref(_sfc_main$3), mergeProps({
                          type: "email",
                          placeholder: "johnDoe@example.com"
                        }, componentField), null, 16)
                      ]),
                      _: 2
                    }, 1024),
                    createVNode(unref(_sfc_main$1$1))
                  ];
                }
              }),
              _: 2
            }, _parent2, _scopeId));
          } else {
            return [
              createVNode(unref(_sfc_main$4), null, {
                default: withCtx(() => [
                  createVNode(unref(_sfc_main$2), null, {
                    default: withCtx(() => [
                      createTextVNode("Email")
                    ]),
                    _: 1
                  }),
                  createVNode(unref(_sfc_main$5), null, {
                    default: withCtx(() => [
                      createVNode(unref(_sfc_main$3), mergeProps({
                        type: "email",
                        placeholder: "johnDoe@example.com"
                      }, componentField), null, 16)
                    ]),
                    _: 2
                  }, 1024),
                  createVNode(unref(_sfc_main$1$1))
                ]),
                _: 2
              }, 1024)
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(ssrRenderComponent(unref(Field), { name: "password" }, {
        default: withCtx(({ componentField }, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(ssrRenderComponent(unref(_sfc_main$4), null, {
              default: withCtx((_, _push3, _parent3, _scopeId2) => {
                if (_push3) {
                  _push3(ssrRenderComponent(unref(_sfc_main$2), null, {
                    default: withCtx((_2, _push4, _parent4, _scopeId3) => {
                      if (_push4) {
                        _push4(`Password`);
                      } else {
                        return [
                          createTextVNode("Password")
                        ];
                      }
                    }),
                    _: 2
                  }, _parent3, _scopeId2));
                  _push3(ssrRenderComponent(unref(_sfc_main$5), null, {
                    default: withCtx((_2, _push4, _parent4, _scopeId3) => {
                      if (_push4) {
                        _push4(`<div class="relative"${_scopeId3}>`);
                        _push4(ssrRenderComponent(unref(_sfc_main$3), mergeProps({
                          type: isPasswordVisible.value ? "text" : "password",
                          placeholder: "Enter Your password"
                        }, componentField), null, _parent4, _scopeId3));
                        _push4(`<button class="absolute inset-y-0 right-0 pr-3 flex items-center text-sm text-gray-600"${_scopeId3}>`);
                        if (isPasswordVisible.value) {
                          _push4(`<div${_scopeId3}>`);
                          _push4(ssrRenderComponent(unref(EyeOff), null, null, _parent4, _scopeId3));
                          _push4(`</div>`);
                        } else {
                          _push4(`<div${_scopeId3}>`);
                          _push4(ssrRenderComponent(unref(Eye), null, null, _parent4, _scopeId3));
                          _push4(`</div>`);
                        }
                        _push4(`</button></div>`);
                      } else {
                        return [
                          createVNode("div", { class: "relative" }, [
                            createVNode(unref(_sfc_main$3), mergeProps({
                              type: isPasswordVisible.value ? "text" : "password",
                              placeholder: "Enter Your password"
                            }, componentField), null, 16, ["type"]),
                            createVNode("button", {
                              onClick: withModifiers(togglePassword, ["prevent"]),
                              class: "absolute inset-y-0 right-0 pr-3 flex items-center text-sm text-gray-600"
                            }, [
                              isPasswordVisible.value ? (openBlock(), createBlock("div", { key: 0 }, [
                                createVNode(unref(EyeOff))
                              ])) : (openBlock(), createBlock("div", { key: 1 }, [
                                createVNode(unref(Eye))
                              ]))
                            ])
                          ])
                        ];
                      }
                    }),
                    _: 2
                  }, _parent3, _scopeId2));
                  _push3(ssrRenderComponent(unref(_sfc_main$1$1), null, null, _parent3, _scopeId2));
                } else {
                  return [
                    createVNode(unref(_sfc_main$2), null, {
                      default: withCtx(() => [
                        createTextVNode("Password")
                      ]),
                      _: 1
                    }),
                    createVNode(unref(_sfc_main$5), null, {
                      default: withCtx(() => [
                        createVNode("div", { class: "relative" }, [
                          createVNode(unref(_sfc_main$3), mergeProps({
                            type: isPasswordVisible.value ? "text" : "password",
                            placeholder: "Enter Your password"
                          }, componentField), null, 16, ["type"]),
                          createVNode("button", {
                            onClick: withModifiers(togglePassword, ["prevent"]),
                            class: "absolute inset-y-0 right-0 pr-3 flex items-center text-sm text-gray-600"
                          }, [
                            isPasswordVisible.value ? (openBlock(), createBlock("div", { key: 0 }, [
                              createVNode(unref(EyeOff))
                            ])) : (openBlock(), createBlock("div", { key: 1 }, [
                              createVNode(unref(Eye))
                            ]))
                          ])
                        ])
                      ]),
                      _: 2
                    }, 1024),
                    createVNode(unref(_sfc_main$1$1))
                  ];
                }
              }),
              _: 2
            }, _parent2, _scopeId));
          } else {
            return [
              createVNode(unref(_sfc_main$4), null, {
                default: withCtx(() => [
                  createVNode(unref(_sfc_main$2), null, {
                    default: withCtx(() => [
                      createTextVNode("Password")
                    ]),
                    _: 1
                  }),
                  createVNode(unref(_sfc_main$5), null, {
                    default: withCtx(() => [
                      createVNode("div", { class: "relative" }, [
                        createVNode(unref(_sfc_main$3), mergeProps({
                          type: isPasswordVisible.value ? "text" : "password",
                          placeholder: "Enter Your password"
                        }, componentField), null, 16, ["type"]),
                        createVNode("button", {
                          onClick: withModifiers(togglePassword, ["prevent"]),
                          class: "absolute inset-y-0 right-0 pr-3 flex items-center text-sm text-gray-600"
                        }, [
                          isPasswordVisible.value ? (openBlock(), createBlock("div", { key: 0 }, [
                            createVNode(unref(EyeOff))
                          ])) : (openBlock(), createBlock("div", { key: 1 }, [
                            createVNode(unref(Eye))
                          ]))
                        ])
                      ])
                    ]),
                    _: 2
                  }, 1024),
                  createVNode(unref(_sfc_main$1$1))
                ]),
                _: 2
              }, 1024)
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(ssrRenderComponent(unref(Field), { name: "confirm" }, {
        default: withCtx(({ componentField }, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(ssrRenderComponent(unref(_sfc_main$4), null, {
              default: withCtx((_, _push3, _parent3, _scopeId2) => {
                if (_push3) {
                  _push3(ssrRenderComponent(unref(_sfc_main$2), null, {
                    default: withCtx((_2, _push4, _parent4, _scopeId3) => {
                      if (_push4) {
                        _push4(`Confirm Password`);
                      } else {
                        return [
                          createTextVNode("Confirm Password")
                        ];
                      }
                    }),
                    _: 2
                  }, _parent3, _scopeId2));
                  _push3(ssrRenderComponent(unref(_sfc_main$5), null, {
                    default: withCtx((_2, _push4, _parent4, _scopeId3) => {
                      if (_push4) {
                        _push4(`<div class="relative"${_scopeId3}>`);
                        _push4(ssrRenderComponent(unref(_sfc_main$3), mergeProps({
                          type: isConfirmPasswordVisible.value ? "text" : "password",
                          placeholder: "Enter Your password"
                        }, componentField), null, _parent4, _scopeId3));
                        _push4(`<button class="absolute inset-y-0 right-0 pr-3 flex items-center text-sm text-gray-600 cursor-pointer"${_scopeId3}>`);
                        if (isConfirmPasswordVisible.value) {
                          _push4(`<div${_scopeId3}>`);
                          _push4(ssrRenderComponent(unref(EyeOff), null, null, _parent4, _scopeId3));
                          _push4(`</div>`);
                        } else {
                          _push4(`<div${_scopeId3}>`);
                          _push4(ssrRenderComponent(unref(Eye), null, null, _parent4, _scopeId3));
                          _push4(`</div>`);
                        }
                        _push4(`</button></div>`);
                      } else {
                        return [
                          createVNode("div", { class: "relative" }, [
                            createVNode(unref(_sfc_main$3), mergeProps({
                              type: isConfirmPasswordVisible.value ? "text" : "password",
                              placeholder: "Enter Your password"
                            }, componentField), null, 16, ["type"]),
                            createVNode("button", {
                              onClick: withModifiers(toggleConfirmPassword, ["prevent"]),
                              class: "absolute inset-y-0 right-0 pr-3 flex items-center text-sm text-gray-600 cursor-pointer"
                            }, [
                              isConfirmPasswordVisible.value ? (openBlock(), createBlock("div", { key: 0 }, [
                                createVNode(unref(EyeOff))
                              ])) : (openBlock(), createBlock("div", { key: 1 }, [
                                createVNode(unref(Eye))
                              ]))
                            ])
                          ])
                        ];
                      }
                    }),
                    _: 2
                  }, _parent3, _scopeId2));
                  _push3(ssrRenderComponent(unref(_sfc_main$1$1), null, null, _parent3, _scopeId2));
                } else {
                  return [
                    createVNode(unref(_sfc_main$2), null, {
                      default: withCtx(() => [
                        createTextVNode("Confirm Password")
                      ]),
                      _: 1
                    }),
                    createVNode(unref(_sfc_main$5), null, {
                      default: withCtx(() => [
                        createVNode("div", { class: "relative" }, [
                          createVNode(unref(_sfc_main$3), mergeProps({
                            type: isConfirmPasswordVisible.value ? "text" : "password",
                            placeholder: "Enter Your password"
                          }, componentField), null, 16, ["type"]),
                          createVNode("button", {
                            onClick: withModifiers(toggleConfirmPassword, ["prevent"]),
                            class: "absolute inset-y-0 right-0 pr-3 flex items-center text-sm text-gray-600 cursor-pointer"
                          }, [
                            isConfirmPasswordVisible.value ? (openBlock(), createBlock("div", { key: 0 }, [
                              createVNode(unref(EyeOff))
                            ])) : (openBlock(), createBlock("div", { key: 1 }, [
                              createVNode(unref(Eye))
                            ]))
                          ])
                        ])
                      ]),
                      _: 2
                    }, 1024),
                    createVNode(unref(_sfc_main$1$1))
                  ];
                }
              }),
              _: 2
            }, _parent2, _scopeId));
          } else {
            return [
              createVNode(unref(_sfc_main$4), null, {
                default: withCtx(() => [
                  createVNode(unref(_sfc_main$2), null, {
                    default: withCtx(() => [
                      createTextVNode("Confirm Password")
                    ]),
                    _: 1
                  }),
                  createVNode(unref(_sfc_main$5), null, {
                    default: withCtx(() => [
                      createVNode("div", { class: "relative" }, [
                        createVNode(unref(_sfc_main$3), mergeProps({
                          type: isConfirmPasswordVisible.value ? "text" : "password",
                          placeholder: "Enter Your password"
                        }, componentField), null, 16, ["type"]),
                        createVNode("button", {
                          onClick: withModifiers(toggleConfirmPassword, ["prevent"]),
                          class: "absolute inset-y-0 right-0 pr-3 flex items-center text-sm text-gray-600 cursor-pointer"
                        }, [
                          isConfirmPasswordVisible.value ? (openBlock(), createBlock("div", { key: 0 }, [
                            createVNode(unref(EyeOff))
                          ])) : (openBlock(), createBlock("div", { key: 1 }, [
                            createVNode(unref(Eye))
                          ]))
                        ])
                      ])
                    ]),
                    _: 2
                  }, 1024),
                  createVNode(unref(_sfc_main$1$1))
                ]),
                _: 2
              }, 1024)
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(ssrRenderComponent(unref(_sfc_main$6), {
        type: "submit",
        class: "w-full",
        disabled: unref(isLoading)
      }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`${ssrInterpolate(unref(isLoading) ? "Signing Up" : "Sign Up ")}`);
          } else {
            return [
              createTextVNode(toDisplayString(unref(isLoading) ? "Signing Up" : "Sign Up "), 1)
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</form><p class="mt-4 text-sm text-right"> Already Have an account? `);
      _push(ssrRenderComponent(_component_NuxtLink, {
        to: "/login",
        class: "underline text-indigo-600"
      }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`Login Now `);
          } else {
            return [
              createTextVNode("Login Now ")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</p></div></div>`);
    };
  }
});
const _sfc_setup$1 = _sfc_main$1.setup;
_sfc_main$1.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("features/auth/components/SignUpForm.vue");
  return _sfc_setup$1 ? _sfc_setup$1(props, ctx) : void 0;
};
const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "signup",
  __ssrInlineRender: true,
  setup(__props) {
    useHead({
      title: "Invoicfiy | Sign Up"
    });
    return (_ctx, _push, _parent, _attrs) => {
      _push(ssrRenderComponent(_sfc_main$1, _attrs, null, _parent));
    };
  }
});
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("pages/signup.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};

export { _sfc_main as default };
//# sourceMappingURL=signup-D03xVxSZ.mjs.map
