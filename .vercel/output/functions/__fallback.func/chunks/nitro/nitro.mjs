import process from 'node:process';globalThis._importMeta_=globalThis._importMeta_||{url:"file:///_entry.js",env:process.env};import * as node_os from 'node:os';
import * as node_tty from 'node:tty';
import * as node_fs from 'node:fs';
import { promises as promises$1, existsSync } from 'node:fs';
import * as node_path from 'node:path';
import { resolve as resolve$1, dirname, join } from 'node:path';
import * as nodeCrypto from 'node:crypto';
import { createHash } from 'node:crypto';
import * as node_child_process from 'node:child_process';
import * as promises from 'node:fs/promises';
import * as node_util from 'node:util';
import * as node_process from 'node:process';
import * as node_async_hooks from 'node:async_hooks';
import * as node_events from 'node:events';
import { EventEmitter } from 'node:events';
import * as path from 'path';
import * as fs$1 from 'fs';
import http from 'node:http';
import https from 'node:https';
import { Buffer as Buffer$1 } from 'node:buffer';
import * as jose from 'jose';
import { fileURLToPath } from 'node:url';
import { ipxFSStorage, ipxHttpStorage, createIPX, createIPXH3Handler } from 'ipx';

const suspectProtoRx = /"(?:_|\\u0{2}5[Ff]){2}(?:p|\\u0{2}70)(?:r|\\u0{2}72)(?:o|\\u0{2}6[Ff])(?:t|\\u0{2}74)(?:o|\\u0{2}6[Ff])(?:_|\\u0{2}5[Ff]){2}"\s*:/;
const suspectConstructorRx = /"(?:c|\\u0063)(?:o|\\u006[Ff])(?:n|\\u006[Ee])(?:s|\\u0073)(?:t|\\u0074)(?:r|\\u0072)(?:u|\\u0075)(?:c|\\u0063)(?:t|\\u0074)(?:o|\\u006[Ff])(?:r|\\u0072)"\s*:/;
const JsonSigRx = /^\s*["[{]|^\s*-?\d{1,16}(\.\d{1,17})?([Ee][+-]?\d+)?\s*$/;
function jsonParseTransform(key, value) {
  if (key === "__proto__" || key === "constructor" && value && typeof value === "object" && "prototype" in value) {
    warnKeyDropped(key);
    return;
  }
  return value;
}
function warnKeyDropped(key) {
  console.warn(`[destr] Dropping "${key}" key to prevent prototype pollution.`);
}
function destr(value, options = {}) {
  if (typeof value !== "string") {
    return value;
  }
  if (value[0] === '"' && value[value.length - 1] === '"' && value.indexOf("\\") === -1) {
    return value.slice(1, -1);
  }
  const _value = value.trim();
  if (_value.length <= 9) {
    switch (_value.toLowerCase()) {
      case "true": {
        return true;
      }
      case "false": {
        return false;
      }
      case "undefined": {
        return void 0;
      }
      case "null": {
        return null;
      }
      case "nan": {
        return Number.NaN;
      }
      case "infinity": {
        return Number.POSITIVE_INFINITY;
      }
      case "-infinity": {
        return Number.NEGATIVE_INFINITY;
      }
    }
  }
  if (!JsonSigRx.test(value)) {
    if (options.strict) {
      throw new SyntaxError("[destr] Invalid JSON");
    }
    return value;
  }
  try {
    if (suspectProtoRx.test(value) || suspectConstructorRx.test(value)) {
      if (options.strict) {
        throw new Error("[destr] Possible prototype pollution");
      }
      return JSON.parse(value, jsonParseTransform);
    }
    return JSON.parse(value);
  } catch (error) {
    if (options.strict) {
      throw error;
    }
    return value;
  }
}

const HASH_RE = /#/g;
const AMPERSAND_RE = /&/g;
const SLASH_RE = /\//g;
const EQUAL_RE = /=/g;
const IM_RE = /\?/g;
const PLUS_RE = /\+/g;
const ENC_CARET_RE = /%5e/gi;
const ENC_BACKTICK_RE = /%60/gi;
const ENC_PIPE_RE = /%7c/gi;
const ENC_SPACE_RE = /%20/gi;
const ENC_ENC_SLASH_RE = /%252f/gi;
function encode(text) {
  return encodeURI("" + text).replace(ENC_PIPE_RE, "|");
}
function encodeQueryValue(input) {
  return encode(typeof input === "string" ? input : JSON.stringify(input)).replace(PLUS_RE, "%2B").replace(ENC_SPACE_RE, "+").replace(HASH_RE, "%23").replace(AMPERSAND_RE, "%26").replace(ENC_BACKTICK_RE, "`").replace(ENC_CARET_RE, "^").replace(SLASH_RE, "%2F");
}
function encodeQueryKey(text) {
  return encodeQueryValue(text).replace(EQUAL_RE, "%3D");
}
function encodePath(text) {
  return encode(text).replace(HASH_RE, "%23").replace(IM_RE, "%3F").replace(ENC_ENC_SLASH_RE, "%2F").replace(AMPERSAND_RE, "%26").replace(PLUS_RE, "%2B");
}
function encodeParam(text) {
  return encodePath(text).replace(SLASH_RE, "%2F");
}
function decode$1(text = "") {
  try {
    return decodeURIComponent("" + text);
  } catch {
    return "" + text;
  }
}
function decodeQueryKey(text) {
  return decode$1(text.replace(PLUS_RE, " "));
}
function decodeQueryValue(text) {
  return decode$1(text.replace(PLUS_RE, " "));
}

function parseQuery(parametersString = "") {
  const object = /* @__PURE__ */ Object.create(null);
  if (parametersString[0] === "?") {
    parametersString = parametersString.slice(1);
  }
  for (const parameter of parametersString.split("&")) {
    const s = parameter.match(/([^=]+)=?(.*)/) || [];
    if (s.length < 2) {
      continue;
    }
    const key = decodeQueryKey(s[1]);
    if (key === "__proto__" || key === "constructor") {
      continue;
    }
    const value = decodeQueryValue(s[2] || "");
    if (object[key] === void 0) {
      object[key] = value;
    } else if (Array.isArray(object[key])) {
      object[key].push(value);
    } else {
      object[key] = [object[key], value];
    }
  }
  return object;
}
function encodeQueryItem(key, value) {
  if (typeof value === "number" || typeof value === "boolean") {
    value = String(value);
  }
  if (!value) {
    return encodeQueryKey(key);
  }
  if (Array.isArray(value)) {
    return value.map(
      (_value) => `${encodeQueryKey(key)}=${encodeQueryValue(_value)}`
    ).join("&");
  }
  return `${encodeQueryKey(key)}=${encodeQueryValue(value)}`;
}
function stringifyQuery(query) {
  return Object.keys(query).filter((k) => query[k] !== void 0).map((k) => encodeQueryItem(k, query[k])).filter(Boolean).join("&");
}

const PROTOCOL_STRICT_REGEX = /^[\s\w\0+.-]{2,}:([/\\]{1,2})/;
const PROTOCOL_REGEX = /^[\s\w\0+.-]{2,}:([/\\]{2})?/;
const PROTOCOL_RELATIVE_REGEX = /^([/\\]\s*){2,}[^/\\]/;
const PROTOCOL_SCRIPT_RE = /^[\s\0]*(blob|data|javascript|vbscript):$/i;
const TRAILING_SLASH_RE = /\/$|\/\?|\/#/;
const JOIN_LEADING_SLASH_RE = /^\.?\//;
function hasProtocol(inputString, opts = {}) {
  if (typeof opts === "boolean") {
    opts = { acceptRelative: opts };
  }
  if (opts.strict) {
    return PROTOCOL_STRICT_REGEX.test(inputString);
  }
  return PROTOCOL_REGEX.test(inputString) || (opts.acceptRelative ? PROTOCOL_RELATIVE_REGEX.test(inputString) : false);
}
function isScriptProtocol(protocol) {
  return !!protocol && PROTOCOL_SCRIPT_RE.test(protocol);
}
function hasTrailingSlash(input = "", respectQueryAndFragment) {
  if (!respectQueryAndFragment) {
    return input.endsWith("/");
  }
  return TRAILING_SLASH_RE.test(input);
}
function withoutTrailingSlash(input = "", respectQueryAndFragment) {
  if (!respectQueryAndFragment) {
    return (hasTrailingSlash(input) ? input.slice(0, -1) : input) || "/";
  }
  if (!hasTrailingSlash(input, true)) {
    return input || "/";
  }
  let path = input;
  let fragment = "";
  const fragmentIndex = input.indexOf("#");
  if (fragmentIndex !== -1) {
    path = input.slice(0, fragmentIndex);
    fragment = input.slice(fragmentIndex);
  }
  const [s0, ...s] = path.split("?");
  const cleanPath = s0.endsWith("/") ? s0.slice(0, -1) : s0;
  return (cleanPath || "/") + (s.length > 0 ? `?${s.join("?")}` : "") + fragment;
}
function withTrailingSlash(input = "", respectQueryAndFragment) {
  if (!respectQueryAndFragment) {
    return input.endsWith("/") ? input : input + "/";
  }
  if (hasTrailingSlash(input, true)) {
    return input || "/";
  }
  let path = input;
  let fragment = "";
  const fragmentIndex = input.indexOf("#");
  if (fragmentIndex !== -1) {
    path = input.slice(0, fragmentIndex);
    fragment = input.slice(fragmentIndex);
    if (!path) {
      return fragment;
    }
  }
  const [s0, ...s] = path.split("?");
  return s0 + "/" + (s.length > 0 ? `?${s.join("?")}` : "") + fragment;
}
function hasLeadingSlash(input = "") {
  return input.startsWith("/");
}
function withLeadingSlash(input = "") {
  return hasLeadingSlash(input) ? input : "/" + input;
}
function withBase(input, base) {
  if (isEmptyURL(base) || hasProtocol(input)) {
    return input;
  }
  const _base = withoutTrailingSlash(base);
  if (input.startsWith(_base)) {
    return input;
  }
  return joinURL(_base, input);
}
function withoutBase(input, base) {
  if (isEmptyURL(base)) {
    return input;
  }
  const _base = withoutTrailingSlash(base);
  if (!input.startsWith(_base)) {
    return input;
  }
  const trimmed = input.slice(_base.length);
  return trimmed[0] === "/" ? trimmed : "/" + trimmed;
}
function withQuery(input, query) {
  const parsed = parseURL(input);
  const mergedQuery = { ...parseQuery(parsed.search), ...query };
  parsed.search = stringifyQuery(mergedQuery);
  return stringifyParsedURL(parsed);
}
function getQuery$1(input) {
  return parseQuery(parseURL(input).search);
}
function isEmptyURL(url) {
  return !url || url === "/";
}
function isNonEmptyURL(url) {
  return url && url !== "/";
}
function joinURL(base, ...input) {
  let url = base || "";
  for (const segment of input.filter((url2) => isNonEmptyURL(url2))) {
    if (url) {
      const _segment = segment.replace(JOIN_LEADING_SLASH_RE, "");
      url = withTrailingSlash(url) + _segment;
    } else {
      url = segment;
    }
  }
  return url;
}
function joinRelativeURL(..._input) {
  const JOIN_SEGMENT_SPLIT_RE = /\/(?!\/)/;
  const input = _input.filter(Boolean);
  const segments = [];
  let segmentsDepth = 0;
  for (const i of input) {
    if (!i || i === "/") {
      continue;
    }
    for (const [sindex, s] of i.split(JOIN_SEGMENT_SPLIT_RE).entries()) {
      if (!s || s === ".") {
        continue;
      }
      if (s === "..") {
        if (segments.length === 1 && hasProtocol(segments[0])) {
          continue;
        }
        segments.pop();
        segmentsDepth--;
        continue;
      }
      if (sindex === 1 && segments[segments.length - 1]?.endsWith(":/")) {
        segments[segments.length - 1] += "/" + s;
        continue;
      }
      segments.push(s);
      segmentsDepth++;
    }
  }
  let url = segments.join("/");
  if (segmentsDepth >= 0) {
    if (input[0]?.startsWith("/") && !url.startsWith("/")) {
      url = "/" + url;
    } else if (input[0]?.startsWith("./") && !url.startsWith("./")) {
      url = "./" + url;
    }
  } else {
    url = "../".repeat(-1 * segmentsDepth) + url;
  }
  if (input[input.length - 1]?.endsWith("/") && !url.endsWith("/")) {
    url += "/";
  }
  return url;
}

const protocolRelative = Symbol.for("ufo:protocolRelative");
function parseURL(input = "", defaultProto) {
  const _specialProtoMatch = input.match(
    /^[\s\0]*(blob:|data:|javascript:|vbscript:)(.*)/i
  );
  if (_specialProtoMatch) {
    const [, _proto, _pathname = ""] = _specialProtoMatch;
    return {
      protocol: _proto.toLowerCase(),
      pathname: _pathname,
      href: _proto + _pathname,
      auth: "",
      host: "",
      search: "",
      hash: ""
    };
  }
  if (!hasProtocol(input, { acceptRelative: true })) {
    return parsePath(input);
  }
  const [, protocol = "", auth, hostAndPath = ""] = input.replace(/\\/g, "/").match(/^[\s\0]*([\w+.-]{2,}:)?\/\/([^/@]+@)?(.*)/) || [];
  let [, host = "", path = ""] = hostAndPath.match(/([^#/?]*)(.*)?/) || [];
  if (protocol === "file:") {
    path = path.replace(/\/(?=[A-Za-z]:)/, "");
  }
  const { pathname, search, hash } = parsePath(path);
  return {
    protocol: protocol.toLowerCase(),
    auth: auth ? auth.slice(0, Math.max(0, auth.length - 1)) : "",
    host,
    pathname,
    search,
    hash,
    [protocolRelative]: !protocol
  };
}
function parsePath(input = "") {
  const [pathname = "", search = "", hash = ""] = (input.match(/([^#?]*)(\?[^#]*)?(#.*)?/) || []).splice(1);
  return {
    pathname,
    search,
    hash
  };
}
function stringifyParsedURL(parsed) {
  const pathname = parsed.pathname || "";
  const search = parsed.search ? (parsed.search.startsWith("?") ? "" : "?") + parsed.search : "";
  const hash = parsed.hash || "";
  const auth = parsed.auth ? parsed.auth + "@" : "";
  const host = parsed.host || "";
  const proto = parsed.protocol || parsed[protocolRelative] ? (parsed.protocol || "") + "//" : "";
  return proto + auth + host + pathname + search + hash;
}

function parse(str, options) {
  if (typeof str !== "string") {
    throw new TypeError("argument str must be a string");
  }
  const obj = {};
  const opt = {};
  const dec = opt.decode || decode;
  let index = 0;
  while (index < str.length) {
    const eqIdx = str.indexOf("=", index);
    if (eqIdx === -1) {
      break;
    }
    let endIdx = str.indexOf(";", index);
    if (endIdx === -1) {
      endIdx = str.length;
    } else if (endIdx < eqIdx) {
      index = str.lastIndexOf(";", eqIdx - 1) + 1;
      continue;
    }
    const key = str.slice(index, eqIdx).trim();
    if (opt?.filter && !opt?.filter(key)) {
      index = endIdx + 1;
      continue;
    }
    if (void 0 === obj[key]) {
      let val = str.slice(eqIdx + 1, endIdx).trim();
      if (val.codePointAt(0) === 34) {
        val = val.slice(1, -1);
      }
      obj[key] = tryDecode(val, dec);
    }
    index = endIdx + 1;
  }
  return obj;
}
function decode(str) {
  return str.includes("%") ? decodeURIComponent(str) : str;
}
function tryDecode(str, decode2) {
  try {
    return decode2(str);
  } catch {
    return str;
  }
}

const fieldContentRegExp = /^[\u0009\u0020-\u007E\u0080-\u00FF]+$/;
function serialize$1(name, value, options) {
  const opt = options || {};
  const enc = opt.encode || encodeURIComponent;
  if (typeof enc !== "function") {
    throw new TypeError("option encode is invalid");
  }
  if (!fieldContentRegExp.test(name)) {
    throw new TypeError("argument name is invalid");
  }
  const encodedValue = enc(value);
  if (encodedValue && !fieldContentRegExp.test(encodedValue)) {
    throw new TypeError("argument val is invalid");
  }
  let str = name + "=" + encodedValue;
  if (void 0 !== opt.maxAge && opt.maxAge !== null) {
    const maxAge = opt.maxAge - 0;
    if (Number.isNaN(maxAge) || !Number.isFinite(maxAge)) {
      throw new TypeError("option maxAge is invalid");
    }
    str += "; Max-Age=" + Math.floor(maxAge);
  }
  if (opt.domain) {
    if (!fieldContentRegExp.test(opt.domain)) {
      throw new TypeError("option domain is invalid");
    }
    str += "; Domain=" + opt.domain;
  }
  if (opt.path) {
    if (!fieldContentRegExp.test(opt.path)) {
      throw new TypeError("option path is invalid");
    }
    str += "; Path=" + opt.path;
  }
  if (opt.expires) {
    if (!isDate(opt.expires) || Number.isNaN(opt.expires.valueOf())) {
      throw new TypeError("option expires is invalid");
    }
    str += "; Expires=" + opt.expires.toUTCString();
  }
  if (opt.httpOnly) {
    str += "; HttpOnly";
  }
  if (opt.secure) {
    str += "; Secure";
  }
  if (opt.priority) {
    const priority = typeof opt.priority === "string" ? opt.priority.toLowerCase() : opt.priority;
    switch (priority) {
      case "low": {
        str += "; Priority=Low";
        break;
      }
      case "medium": {
        str += "; Priority=Medium";
        break;
      }
      case "high": {
        str += "; Priority=High";
        break;
      }
      default: {
        throw new TypeError("option priority is invalid");
      }
    }
  }
  if (opt.sameSite) {
    const sameSite = typeof opt.sameSite === "string" ? opt.sameSite.toLowerCase() : opt.sameSite;
    switch (sameSite) {
      case true: {
        str += "; SameSite=Strict";
        break;
      }
      case "lax": {
        str += "; SameSite=Lax";
        break;
      }
      case "strict": {
        str += "; SameSite=Strict";
        break;
      }
      case "none": {
        str += "; SameSite=None";
        break;
      }
      default: {
        throw new TypeError("option sameSite is invalid");
      }
    }
  }
  if (opt.partitioned) {
    str += "; Partitioned";
  }
  return str;
}
function isDate(val) {
  return Object.prototype.toString.call(val) === "[object Date]" || val instanceof Date;
}

function parseSetCookie(setCookieValue, options) {
  const parts = (setCookieValue || "").split(";").filter((str) => typeof str === "string" && !!str.trim());
  const nameValuePairStr = parts.shift() || "";
  const parsed = _parseNameValuePair(nameValuePairStr);
  const name = parsed.name;
  let value = parsed.value;
  try {
    value = options?.decode === false ? value : (options?.decode || decodeURIComponent)(value);
  } catch {
  }
  const cookie = {
    name,
    value
  };
  for (const part of parts) {
    const sides = part.split("=");
    const partKey = (sides.shift() || "").trimStart().toLowerCase();
    const partValue = sides.join("=");
    switch (partKey) {
      case "expires": {
        cookie.expires = new Date(partValue);
        break;
      }
      case "max-age": {
        cookie.maxAge = Number.parseInt(partValue, 10);
        break;
      }
      case "secure": {
        cookie.secure = true;
        break;
      }
      case "httponly": {
        cookie.httpOnly = true;
        break;
      }
      case "samesite": {
        cookie.sameSite = partValue;
        break;
      }
      default: {
        cookie[partKey] = partValue;
      }
    }
  }
  return cookie;
}
function _parseNameValuePair(nameValuePairStr) {
  let name = "";
  let value = "";
  const nameValueArr = nameValuePairStr.split("=");
  if (nameValueArr.length > 1) {
    name = nameValueArr.shift();
    value = nameValueArr.join("=");
  } else {
    value = nameValuePairStr;
  }
  return { name, value };
}

const NODE_TYPES = {
  NORMAL: 0,
  WILDCARD: 1,
  PLACEHOLDER: 2
};

function createRouter$1(options = {}) {
  const ctx = {
    options,
    rootNode: createRadixNode(),
    staticRoutesMap: {}
  };
  const normalizeTrailingSlash = (p) => options.strictTrailingSlash ? p : p.replace(/\/$/, "") || "/";
  if (options.routes) {
    for (const path in options.routes) {
      insert(ctx, normalizeTrailingSlash(path), options.routes[path]);
    }
  }
  return {
    ctx,
    lookup: (path) => lookup(ctx, normalizeTrailingSlash(path)),
    insert: (path, data) => insert(ctx, normalizeTrailingSlash(path), data),
    remove: (path) => remove(ctx, normalizeTrailingSlash(path))
  };
}
function lookup(ctx, path) {
  const staticPathNode = ctx.staticRoutesMap[path];
  if (staticPathNode) {
    return staticPathNode.data;
  }
  const sections = path.split("/");
  const params = {};
  let paramsFound = false;
  let wildcardNode = null;
  let node = ctx.rootNode;
  let wildCardParam = null;
  for (let i = 0; i < sections.length; i++) {
    const section = sections[i];
    if (node.wildcardChildNode !== null) {
      wildcardNode = node.wildcardChildNode;
      wildCardParam = sections.slice(i).join("/");
    }
    const nextNode = node.children.get(section);
    if (nextNode === void 0) {
      if (node && node.placeholderChildren.length > 1) {
        const remaining = sections.length - i;
        node = node.placeholderChildren.find((c) => c.maxDepth === remaining) || null;
      } else {
        node = node.placeholderChildren[0] || null;
      }
      if (!node) {
        break;
      }
      if (node.paramName) {
        params[node.paramName] = section;
      }
      paramsFound = true;
    } else {
      node = nextNode;
    }
  }
  if ((node === null || node.data === null) && wildcardNode !== null) {
    node = wildcardNode;
    params[node.paramName || "_"] = wildCardParam;
    paramsFound = true;
  }
  if (!node) {
    return null;
  }
  if (paramsFound) {
    return {
      ...node.data,
      params: paramsFound ? params : void 0
    };
  }
  return node.data;
}
function insert(ctx, path, data) {
  let isStaticRoute = true;
  const sections = path.split("/");
  let node = ctx.rootNode;
  let _unnamedPlaceholderCtr = 0;
  const matchedNodes = [node];
  for (const section of sections) {
    let childNode;
    if (childNode = node.children.get(section)) {
      node = childNode;
    } else {
      const type = getNodeType(section);
      childNode = createRadixNode({ type, parent: node });
      node.children.set(section, childNode);
      if (type === NODE_TYPES.PLACEHOLDER) {
        childNode.paramName = section === "*" ? `_${_unnamedPlaceholderCtr++}` : section.slice(1);
        node.placeholderChildren.push(childNode);
        isStaticRoute = false;
      } else if (type === NODE_TYPES.WILDCARD) {
        node.wildcardChildNode = childNode;
        childNode.paramName = section.slice(
          3
          /* "**:" */
        ) || "_";
        isStaticRoute = false;
      }
      matchedNodes.push(childNode);
      node = childNode;
    }
  }
  for (const [depth, node2] of matchedNodes.entries()) {
    node2.maxDepth = Math.max(matchedNodes.length - depth, node2.maxDepth || 0);
  }
  node.data = data;
  if (isStaticRoute === true) {
    ctx.staticRoutesMap[path] = node;
  }
  return node;
}
function remove(ctx, path) {
  let success = false;
  const sections = path.split("/");
  let node = ctx.rootNode;
  for (const section of sections) {
    node = node.children.get(section);
    if (!node) {
      return success;
    }
  }
  if (node.data) {
    const lastSection = sections.at(-1) || "";
    node.data = null;
    if (Object.keys(node.children).length === 0 && node.parent) {
      node.parent.children.delete(lastSection);
      node.parent.wildcardChildNode = null;
      node.parent.placeholderChildren = [];
    }
    success = true;
  }
  return success;
}
function createRadixNode(options = {}) {
  return {
    type: options.type || NODE_TYPES.NORMAL,
    maxDepth: 0,
    parent: options.parent || null,
    children: /* @__PURE__ */ new Map(),
    data: options.data || null,
    paramName: options.paramName || null,
    wildcardChildNode: null,
    placeholderChildren: []
  };
}
function getNodeType(str) {
  if (str.startsWith("**")) {
    return NODE_TYPES.WILDCARD;
  }
  if (str[0] === ":" || str === "*") {
    return NODE_TYPES.PLACEHOLDER;
  }
  return NODE_TYPES.NORMAL;
}

function toRouteMatcher(router) {
  const table = _routerNodeToTable("", router.ctx.rootNode);
  return _createMatcher(table, router.ctx.options.strictTrailingSlash);
}
function _createMatcher(table, strictTrailingSlash) {
  return {
    ctx: { table },
    matchAll: (path) => _matchRoutes(path, table, strictTrailingSlash)
  };
}
function _createRouteTable() {
  return {
    static: /* @__PURE__ */ new Map(),
    wildcard: /* @__PURE__ */ new Map(),
    dynamic: /* @__PURE__ */ new Map()
  };
}
function _matchRoutes(path, table, strictTrailingSlash) {
  if (strictTrailingSlash !== true && path.endsWith("/")) {
    path = path.slice(0, -1) || "/";
  }
  const matches = [];
  for (const [key, value] of _sortRoutesMap(table.wildcard)) {
    if (path === key || path.startsWith(key + "/")) {
      matches.push(value);
    }
  }
  for (const [key, value] of _sortRoutesMap(table.dynamic)) {
    if (path.startsWith(key + "/")) {
      const subPath = "/" + path.slice(key.length).split("/").splice(2).join("/");
      matches.push(..._matchRoutes(subPath, value));
    }
  }
  const staticMatch = table.static.get(path);
  if (staticMatch) {
    matches.push(staticMatch);
  }
  return matches.filter(Boolean);
}
function _sortRoutesMap(m) {
  return [...m.entries()].sort((a, b) => a[0].length - b[0].length);
}
function _routerNodeToTable(initialPath, initialNode) {
  const table = _createRouteTable();
  function _addNode(path, node) {
    if (path) {
      if (node.type === NODE_TYPES.NORMAL && !(path.includes("*") || path.includes(":"))) {
        if (node.data) {
          table.static.set(path, node.data);
        }
      } else if (node.type === NODE_TYPES.WILDCARD) {
        table.wildcard.set(path.replace("/**", ""), node.data);
      } else if (node.type === NODE_TYPES.PLACEHOLDER) {
        const subTable = _routerNodeToTable("", node);
        if (node.data) {
          subTable.static.set("/", node.data);
        }
        table.dynamic.set(path.replace(/\/\*|\/:\w+/, ""), subTable);
        return;
      }
    }
    for (const [childPath, child] of node.children.entries()) {
      _addNode(`${path}/${childPath}`.replace("//", "/"), child);
    }
  }
  _addNode(initialPath, initialNode);
  return table;
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype && Object.getPrototypeOf(prototype) !== null) {
    return false;
  }
  if (Symbol.iterator in value) {
    return false;
  }
  if (Symbol.toStringTag in value) {
    return Object.prototype.toString.call(value) === "[object Module]";
  }
  return true;
}

function _defu(baseObject, defaults, namespace = ".", merger) {
  if (!isPlainObject(defaults)) {
    return _defu(baseObject, {}, namespace, merger);
  }
  const object = Object.assign({}, defaults);
  for (const key in baseObject) {
    if (key === "__proto__" || key === "constructor") {
      continue;
    }
    const value = baseObject[key];
    if (value === null || value === void 0) {
      continue;
    }
    if (merger && merger(object, key, value, namespace)) {
      continue;
    }
    if (Array.isArray(value) && Array.isArray(object[key])) {
      object[key] = [...value, ...object[key]];
    } else if (isPlainObject(value) && isPlainObject(object[key])) {
      object[key] = _defu(
        value,
        object[key],
        (namespace ? `${namespace}.` : "") + key.toString(),
        merger
      );
    } else {
      object[key] = value;
    }
  }
  return object;
}
function createDefu(merger) {
  return (...arguments_) => (
    // eslint-disable-next-line unicorn/no-array-reduce
    arguments_.reduce((p, c) => _defu(p, c, "", merger), {})
  );
}
const defu = createDefu();
const defuFn = createDefu((object, key, currentValue) => {
  if (object[key] !== void 0 && typeof currentValue === "function") {
    object[key] = currentValue(object[key]);
    return true;
  }
});

function o(n){throw new Error(`${n} is not implemented yet!`)}let i$1 = class i extends EventEmitter{__unenv__={};readableEncoding=null;readableEnded=true;readableFlowing=false;readableHighWaterMark=0;readableLength=0;readableObjectMode=false;readableAborted=false;readableDidRead=false;closed=false;errored=null;readable=false;destroyed=false;static from(e,t){return new i(t)}constructor(e){super();}_read(e){}read(e){}setEncoding(e){return this}pause(){return this}resume(){return this}isPaused(){return  true}unpipe(e){return this}unshift(e,t){}wrap(e){return this}push(e,t){return  false}_destroy(e,t){this.removeAllListeners();}destroy(e){return this.destroyed=true,this._destroy(e),this}pipe(e,t){return {}}compose(e,t){throw new Error("Method not implemented.")}[Symbol.asyncDispose](){return this.destroy(),Promise.resolve()}async*[Symbol.asyncIterator](){throw o("Readable.asyncIterator")}iterator(e){throw o("Readable.iterator")}map(e,t){throw o("Readable.map")}filter(e,t){throw o("Readable.filter")}forEach(e,t){throw o("Readable.forEach")}reduce(e,t,r){throw o("Readable.reduce")}find(e,t){throw o("Readable.find")}findIndex(e,t){throw o("Readable.findIndex")}some(e,t){throw o("Readable.some")}toArray(e){throw o("Readable.toArray")}every(e,t){throw o("Readable.every")}flatMap(e,t){throw o("Readable.flatMap")}drop(e,t){throw o("Readable.drop")}take(e,t){throw o("Readable.take")}asIndexedPairs(e){throw o("Readable.asIndexedPairs")}};let l$1 = class l extends EventEmitter{__unenv__={};writable=true;writableEnded=false;writableFinished=false;writableHighWaterMark=0;writableLength=0;writableObjectMode=false;writableCorked=0;closed=false;errored=null;writableNeedDrain=false;writableAborted=false;destroyed=false;_data;_encoding="utf8";constructor(e){super();}pipe(e,t){return {}}_write(e,t,r){if(this.writableEnded){r&&r();return}if(this._data===void 0)this._data=e;else {const s=typeof this._data=="string"?Buffer$1.from(this._data,this._encoding||t||"utf8"):this._data,a=typeof e=="string"?Buffer$1.from(e,t||this._encoding||"utf8"):e;this._data=Buffer$1.concat([s,a]);}this._encoding=t,r&&r();}_writev(e,t){}_destroy(e,t){}_final(e){}write(e,t,r){const s=typeof t=="string"?this._encoding:"utf8",a=typeof t=="function"?t:typeof r=="function"?r:void 0;return this._write(e,s,a),true}setDefaultEncoding(e){return this}end(e,t,r){const s=typeof e=="function"?e:typeof t=="function"?t:typeof r=="function"?r:void 0;if(this.writableEnded)return s&&s(),this;const a=e===s?void 0:e;if(a){const u=t===s?void 0:t;this.write(a,u,s);}return this.writableEnded=true,this.writableFinished=true,this.emit("close"),this.emit("finish"),this}cork(){}uncork(){}destroy(e){return this.destroyed=true,delete this._data,this.removeAllListeners(),this}compose(e,t){throw new Error("Method not implemented.")}[Symbol.asyncDispose](){return Promise.resolve()}};const c=class{allowHalfOpen=true;_destroy;constructor(e=new i$1,t=new l$1){Object.assign(this,e),Object.assign(this,t),this._destroy=m$1(e._destroy,t._destroy);}};function _(){return Object.assign(c.prototype,i$1.prototype),Object.assign(c.prototype,l$1.prototype),c}function m$1(...n){return function(...e){for(const t of n)t(...e);}}const g=_();let A$1 = class A extends g{__unenv__={};bufferSize=0;bytesRead=0;bytesWritten=0;connecting=false;destroyed=false;pending=false;localAddress="";localPort=0;remoteAddress="";remoteFamily="";remotePort=0;autoSelectFamilyAttemptedAddresses=[];readyState="readOnly";constructor(e){super();}write(e,t,r){return  false}connect(e,t,r){return this}end(e,t,r){return this}setEncoding(e){return this}pause(){return this}resume(){return this}setTimeout(e,t){return this}setNoDelay(e){return this}setKeepAlive(e,t){return this}address(){return {}}unref(){return this}ref(){return this}destroySoon(){this.destroy();}resetAndDestroy(){const e=new Error("ERR_SOCKET_CLOSED");return e.code="ERR_SOCKET_CLOSED",this.destroy(e),this}};let y$1 = class y extends i$1{aborted=false;httpVersion="1.1";httpVersionMajor=1;httpVersionMinor=1;complete=true;connection;socket;headers={};trailers={};method="GET";url="/";statusCode=200;statusMessage="";closed=false;errored=null;readable=false;constructor(e){super(),this.socket=this.connection=e||new A$1;}get rawHeaders(){const e=this.headers,t=[];for(const r in e)if(Array.isArray(e[r]))for(const s of e[r])t.push(r,s);else t.push(r,e[r]);return t}get rawTrailers(){return []}setTimeout(e,t){return this}get headersDistinct(){return p(this.headers)}get trailersDistinct(){return p(this.trailers)}};function p(n){const e={};for(const[t,r]of Object.entries(n))t&&(e[t]=(Array.isArray(r)?r:[r]).filter(Boolean));return e}let w$1 = class w extends l$1{statusCode=200;statusMessage="";upgrading=false;chunkedEncoding=false;shouldKeepAlive=false;useChunkedEncodingByDefault=false;sendDate=false;finished=false;headersSent=false;strictContentLength=false;connection=null;socket=null;req;_headers={};constructor(e){super(),this.req=e;}assignSocket(e){e._httpMessage=this,this.socket=e,this.connection=e,this.emit("socket",e),this._flush();}_flush(){this.flushHeaders();}detachSocket(e){}writeContinue(e){}writeHead(e,t,r){e&&(this.statusCode=e),typeof t=="string"&&(this.statusMessage=t,t=void 0);const s=r||t;if(s&&!Array.isArray(s))for(const a in s)this.setHeader(a,s[a]);return this.headersSent=true,this}writeProcessing(){}setTimeout(e,t){return this}appendHeader(e,t){e=e.toLowerCase();const r=this._headers[e],s=[...Array.isArray(r)?r:[r],...Array.isArray(t)?t:[t]].filter(Boolean);return this._headers[e]=s.length>1?s:s[0],this}setHeader(e,t){return this._headers[e.toLowerCase()]=t,this}setHeaders(e){for(const[t,r]of Object.entries(e))this.setHeader(t,r);return this}getHeader(e){return this._headers[e.toLowerCase()]}getHeaders(){return this._headers}getHeaderNames(){return Object.keys(this._headers)}hasHeader(e){return e.toLowerCase()in this._headers}removeHeader(e){delete this._headers[e.toLowerCase()];}addTrailers(e){}flushHeaders(){}writeEarlyHints(e,t){typeof t=="function"&&t();}};const E$1=(()=>{const n=function(){};return n.prototype=Object.create(null),n})();function R$1(n={}){const e=new E$1,t=Array.isArray(n)||H(n)?n:Object.entries(n);for(const[r,s]of t)if(s){if(e[r]===void 0){e[r]=s;continue}e[r]=[...Array.isArray(e[r])?e[r]:[e[r]],...Array.isArray(s)?s:[s]];}return e}function H(n){return typeof n?.entries=="function"}function v$1(n={}){if(n instanceof Headers)return n;const e=new Headers;for(const[t,r]of Object.entries(n))if(r!==void 0){if(Array.isArray(r)){for(const s of r)e.append(t,String(s));continue}e.set(t,String(r));}return e}const S=new Set([101,204,205,304]);async function b(n,e){const t=new y$1,r=new w$1(t);t.url=e.url?.toString()||"/";let s;if(!t.url.startsWith("/")){const d=new URL(t.url);s=d.host,t.url=d.pathname+d.search+d.hash;}t.method=e.method||"GET",t.headers=R$1(e.headers||{}),t.headers.host||(t.headers.host=e.host||s||"localhost"),t.connection.encrypted=t.connection.encrypted||e.protocol==="https",t.body=e.body||null,t.__unenv__=e.context,await n(t,r);let a=r._data;(S.has(r.statusCode)||t.method.toUpperCase()==="HEAD")&&(a=null,delete r._headers["content-length"]);const u={status:r.statusCode,statusText:r.statusMessage,headers:r._headers,body:a};return t.destroy(),r.destroy(),u}async function C$1(n,e,t={}){try{const r=await b(n,{url:e,...t});return new Response(r.body,{status:r.status,statusText:r.statusText,headers:v$1(r.headers)})}catch(r){return new Response(r.toString(),{status:Number.parseInt(r.statusCode||r.code)||500,statusText:r.statusText})}}

function useBase(base, handler) {
  base = withoutTrailingSlash(base);
  if (!base || base === "/") {
    return handler;
  }
  return eventHandler(async (event) => {
    event.node.req.originalUrl = event.node.req.originalUrl || event.node.req.url || "/";
    const _path = event._path || event.node.req.url || "/";
    event._path = withoutBase(event.path || "/", base);
    event.node.req.url = event._path;
    try {
      return await handler(event);
    } finally {
      event._path = event.node.req.url = _path;
    }
  });
}

function hasProp(obj, prop) {
  try {
    return prop in obj;
  } catch {
    return false;
  }
}

class H3Error extends Error {
  static __h3_error__ = true;
  statusCode = 500;
  fatal = false;
  unhandled = false;
  statusMessage;
  data;
  cause;
  constructor(message, opts = {}) {
    super(message, opts);
    if (opts.cause && !this.cause) {
      this.cause = opts.cause;
    }
  }
  toJSON() {
    const obj = {
      message: this.message,
      statusCode: sanitizeStatusCode(this.statusCode, 500)
    };
    if (this.statusMessage) {
      obj.statusMessage = sanitizeStatusMessage(this.statusMessage);
    }
    if (this.data !== void 0) {
      obj.data = this.data;
    }
    return obj;
  }
}
function createError$1(input) {
  if (typeof input === "string") {
    return new H3Error(input);
  }
  if (isError(input)) {
    return input;
  }
  const err = new H3Error(input.message ?? input.statusMessage ?? "", {
    cause: input.cause || input
  });
  if (hasProp(input, "stack")) {
    try {
      Object.defineProperty(err, "stack", {
        get() {
          return input.stack;
        }
      });
    } catch {
      try {
        err.stack = input.stack;
      } catch {
      }
    }
  }
  if (input.data) {
    err.data = input.data;
  }
  if (input.statusCode) {
    err.statusCode = sanitizeStatusCode(input.statusCode, err.statusCode);
  } else if (input.status) {
    err.statusCode = sanitizeStatusCode(input.status, err.statusCode);
  }
  if (input.statusMessage) {
    err.statusMessage = input.statusMessage;
  } else if (input.statusText) {
    err.statusMessage = input.statusText;
  }
  if (err.statusMessage) {
    const originalMessage = err.statusMessage;
    const sanitizedMessage = sanitizeStatusMessage(err.statusMessage);
    if (sanitizedMessage !== originalMessage) {
      console.warn(
        "[h3] Please prefer using `message` for longer error messages instead of `statusMessage`. In the future, `statusMessage` will be sanitized by default."
      );
    }
  }
  if (input.fatal !== void 0) {
    err.fatal = input.fatal;
  }
  if (input.unhandled !== void 0) {
    err.unhandled = input.unhandled;
  }
  return err;
}
function sendError(event, error, debug) {
  if (event.handled) {
    return;
  }
  const h3Error = isError(error) ? error : createError$1(error);
  const responseBody = {
    statusCode: h3Error.statusCode,
    statusMessage: h3Error.statusMessage,
    stack: [],
    data: h3Error.data
  };
  if (debug) {
    responseBody.stack = (h3Error.stack || "").split("\n").map((l) => l.trim());
  }
  if (event.handled) {
    return;
  }
  const _code = Number.parseInt(h3Error.statusCode);
  setResponseStatus(event, _code, h3Error.statusMessage);
  event.node.res.setHeader("content-type", MIMES.json);
  event.node.res.end(JSON.stringify(responseBody, void 0, 2));
}
function isError(input) {
  return input?.constructor?.__h3_error__ === true;
}

function getQuery(event) {
  return getQuery$1(event.path || "");
}
function isMethod(event, expected, allowHead) {
  if (typeof expected === "string") {
    if (event.method === expected) {
      return true;
    }
  } else if (expected.includes(event.method)) {
    return true;
  }
  return false;
}
function assertMethod(event, expected, allowHead) {
  if (!isMethod(event, expected)) {
    throw createError$1({
      statusCode: 405,
      statusMessage: "HTTP method is not allowed."
    });
  }
}
function getRequestHeaders(event) {
  const _headers = {};
  for (const key in event.node.req.headers) {
    const val = event.node.req.headers[key];
    _headers[key] = Array.isArray(val) ? val.filter(Boolean).join(", ") : val;
  }
  return _headers;
}
function getRequestHeader(event, name) {
  const headers = getRequestHeaders(event);
  const value = headers[name.toLowerCase()];
  return value;
}
function getRequestHost(event, opts = {}) {
  if (opts.xForwardedHost) {
    const _header = event.node.req.headers["x-forwarded-host"];
    const xForwardedHost = (_header || "").split(",").shift()?.trim();
    if (xForwardedHost) {
      return xForwardedHost;
    }
  }
  return event.node.req.headers.host || "localhost";
}
function getRequestProtocol(event, opts = {}) {
  if (opts.xForwardedProto !== false && event.node.req.headers["x-forwarded-proto"] === "https") {
    return "https";
  }
  return event.node.req.connection?.encrypted ? "https" : "http";
}
function getRequestURL(event, opts = {}) {
  const host = getRequestHost(event, opts);
  const protocol = getRequestProtocol(event, opts);
  const path = (event.node.req.originalUrl || event.path).replace(
    /^[/\\]+/g,
    "/"
  );
  return new URL(path, `${protocol}://${host}`);
}

const RawBodySymbol = Symbol.for("h3RawBody");
const ParsedBodySymbol = Symbol.for("h3ParsedBody");
const PayloadMethods$1 = ["PATCH", "POST", "PUT", "DELETE"];
function readRawBody(event, encoding = "utf8") {
  assertMethod(event, PayloadMethods$1);
  const _rawBody = event._requestBody || event.web?.request?.body || event.node.req[RawBodySymbol] || event.node.req.rawBody || event.node.req.body;
  if (_rawBody) {
    const promise2 = Promise.resolve(_rawBody).then((_resolved) => {
      if (Buffer.isBuffer(_resolved)) {
        return _resolved;
      }
      if (typeof _resolved.pipeTo === "function") {
        return new Promise((resolve, reject) => {
          const chunks = [];
          _resolved.pipeTo(
            new WritableStream({
              write(chunk) {
                chunks.push(chunk);
              },
              close() {
                resolve(Buffer.concat(chunks));
              },
              abort(reason) {
                reject(reason);
              }
            })
          ).catch(reject);
        });
      } else if (typeof _resolved.pipe === "function") {
        return new Promise((resolve, reject) => {
          const chunks = [];
          _resolved.on("data", (chunk) => {
            chunks.push(chunk);
          }).on("end", () => {
            resolve(Buffer.concat(chunks));
          }).on("error", reject);
        });
      }
      if (_resolved.constructor === Object) {
        return Buffer.from(JSON.stringify(_resolved));
      }
      if (_resolved instanceof URLSearchParams) {
        return Buffer.from(_resolved.toString());
      }
      if (_resolved instanceof FormData) {
        return new Response(_resolved).bytes().then((uint8arr) => Buffer.from(uint8arr));
      }
      return Buffer.from(_resolved);
    });
    return encoding ? promise2.then((buff) => buff.toString(encoding)) : promise2;
  }
  if (!Number.parseInt(event.node.req.headers["content-length"] || "") && !String(event.node.req.headers["transfer-encoding"] ?? "").split(",").map((e) => e.trim()).filter(Boolean).includes("chunked")) {
    return Promise.resolve(void 0);
  }
  const promise = event.node.req[RawBodySymbol] = new Promise(
    (resolve, reject) => {
      const bodyData = [];
      event.node.req.on("error", (err) => {
        reject(err);
      }).on("data", (chunk) => {
        bodyData.push(chunk);
      }).on("end", () => {
        resolve(Buffer.concat(bodyData));
      });
    }
  );
  const result = encoding ? promise.then((buff) => buff.toString(encoding)) : promise;
  return result;
}
async function readBody(event, options = {}) {
  const request = event.node.req;
  if (hasProp(request, ParsedBodySymbol)) {
    return request[ParsedBodySymbol];
  }
  const contentType = request.headers["content-type"] || "";
  const body = await readRawBody(event);
  let parsed;
  if (contentType === "application/json") {
    parsed = _parseJSON(body, options.strict ?? true);
  } else if (contentType.startsWith("application/x-www-form-urlencoded")) {
    parsed = _parseURLEncodedBody(body);
  } else if (contentType.startsWith("text/")) {
    parsed = body;
  } else {
    parsed = _parseJSON(body, options.strict ?? false);
  }
  request[ParsedBodySymbol] = parsed;
  return parsed;
}
function getRequestWebStream(event) {
  if (!PayloadMethods$1.includes(event.method)) {
    return;
  }
  const bodyStream = event.web?.request?.body || event._requestBody;
  if (bodyStream) {
    return bodyStream;
  }
  const _hasRawBody = RawBodySymbol in event.node.req || "rawBody" in event.node.req || "body" in event.node.req || "__unenv__" in event.node.req;
  if (_hasRawBody) {
    return new ReadableStream({
      async start(controller) {
        const _rawBody = await readRawBody(event, false);
        if (_rawBody) {
          controller.enqueue(_rawBody);
        }
        controller.close();
      }
    });
  }
  return new ReadableStream({
    start: (controller) => {
      event.node.req.on("data", (chunk) => {
        controller.enqueue(chunk);
      });
      event.node.req.on("end", () => {
        controller.close();
      });
      event.node.req.on("error", (err) => {
        controller.error(err);
      });
    }
  });
}
function _parseJSON(body = "", strict) {
  if (!body) {
    return void 0;
  }
  try {
    return destr(body, { strict });
  } catch {
    throw createError$1({
      statusCode: 400,
      statusMessage: "Bad Request",
      message: "Invalid JSON body"
    });
  }
}
function _parseURLEncodedBody(body) {
  const form = new URLSearchParams(body);
  const parsedForm = /* @__PURE__ */ Object.create(null);
  for (const [key, value] of form.entries()) {
    if (hasProp(parsedForm, key)) {
      if (!Array.isArray(parsedForm[key])) {
        parsedForm[key] = [parsedForm[key]];
      }
      parsedForm[key].push(value);
    } else {
      parsedForm[key] = value;
    }
  }
  return parsedForm;
}

function handleCacheHeaders(event, opts) {
  const cacheControls = ["public", ...opts.cacheControls || []];
  let cacheMatched = false;
  if (opts.maxAge !== void 0) {
    cacheControls.push(`max-age=${+opts.maxAge}`, `s-maxage=${+opts.maxAge}`);
  }
  if (opts.modifiedTime) {
    const modifiedTime = new Date(opts.modifiedTime);
    const ifModifiedSince = event.node.req.headers["if-modified-since"];
    event.node.res.setHeader("last-modified", modifiedTime.toUTCString());
    if (ifModifiedSince && new Date(ifModifiedSince) >= modifiedTime) {
      cacheMatched = true;
    }
  }
  if (opts.etag) {
    event.node.res.setHeader("etag", opts.etag);
    const ifNonMatch = event.node.req.headers["if-none-match"];
    if (ifNonMatch === opts.etag) {
      cacheMatched = true;
    }
  }
  event.node.res.setHeader("cache-control", cacheControls.join(", "));
  if (cacheMatched) {
    event.node.res.statusCode = 304;
    if (!event.handled) {
      event.node.res.end();
    }
    return true;
  }
  return false;
}

const MIMES = {
  html: "text/html",
  json: "application/json"
};

const DISALLOWED_STATUS_CHARS = /[^\u0009\u0020-\u007E]/g;
function sanitizeStatusMessage(statusMessage = "") {
  return statusMessage.replace(DISALLOWED_STATUS_CHARS, "");
}
function sanitizeStatusCode(statusCode, defaultStatusCode = 200) {
  if (!statusCode) {
    return defaultStatusCode;
  }
  if (typeof statusCode === "string") {
    statusCode = Number.parseInt(statusCode, 10);
  }
  if (statusCode < 100 || statusCode > 999) {
    return defaultStatusCode;
  }
  return statusCode;
}

function getDistinctCookieKey(name, opts) {
  return [name, opts.domain || "", opts.path || "/"].join(";");
}

function parseCookies(event) {
  return parse(event.node.req.headers.cookie || "");
}
function getCookie(event, name) {
  return parseCookies(event)[name];
}
function setCookie(event, name, value, serializeOptions = {}) {
  if (!serializeOptions.path) {
    serializeOptions = { path: "/", ...serializeOptions };
  }
  const newCookie = serialize$1(name, value, serializeOptions);
  const currentCookies = splitCookiesString(
    event.node.res.getHeader("set-cookie")
  );
  if (currentCookies.length === 0) {
    event.node.res.setHeader("set-cookie", newCookie);
    return;
  }
  const newCookieKey = getDistinctCookieKey(name, serializeOptions);
  event.node.res.removeHeader("set-cookie");
  for (const cookie of currentCookies) {
    const parsed = parseSetCookie(cookie);
    const key = getDistinctCookieKey(parsed.name, parsed);
    if (key === newCookieKey) {
      continue;
    }
    event.node.res.appendHeader("set-cookie", cookie);
  }
  event.node.res.appendHeader("set-cookie", newCookie);
}
function splitCookiesString(cookiesString) {
  if (Array.isArray(cookiesString)) {
    return cookiesString.flatMap((c) => splitCookiesString(c));
  }
  if (typeof cookiesString !== "string") {
    return [];
  }
  const cookiesStrings = [];
  let pos = 0;
  let start;
  let ch;
  let lastComma;
  let nextStart;
  let cookiesSeparatorFound;
  const skipWhitespace = () => {
    while (pos < cookiesString.length && /\s/.test(cookiesString.charAt(pos))) {
      pos += 1;
    }
    return pos < cookiesString.length;
  };
  const notSpecialChar = () => {
    ch = cookiesString.charAt(pos);
    return ch !== "=" && ch !== ";" && ch !== ",";
  };
  while (pos < cookiesString.length) {
    start = pos;
    cookiesSeparatorFound = false;
    while (skipWhitespace()) {
      ch = cookiesString.charAt(pos);
      if (ch === ",") {
        lastComma = pos;
        pos += 1;
        skipWhitespace();
        nextStart = pos;
        while (pos < cookiesString.length && notSpecialChar()) {
          pos += 1;
        }
        if (pos < cookiesString.length && cookiesString.charAt(pos) === "=") {
          cookiesSeparatorFound = true;
          pos = nextStart;
          cookiesStrings.push(cookiesString.slice(start, lastComma));
          start = pos;
        } else {
          pos = lastComma + 1;
        }
      } else {
        pos += 1;
      }
    }
    if (!cookiesSeparatorFound || pos >= cookiesString.length) {
      cookiesStrings.push(cookiesString.slice(start));
    }
  }
  return cookiesStrings;
}

const defer = typeof setImmediate === "undefined" ? (fn) => fn() : setImmediate;
function send(event, data, type) {
  if (type) {
    defaultContentType(event, type);
  }
  return new Promise((resolve) => {
    defer(() => {
      if (!event.handled) {
        event.node.res.end(data);
      }
      resolve();
    });
  });
}
function sendNoContent(event, code) {
  if (event.handled) {
    return;
  }
  if (!code && event.node.res.statusCode !== 200) {
    code = event.node.res.statusCode;
  }
  const _code = sanitizeStatusCode(code, 204);
  if (_code === 204) {
    event.node.res.removeHeader("content-length");
  }
  event.node.res.writeHead(_code);
  event.node.res.end();
}
function setResponseStatus(event, code, text) {
  if (code) {
    event.node.res.statusCode = sanitizeStatusCode(
      code,
      event.node.res.statusCode
    );
  }
  if (text) {
    event.node.res.statusMessage = sanitizeStatusMessage(text);
  }
}
function getResponseStatus(event) {
  return event.node.res.statusCode;
}
function getResponseStatusText(event) {
  return event.node.res.statusMessage;
}
function defaultContentType(event, type) {
  if (type && event.node.res.statusCode !== 304 && !event.node.res.getHeader("content-type")) {
    event.node.res.setHeader("content-type", type);
  }
}
function sendRedirect(event, location, code = 302) {
  event.node.res.statusCode = sanitizeStatusCode(
    code,
    event.node.res.statusCode
  );
  event.node.res.setHeader("location", location);
  const encodedLoc = location.replace(/"/g, "%22");
  const html = `<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0; url=${encodedLoc}"></head></html>`;
  return send(event, html, MIMES.html);
}
function getResponseHeader(event, name) {
  return event.node.res.getHeader(name);
}
function setResponseHeaders(event, headers) {
  for (const [name, value] of Object.entries(headers)) {
    event.node.res.setHeader(
      name,
      value
    );
  }
}
const setHeaders = setResponseHeaders;
function setResponseHeader(event, name, value) {
  event.node.res.setHeader(name, value);
}
function appendResponseHeader(event, name, value) {
  let current = event.node.res.getHeader(name);
  if (!current) {
    event.node.res.setHeader(name, value);
    return;
  }
  if (!Array.isArray(current)) {
    current = [current.toString()];
  }
  event.node.res.setHeader(name, [...current, value]);
}
function isStream(data) {
  if (!data || typeof data !== "object") {
    return false;
  }
  if (typeof data.pipe === "function") {
    if (typeof data._read === "function") {
      return true;
    }
    if (typeof data.abort === "function") {
      return true;
    }
  }
  if (typeof data.pipeTo === "function") {
    return true;
  }
  return false;
}
function isWebResponse(data) {
  return typeof Response !== "undefined" && data instanceof Response;
}
function sendStream(event, stream) {
  if (!stream || typeof stream !== "object") {
    throw new Error("[h3] Invalid stream provided.");
  }
  event.node.res._data = stream;
  if (!event.node.res.socket) {
    event._handled = true;
    return Promise.resolve();
  }
  if (hasProp(stream, "pipeTo") && typeof stream.pipeTo === "function") {
    return stream.pipeTo(
      new WritableStream({
        write(chunk) {
          event.node.res.write(chunk);
        }
      })
    ).then(() => {
      event.node.res.end();
    });
  }
  if (hasProp(stream, "pipe") && typeof stream.pipe === "function") {
    return new Promise((resolve, reject) => {
      stream.pipe(event.node.res);
      if (stream.on) {
        stream.on("end", () => {
          event.node.res.end();
          resolve();
        });
        stream.on("error", (error) => {
          reject(error);
        });
      }
      event.node.res.on("close", () => {
        if (stream.abort) {
          stream.abort();
        }
      });
    });
  }
  throw new Error("[h3] Invalid or incompatible stream provided.");
}
function sendWebResponse(event, response) {
  for (const [key, value] of response.headers) {
    if (key === "set-cookie") {
      event.node.res.appendHeader(key, splitCookiesString(value));
    } else {
      event.node.res.setHeader(key, value);
    }
  }
  if (response.status) {
    event.node.res.statusCode = sanitizeStatusCode(
      response.status,
      event.node.res.statusCode
    );
  }
  if (response.statusText) {
    event.node.res.statusMessage = sanitizeStatusMessage(response.statusText);
  }
  if (response.redirected) {
    event.node.res.setHeader("location", response.url);
  }
  if (!response.body) {
    event.node.res.end();
    return;
  }
  return sendStream(event, response.body);
}

const PayloadMethods = /* @__PURE__ */ new Set(["PATCH", "POST", "PUT", "DELETE"]);
const ignoredHeaders = /* @__PURE__ */ new Set([
  "transfer-encoding",
  "accept-encoding",
  "connection",
  "keep-alive",
  "upgrade",
  "expect",
  "host",
  "accept"
]);
async function proxyRequest(event, target, opts = {}) {
  let body;
  let duplex;
  if (PayloadMethods.has(event.method)) {
    if (opts.streamRequest) {
      body = getRequestWebStream(event);
      duplex = "half";
    } else {
      body = await readRawBody(event, false).catch(() => void 0);
    }
  }
  const method = opts.fetchOptions?.method || event.method;
  const fetchHeaders = mergeHeaders$1(
    getProxyRequestHeaders(event, { host: target.startsWith("/") }),
    opts.fetchOptions?.headers,
    opts.headers
  );
  return sendProxy(event, target, {
    ...opts,
    fetchOptions: {
      method,
      body,
      duplex,
      ...opts.fetchOptions,
      headers: fetchHeaders
    }
  });
}
async function sendProxy(event, target, opts = {}) {
  let response;
  try {
    response = await _getFetch(opts.fetch)(target, {
      headers: opts.headers,
      ignoreResponseError: true,
      // make $ofetch.raw transparent
      ...opts.fetchOptions
    });
  } catch (error) {
    throw createError$1({
      status: 502,
      statusMessage: "Bad Gateway",
      cause: error
    });
  }
  event.node.res.statusCode = sanitizeStatusCode(
    response.status,
    event.node.res.statusCode
  );
  event.node.res.statusMessage = sanitizeStatusMessage(response.statusText);
  const cookies = [];
  for (const [key, value] of response.headers.entries()) {
    if (key === "content-encoding") {
      continue;
    }
    if (key === "content-length") {
      continue;
    }
    if (key === "set-cookie") {
      cookies.push(...splitCookiesString(value));
      continue;
    }
    event.node.res.setHeader(key, value);
  }
  if (cookies.length > 0) {
    event.node.res.setHeader(
      "set-cookie",
      cookies.map((cookie) => {
        if (opts.cookieDomainRewrite) {
          cookie = rewriteCookieProperty(
            cookie,
            opts.cookieDomainRewrite,
            "domain"
          );
        }
        if (opts.cookiePathRewrite) {
          cookie = rewriteCookieProperty(
            cookie,
            opts.cookiePathRewrite,
            "path"
          );
        }
        return cookie;
      })
    );
  }
  if (opts.onResponse) {
    await opts.onResponse(event, response);
  }
  if (response._data !== void 0) {
    return response._data;
  }
  if (event.handled) {
    return;
  }
  if (opts.sendStream === false) {
    const data = new Uint8Array(await response.arrayBuffer());
    return event.node.res.end(data);
  }
  if (response.body) {
    for await (const chunk of response.body) {
      event.node.res.write(chunk);
    }
  }
  return event.node.res.end();
}
function getProxyRequestHeaders(event, opts) {
  const headers = /* @__PURE__ */ Object.create(null);
  const reqHeaders = getRequestHeaders(event);
  for (const name in reqHeaders) {
    if (!ignoredHeaders.has(name) || name === "host" && opts?.host) {
      headers[name] = reqHeaders[name];
    }
  }
  return headers;
}
function fetchWithEvent(event, req, init, options) {
  return _getFetch(options?.fetch)(req, {
    ...init,
    context: init?.context || event.context,
    headers: {
      ...getProxyRequestHeaders(event, {
        host: typeof req === "string" && req.startsWith("/")
      }),
      ...init?.headers
    }
  });
}
function _getFetch(_fetch) {
  if (_fetch) {
    return _fetch;
  }
  if (globalThis.fetch) {
    return globalThis.fetch;
  }
  throw new Error(
    "fetch is not available. Try importing `node-fetch-native/polyfill` for Node.js."
  );
}
function rewriteCookieProperty(header, map, property) {
  const _map = typeof map === "string" ? { "*": map } : map;
  return header.replace(
    new RegExp(`(;\\s*${property}=)([^;]+)`, "gi"),
    (match, prefix, previousValue) => {
      let newValue;
      if (previousValue in _map) {
        newValue = _map[previousValue];
      } else if ("*" in _map) {
        newValue = _map["*"];
      } else {
        return match;
      }
      return newValue ? prefix + newValue : "";
    }
  );
}
function mergeHeaders$1(defaults, ...inputs) {
  const _inputs = inputs.filter(Boolean);
  if (_inputs.length === 0) {
    return defaults;
  }
  const merged = new Headers(defaults);
  for (const input of _inputs) {
    const entries = Array.isArray(input) ? input : typeof input.entries === "function" ? input.entries() : Object.entries(input);
    for (const [key, value] of entries) {
      if (value !== void 0) {
        merged.set(key, value);
      }
    }
  }
  return merged;
}

class H3Event {
  "__is_event__" = true;
  // Context
  node;
  // Node
  web;
  // Web
  context = {};
  // Shared
  // Request
  _method;
  _path;
  _headers;
  _requestBody;
  // Response
  _handled = false;
  // Hooks
  _onBeforeResponseCalled;
  _onAfterResponseCalled;
  constructor(req, res) {
    this.node = { req, res };
  }
  // --- Request ---
  get method() {
    if (!this._method) {
      this._method = (this.node.req.method || "GET").toUpperCase();
    }
    return this._method;
  }
  get path() {
    return this._path || this.node.req.url || "/";
  }
  get headers() {
    if (!this._headers) {
      this._headers = _normalizeNodeHeaders(this.node.req.headers);
    }
    return this._headers;
  }
  // --- Respoonse ---
  get handled() {
    return this._handled || this.node.res.writableEnded || this.node.res.headersSent;
  }
  respondWith(response) {
    return Promise.resolve(response).then(
      (_response) => sendWebResponse(this, _response)
    );
  }
  // --- Utils ---
  toString() {
    return `[${this.method}] ${this.path}`;
  }
  toJSON() {
    return this.toString();
  }
  // --- Deprecated ---
  /** @deprecated Please use `event.node.req` instead. */
  get req() {
    return this.node.req;
  }
  /** @deprecated Please use `event.node.res` instead. */
  get res() {
    return this.node.res;
  }
}
function isEvent(input) {
  return hasProp(input, "__is_event__");
}
function createEvent(req, res) {
  return new H3Event(req, res);
}
function _normalizeNodeHeaders(nodeHeaders) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(nodeHeaders)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        headers.append(name, item);
      }
    } else if (value) {
      headers.set(name, value);
    }
  }
  return headers;
}

function defineEventHandler(handler) {
  if (typeof handler === "function") {
    handler.__is_handler__ = true;
    return handler;
  }
  const _hooks = {
    onRequest: _normalizeArray(handler.onRequest),
    onBeforeResponse: _normalizeArray(handler.onBeforeResponse)
  };
  const _handler = (event) => {
    return _callHandler(event, handler.handler, _hooks);
  };
  _handler.__is_handler__ = true;
  _handler.__resolve__ = handler.handler.__resolve__;
  _handler.__websocket__ = handler.websocket;
  return _handler;
}
function _normalizeArray(input) {
  return input ? Array.isArray(input) ? input : [input] : void 0;
}
async function _callHandler(event, handler, hooks) {
  if (hooks.onRequest) {
    for (const hook of hooks.onRequest) {
      await hook(event);
      if (event.handled) {
        return;
      }
    }
  }
  const body = await handler(event);
  const response = { body };
  if (hooks.onBeforeResponse) {
    for (const hook of hooks.onBeforeResponse) {
      await hook(event, response);
    }
  }
  return response.body;
}
const eventHandler = defineEventHandler;
function isEventHandler(input) {
  return hasProp(input, "__is_handler__");
}
function toEventHandler(input, _, _route) {
  if (!isEventHandler(input)) {
    console.warn(
      "[h3] Implicit event handler conversion is deprecated. Use `eventHandler()` or `fromNodeMiddleware()` to define event handlers.",
      _route && _route !== "/" ? `
     Route: ${_route}` : "",
      `
     Handler: ${input}`
    );
  }
  return input;
}
function defineLazyEventHandler(factory) {
  let _promise;
  let _resolved;
  const resolveHandler = () => {
    if (_resolved) {
      return Promise.resolve(_resolved);
    }
    if (!_promise) {
      _promise = Promise.resolve(factory()).then((r) => {
        const handler2 = r.default || r;
        if (typeof handler2 !== "function") {
          throw new TypeError(
            "Invalid lazy handler result. It should be a function:",
            handler2
          );
        }
        _resolved = { handler: toEventHandler(r.default || r) };
        return _resolved;
      });
    }
    return _promise;
  };
  const handler = eventHandler((event) => {
    if (_resolved) {
      return _resolved.handler(event);
    }
    return resolveHandler().then((r) => r.handler(event));
  });
  handler.__resolve__ = resolveHandler;
  return handler;
}
const lazyEventHandler = defineLazyEventHandler;

function createApp(options = {}) {
  const stack = [];
  const handler = createAppEventHandler(stack, options);
  const resolve = createResolver(stack);
  handler.__resolve__ = resolve;
  const getWebsocket = cachedFn(() => websocketOptions(resolve, options));
  const app = {
    // @ts-expect-error
    use: (arg1, arg2, arg3) => use(app, arg1, arg2, arg3),
    resolve,
    handler,
    stack,
    options,
    get websocket() {
      return getWebsocket();
    }
  };
  return app;
}
function use(app, arg1, arg2, arg3) {
  if (Array.isArray(arg1)) {
    for (const i of arg1) {
      use(app, i, arg2, arg3);
    }
  } else if (Array.isArray(arg2)) {
    for (const i of arg2) {
      use(app, arg1, i, arg3);
    }
  } else if (typeof arg1 === "string") {
    app.stack.push(
      normalizeLayer({ ...arg3, route: arg1, handler: arg2 })
    );
  } else if (typeof arg1 === "function") {
    app.stack.push(normalizeLayer({ ...arg2, handler: arg1 }));
  } else {
    app.stack.push(normalizeLayer({ ...arg1 }));
  }
  return app;
}
function createAppEventHandler(stack, options) {
  const spacing = options.debug ? 2 : void 0;
  return eventHandler(async (event) => {
    event.node.req.originalUrl = event.node.req.originalUrl || event.node.req.url || "/";
    const _reqPath = event._path || event.node.req.url || "/";
    let _layerPath;
    if (options.onRequest) {
      await options.onRequest(event);
    }
    for (const layer of stack) {
      if (layer.route.length > 1) {
        if (!_reqPath.startsWith(layer.route)) {
          continue;
        }
        _layerPath = _reqPath.slice(layer.route.length) || "/";
      } else {
        _layerPath = _reqPath;
      }
      if (layer.match && !layer.match(_layerPath, event)) {
        continue;
      }
      event._path = _layerPath;
      event.node.req.url = _layerPath;
      const val = await layer.handler(event);
      const _body = val === void 0 ? void 0 : await val;
      if (_body !== void 0) {
        const _response = { body: _body };
        if (options.onBeforeResponse) {
          event._onBeforeResponseCalled = true;
          await options.onBeforeResponse(event, _response);
        }
        await handleHandlerResponse(event, _response.body, spacing);
        if (options.onAfterResponse) {
          event._onAfterResponseCalled = true;
          await options.onAfterResponse(event, _response);
        }
        return;
      }
      if (event.handled) {
        if (options.onAfterResponse) {
          event._onAfterResponseCalled = true;
          await options.onAfterResponse(event, void 0);
        }
        return;
      }
    }
    if (!event.handled) {
      throw createError$1({
        statusCode: 404,
        statusMessage: `Cannot find any path matching ${event.path || "/"}.`
      });
    }
    if (options.onAfterResponse) {
      event._onAfterResponseCalled = true;
      await options.onAfterResponse(event, void 0);
    }
  });
}
function createResolver(stack) {
  return async (path) => {
    let _layerPath;
    for (const layer of stack) {
      if (layer.route === "/" && !layer.handler.__resolve__) {
        continue;
      }
      if (!path.startsWith(layer.route)) {
        continue;
      }
      _layerPath = path.slice(layer.route.length) || "/";
      if (layer.match && !layer.match(_layerPath, void 0)) {
        continue;
      }
      let res = { route: layer.route, handler: layer.handler };
      if (res.handler.__resolve__) {
        const _res = await res.handler.__resolve__(_layerPath);
        if (!_res) {
          continue;
        }
        res = {
          ...res,
          ..._res,
          route: joinURL(res.route || "/", _res.route || "/")
        };
      }
      return res;
    }
  };
}
function normalizeLayer(input) {
  let handler = input.handler;
  if (handler.handler) {
    handler = handler.handler;
  }
  if (input.lazy) {
    handler = lazyEventHandler(handler);
  } else if (!isEventHandler(handler)) {
    handler = toEventHandler(handler, void 0, input.route);
  }
  return {
    route: withoutTrailingSlash(input.route),
    match: input.match,
    handler
  };
}
function handleHandlerResponse(event, val, jsonSpace) {
  if (val === null) {
    return sendNoContent(event);
  }
  if (val) {
    if (isWebResponse(val)) {
      return sendWebResponse(event, val);
    }
    if (isStream(val)) {
      return sendStream(event, val);
    }
    if (val.buffer) {
      return send(event, val);
    }
    if (val.arrayBuffer && typeof val.arrayBuffer === "function") {
      return val.arrayBuffer().then((arrayBuffer) => {
        return send(event, Buffer.from(arrayBuffer), val.type);
      });
    }
    if (val instanceof Error) {
      throw createError$1(val);
    }
    if (typeof val.end === "function") {
      return true;
    }
  }
  const valType = typeof val;
  if (valType === "string") {
    return send(event, val, MIMES.html);
  }
  if (valType === "object" || valType === "boolean" || valType === "number") {
    return send(event, JSON.stringify(val, void 0, jsonSpace), MIMES.json);
  }
  if (valType === "bigint") {
    return send(event, val.toString(), MIMES.json);
  }
  throw createError$1({
    statusCode: 500,
    statusMessage: `[h3] Cannot send ${valType} as response.`
  });
}
function cachedFn(fn) {
  let cache;
  return () => {
    if (!cache) {
      cache = fn();
    }
    return cache;
  };
}
function websocketOptions(evResolver, appOptions) {
  return {
    ...appOptions.websocket,
    async resolve(info) {
      const url = info.request?.url || info.url || "/";
      const { pathname } = typeof url === "string" ? parseURL(url) : url;
      const resolved = await evResolver(pathname);
      return resolved?.handler?.__websocket__ || {};
    }
  };
}

const RouterMethods = [
  "connect",
  "delete",
  "get",
  "head",
  "options",
  "post",
  "put",
  "trace",
  "patch"
];
function createRouter(opts = {}) {
  const _router = createRouter$1({});
  const routes = {};
  let _matcher;
  const router = {};
  const addRoute = (path, handler, method) => {
    let route = routes[path];
    if (!route) {
      routes[path] = route = { path, handlers: {} };
      _router.insert(path, route);
    }
    if (Array.isArray(method)) {
      for (const m of method) {
        addRoute(path, handler, m);
      }
    } else {
      route.handlers[method] = toEventHandler(handler, void 0, path);
    }
    return router;
  };
  router.use = router.add = (path, handler, method) => addRoute(path, handler, method || "all");
  for (const method of RouterMethods) {
    router[method] = (path, handle) => router.add(path, handle, method);
  }
  const matchHandler = (path = "/", method = "get") => {
    const qIndex = path.indexOf("?");
    if (qIndex !== -1) {
      path = path.slice(0, Math.max(0, qIndex));
    }
    const matched = _router.lookup(path);
    if (!matched || !matched.handlers) {
      return {
        error: createError$1({
          statusCode: 404,
          name: "Not Found",
          statusMessage: `Cannot find any route matching ${path || "/"}.`
        })
      };
    }
    let handler = matched.handlers[method] || matched.handlers.all;
    if (!handler) {
      if (!_matcher) {
        _matcher = toRouteMatcher(_router);
      }
      const _matches = _matcher.matchAll(path).reverse();
      for (const _match of _matches) {
        if (_match.handlers[method]) {
          handler = _match.handlers[method];
          matched.handlers[method] = matched.handlers[method] || handler;
          break;
        }
        if (_match.handlers.all) {
          handler = _match.handlers.all;
          matched.handlers.all = matched.handlers.all || handler;
          break;
        }
      }
    }
    if (!handler) {
      return {
        error: createError$1({
          statusCode: 405,
          name: "Method Not Allowed",
          statusMessage: `Method ${method} is not allowed on this route.`
        })
      };
    }
    return { matched, handler };
  };
  const isPreemptive = opts.preemptive || opts.preemtive;
  router.handler = eventHandler((event) => {
    const match = matchHandler(
      event.path,
      event.method.toLowerCase()
    );
    if ("error" in match) {
      if (isPreemptive) {
        throw match.error;
      } else {
        return;
      }
    }
    event.context.matchedRoute = match.matched;
    const params = match.matched.params || {};
    event.context.params = params;
    return Promise.resolve(match.handler(event)).then((res) => {
      if (res === void 0 && isPreemptive) {
        return null;
      }
      return res;
    });
  });
  router.handler.__resolve__ = async (path) => {
    path = withLeadingSlash(path);
    const match = matchHandler(path);
    if ("error" in match) {
      return;
    }
    let res = {
      route: match.matched.path,
      handler: match.handler
    };
    if (match.handler.__resolve__) {
      const _res = await match.handler.__resolve__(path);
      if (!_res) {
        return;
      }
      res = { ...res, ..._res };
    }
    return res;
  };
  return router;
}
function toNodeListener(app) {
  const toNodeHandle = async function(req, res) {
    const event = createEvent(req, res);
    try {
      await app.handler(event);
    } catch (_error) {
      const error = createError$1(_error);
      if (!isError(_error)) {
        error.unhandled = true;
      }
      setResponseStatus(event, error.statusCode, error.statusMessage);
      if (app.options.onError) {
        await app.options.onError(error, event);
      }
      if (event.handled) {
        return;
      }
      if (error.unhandled || error.fatal) {
        console.error("[h3]", error.fatal ? "[fatal]" : "[unhandled]", error);
      }
      if (app.options.onBeforeResponse && !event._onBeforeResponseCalled) {
        await app.options.onBeforeResponse(event, { body: error });
      }
      await sendError(event, error, !!app.options.debug);
      if (app.options.onAfterResponse && !event._onAfterResponseCalled) {
        await app.options.onAfterResponse(event, { body: error });
      }
    }
  };
  return toNodeHandle;
}

function flatHooks(configHooks, hooks = {}, parentName) {
  for (const key in configHooks) {
    const subHook = configHooks[key];
    const name = parentName ? `${parentName}:${key}` : key;
    if (typeof subHook === "object" && subHook !== null) {
      flatHooks(subHook, hooks, name);
    } else if (typeof subHook === "function") {
      hooks[name] = subHook;
    }
  }
  return hooks;
}
const defaultTask = { run: (function_) => function_() };
const _createTask = () => defaultTask;
const createTask = typeof console.createTask !== "undefined" ? console.createTask : _createTask;
function serialTaskCaller(hooks, args) {
  const name = args.shift();
  const task = createTask(name);
  return hooks.reduce(
    (promise, hookFunction) => promise.then(() => task.run(() => hookFunction(...args))),
    Promise.resolve()
  );
}
function parallelTaskCaller(hooks, args) {
  const name = args.shift();
  const task = createTask(name);
  return Promise.all(hooks.map((hook) => task.run(() => hook(...args))));
}
function callEachWith(callbacks, arg0) {
  for (const callback of [...callbacks]) {
    callback(arg0);
  }
}

class Hookable {
  constructor() {
    this._hooks = {};
    this._before = void 0;
    this._after = void 0;
    this._deprecatedMessages = void 0;
    this._deprecatedHooks = {};
    this.hook = this.hook.bind(this);
    this.callHook = this.callHook.bind(this);
    this.callHookWith = this.callHookWith.bind(this);
  }
  hook(name, function_, options = {}) {
    if (!name || typeof function_ !== "function") {
      return () => {
      };
    }
    const originalName = name;
    let dep;
    while (this._deprecatedHooks[name]) {
      dep = this._deprecatedHooks[name];
      name = dep.to;
    }
    if (dep && !options.allowDeprecated) {
      let message = dep.message;
      if (!message) {
        message = `${originalName} hook has been deprecated` + (dep.to ? `, please use ${dep.to}` : "");
      }
      if (!this._deprecatedMessages) {
        this._deprecatedMessages = /* @__PURE__ */ new Set();
      }
      if (!this._deprecatedMessages.has(message)) {
        console.warn(message);
        this._deprecatedMessages.add(message);
      }
    }
    if (!function_.name) {
      try {
        Object.defineProperty(function_, "name", {
          get: () => "_" + name.replace(/\W+/g, "_") + "_hook_cb",
          configurable: true
        });
      } catch {
      }
    }
    this._hooks[name] = this._hooks[name] || [];
    this._hooks[name].push(function_);
    return () => {
      if (function_) {
        this.removeHook(name, function_);
        function_ = void 0;
      }
    };
  }
  hookOnce(name, function_) {
    let _unreg;
    let _function = (...arguments_) => {
      if (typeof _unreg === "function") {
        _unreg();
      }
      _unreg = void 0;
      _function = void 0;
      return function_(...arguments_);
    };
    _unreg = this.hook(name, _function);
    return _unreg;
  }
  removeHook(name, function_) {
    if (this._hooks[name]) {
      const index = this._hooks[name].indexOf(function_);
      if (index !== -1) {
        this._hooks[name].splice(index, 1);
      }
      if (this._hooks[name].length === 0) {
        delete this._hooks[name];
      }
    }
  }
  deprecateHook(name, deprecated) {
    this._deprecatedHooks[name] = typeof deprecated === "string" ? { to: deprecated } : deprecated;
    const _hooks = this._hooks[name] || [];
    delete this._hooks[name];
    for (const hook of _hooks) {
      this.hook(name, hook);
    }
  }
  deprecateHooks(deprecatedHooks) {
    Object.assign(this._deprecatedHooks, deprecatedHooks);
    for (const name in deprecatedHooks) {
      this.deprecateHook(name, deprecatedHooks[name]);
    }
  }
  addHooks(configHooks) {
    const hooks = flatHooks(configHooks);
    const removeFns = Object.keys(hooks).map(
      (key) => this.hook(key, hooks[key])
    );
    return () => {
      for (const unreg of removeFns.splice(0, removeFns.length)) {
        unreg();
      }
    };
  }
  removeHooks(configHooks) {
    const hooks = flatHooks(configHooks);
    for (const key in hooks) {
      this.removeHook(key, hooks[key]);
    }
  }
  removeAllHooks() {
    for (const key in this._hooks) {
      delete this._hooks[key];
    }
  }
  callHook(name, ...arguments_) {
    arguments_.unshift(name);
    return this.callHookWith(serialTaskCaller, name, ...arguments_);
  }
  callHookParallel(name, ...arguments_) {
    arguments_.unshift(name);
    return this.callHookWith(parallelTaskCaller, name, ...arguments_);
  }
  callHookWith(caller, name, ...arguments_) {
    const event = this._before || this._after ? { name, args: arguments_, context: {} } : void 0;
    if (this._before) {
      callEachWith(this._before, event);
    }
    const result = caller(
      name in this._hooks ? [...this._hooks[name]] : [],
      arguments_
    );
    if (result instanceof Promise) {
      return result.finally(() => {
        if (this._after && event) {
          callEachWith(this._after, event);
        }
      });
    }
    if (this._after && event) {
      callEachWith(this._after, event);
    }
    return result;
  }
  beforeEach(function_) {
    this._before = this._before || [];
    this._before.push(function_);
    return () => {
      if (this._before !== void 0) {
        const index = this._before.indexOf(function_);
        if (index !== -1) {
          this._before.splice(index, 1);
        }
      }
    };
  }
  afterEach(function_) {
    this._after = this._after || [];
    this._after.push(function_);
    return () => {
      if (this._after !== void 0) {
        const index = this._after.indexOf(function_);
        if (index !== -1) {
          this._after.splice(index, 1);
        }
      }
    };
  }
}
function createHooks() {
  return new Hookable();
}

const s$1=globalThis.Headers,i=globalThis.AbortController,l=globalThis.fetch||(()=>{throw new Error("[node-fetch-native] Failed to fetch: `globalThis.fetch` is not available!")});

class FetchError extends Error {
  constructor(message, opts) {
    super(message, opts);
    this.name = "FetchError";
    if (opts?.cause && !this.cause) {
      this.cause = opts.cause;
    }
  }
}
function createFetchError(ctx) {
  const errorMessage = ctx.error?.message || ctx.error?.toString() || "";
  const method = ctx.request?.method || ctx.options?.method || "GET";
  const url = ctx.request?.url || String(ctx.request) || "/";
  const requestStr = `[${method}] ${JSON.stringify(url)}`;
  const statusStr = ctx.response ? `${ctx.response.status} ${ctx.response.statusText}` : "<no response>";
  const message = `${requestStr}: ${statusStr}${errorMessage ? ` ${errorMessage}` : ""}`;
  const fetchError = new FetchError(
    message,
    ctx.error ? { cause: ctx.error } : void 0
  );
  for (const key of ["request", "options", "response"]) {
    Object.defineProperty(fetchError, key, {
      get() {
        return ctx[key];
      }
    });
  }
  for (const [key, refKey] of [
    ["data", "_data"],
    ["status", "status"],
    ["statusCode", "status"],
    ["statusText", "statusText"],
    ["statusMessage", "statusText"]
  ]) {
    Object.defineProperty(fetchError, key, {
      get() {
        return ctx.response && ctx.response[refKey];
      }
    });
  }
  return fetchError;
}

const payloadMethods = new Set(
  Object.freeze(["PATCH", "POST", "PUT", "DELETE"])
);
function isPayloadMethod(method = "GET") {
  return payloadMethods.has(method.toUpperCase());
}
function isJSONSerializable(value) {
  if (value === void 0) {
    return false;
  }
  const t = typeof value;
  if (t === "string" || t === "number" || t === "boolean" || t === null) {
    return true;
  }
  if (t !== "object") {
    return false;
  }
  if (Array.isArray(value)) {
    return true;
  }
  if (value.buffer) {
    return false;
  }
  return value.constructor && value.constructor.name === "Object" || typeof value.toJSON === "function";
}
const textTypes = /* @__PURE__ */ new Set([
  "image/svg",
  "application/xml",
  "application/xhtml",
  "application/html"
]);
const JSON_RE = /^application\/(?:[\w!#$%&*.^`~-]*\+)?json(;.+)?$/i;
function detectResponseType(_contentType = "") {
  if (!_contentType) {
    return "json";
  }
  const contentType = _contentType.split(";").shift() || "";
  if (JSON_RE.test(contentType)) {
    return "json";
  }
  if (textTypes.has(contentType) || contentType.startsWith("text/")) {
    return "text";
  }
  return "blob";
}
function resolveFetchOptions(request, input, defaults, Headers) {
  const headers = mergeHeaders(
    input?.headers ?? request?.headers,
    defaults?.headers,
    Headers
  );
  let query;
  if (defaults?.query || defaults?.params || input?.params || input?.query) {
    query = {
      ...defaults?.params,
      ...defaults?.query,
      ...input?.params,
      ...input?.query
    };
  }
  return {
    ...defaults,
    ...input,
    query,
    params: query,
    headers
  };
}
function mergeHeaders(input, defaults, Headers) {
  if (!defaults) {
    return new Headers(input);
  }
  const headers = new Headers(defaults);
  if (input) {
    for (const [key, value] of Symbol.iterator in input || Array.isArray(input) ? input : new Headers(input)) {
      headers.set(key, value);
    }
  }
  return headers;
}
async function callHooks(context, hooks) {
  if (hooks) {
    if (Array.isArray(hooks)) {
      for (const hook of hooks) {
        await hook(context);
      }
    } else {
      await hooks(context);
    }
  }
}

const retryStatusCodes = /* @__PURE__ */ new Set([
  408,
  // Request Timeout
  409,
  // Conflict
  425,
  // Too Early (Experimental)
  429,
  // Too Many Requests
  500,
  // Internal Server Error
  502,
  // Bad Gateway
  503,
  // Service Unavailable
  504
  // Gateway Timeout
]);
const nullBodyResponses = /* @__PURE__ */ new Set([101, 204, 205, 304]);
function createFetch(globalOptions = {}) {
  const {
    fetch = globalThis.fetch,
    Headers = globalThis.Headers,
    AbortController = globalThis.AbortController
  } = globalOptions;
  async function onError(context) {
    const isAbort = context.error && context.error.name === "AbortError" && !context.options.timeout || false;
    if (context.options.retry !== false && !isAbort) {
      let retries;
      if (typeof context.options.retry === "number") {
        retries = context.options.retry;
      } else {
        retries = isPayloadMethod(context.options.method) ? 0 : 1;
      }
      const responseCode = context.response && context.response.status || 500;
      if (retries > 0 && (Array.isArray(context.options.retryStatusCodes) ? context.options.retryStatusCodes.includes(responseCode) : retryStatusCodes.has(responseCode))) {
        const retryDelay = typeof context.options.retryDelay === "function" ? context.options.retryDelay(context) : context.options.retryDelay || 0;
        if (retryDelay > 0) {
          await new Promise((resolve) => setTimeout(resolve, retryDelay));
        }
        return $fetchRaw(context.request, {
          ...context.options,
          retry: retries - 1
        });
      }
    }
    const error = createFetchError(context);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(error, $fetchRaw);
    }
    throw error;
  }
  const $fetchRaw = async function $fetchRaw2(_request, _options = {}) {
    const context = {
      request: _request,
      options: resolveFetchOptions(
        _request,
        _options,
        globalOptions.defaults,
        Headers
      ),
      response: void 0,
      error: void 0
    };
    if (context.options.method) {
      context.options.method = context.options.method.toUpperCase();
    }
    if (context.options.onRequest) {
      await callHooks(context, context.options.onRequest);
    }
    if (typeof context.request === "string") {
      if (context.options.baseURL) {
        context.request = withBase(context.request, context.options.baseURL);
      }
      if (context.options.query) {
        context.request = withQuery(context.request, context.options.query);
        delete context.options.query;
      }
      if ("query" in context.options) {
        delete context.options.query;
      }
      if ("params" in context.options) {
        delete context.options.params;
      }
    }
    if (context.options.body && isPayloadMethod(context.options.method)) {
      if (isJSONSerializable(context.options.body)) {
        context.options.body = typeof context.options.body === "string" ? context.options.body : JSON.stringify(context.options.body);
        context.options.headers = new Headers(context.options.headers || {});
        if (!context.options.headers.has("content-type")) {
          context.options.headers.set("content-type", "application/json");
        }
        if (!context.options.headers.has("accept")) {
          context.options.headers.set("accept", "application/json");
        }
      } else if (
        // ReadableStream Body
        "pipeTo" in context.options.body && typeof context.options.body.pipeTo === "function" || // Node.js Stream Body
        typeof context.options.body.pipe === "function"
      ) {
        if (!("duplex" in context.options)) {
          context.options.duplex = "half";
        }
      }
    }
    let abortTimeout;
    if (!context.options.signal && context.options.timeout) {
      const controller = new AbortController();
      abortTimeout = setTimeout(() => {
        const error = new Error(
          "[TimeoutError]: The operation was aborted due to timeout"
        );
        error.name = "TimeoutError";
        error.code = 23;
        controller.abort(error);
      }, context.options.timeout);
      context.options.signal = controller.signal;
    }
    try {
      context.response = await fetch(
        context.request,
        context.options
      );
    } catch (error) {
      context.error = error;
      if (context.options.onRequestError) {
        await callHooks(
          context,
          context.options.onRequestError
        );
      }
      return await onError(context);
    } finally {
      if (abortTimeout) {
        clearTimeout(abortTimeout);
      }
    }
    const hasBody = (context.response.body || // https://github.com/unjs/ofetch/issues/324
    // https://github.com/unjs/ofetch/issues/294
    // https://github.com/JakeChampion/fetch/issues/1454
    context.response._bodyInit) && !nullBodyResponses.has(context.response.status) && context.options.method !== "HEAD";
    if (hasBody) {
      const responseType = (context.options.parseResponse ? "json" : context.options.responseType) || detectResponseType(context.response.headers.get("content-type") || "");
      switch (responseType) {
        case "json": {
          const data = await context.response.text();
          const parseFunction = context.options.parseResponse || destr;
          context.response._data = parseFunction(data);
          break;
        }
        case "stream": {
          context.response._data = context.response.body || context.response._bodyInit;
          break;
        }
        default: {
          context.response._data = await context.response[responseType]();
        }
      }
    }
    if (context.options.onResponse) {
      await callHooks(
        context,
        context.options.onResponse
      );
    }
    if (!context.options.ignoreResponseError && context.response.status >= 400 && context.response.status < 600) {
      if (context.options.onResponseError) {
        await callHooks(
          context,
          context.options.onResponseError
        );
      }
      return await onError(context);
    }
    return context.response;
  };
  const $fetch = async function $fetch2(request, options) {
    const r = await $fetchRaw(request, options);
    return r._data;
  };
  $fetch.raw = $fetchRaw;
  $fetch.native = (...args) => fetch(...args);
  $fetch.create = (defaultOptions = {}, customGlobalOptions = {}) => createFetch({
    ...globalOptions,
    ...customGlobalOptions,
    defaults: {
      ...globalOptions.defaults,
      ...customGlobalOptions.defaults,
      ...defaultOptions
    }
  });
  return $fetch;
}

function createNodeFetch() {
  const useKeepAlive = JSON.parse(process.env.FETCH_KEEP_ALIVE || "false");
  if (!useKeepAlive) {
    return l;
  }
  const agentOptions = { keepAlive: true };
  const httpAgent = new http.Agent(agentOptions);
  const httpsAgent = new https.Agent(agentOptions);
  const nodeFetchOptions = {
    agent(parsedURL) {
      return parsedURL.protocol === "http:" ? httpAgent : httpsAgent;
    }
  };
  return function nodeFetchWithKeepAlive(input, init) {
    return l(input, { ...nodeFetchOptions, ...init });
  };
}
const fetch$1 = globalThis.fetch ? (...args) => globalThis.fetch(...args) : createNodeFetch();
const Headers$1 = globalThis.Headers || s$1;
const AbortController = globalThis.AbortController || i;
const ofetch = createFetch({ fetch: fetch$1, Headers: Headers$1, AbortController });
const $fetch = ofetch;

function wrapToPromise(value) {
  if (!value || typeof value.then !== "function") {
    return Promise.resolve(value);
  }
  return value;
}
function asyncCall(function_, ...arguments_) {
  try {
    return wrapToPromise(function_(...arguments_));
  } catch (error) {
    return Promise.reject(error);
  }
}
function isPrimitive(value) {
  const type = typeof value;
  return value === null || type !== "object" && type !== "function";
}
function isPureObject(value) {
  const proto = Object.getPrototypeOf(value);
  return !proto || proto.isPrototypeOf(Object);
}
function stringify(value) {
  if (isPrimitive(value)) {
    return String(value);
  }
  if (isPureObject(value) || Array.isArray(value)) {
    return JSON.stringify(value);
  }
  if (typeof value.toJSON === "function") {
    return stringify(value.toJSON());
  }
  throw new Error("[unstorage] Cannot stringify value!");
}
const BASE64_PREFIX = "base64:";
function serializeRaw(value) {
  if (typeof value === "string") {
    return value;
  }
  return BASE64_PREFIX + base64Encode(value);
}
function deserializeRaw(value) {
  if (typeof value !== "string") {
    return value;
  }
  if (!value.startsWith(BASE64_PREFIX)) {
    return value;
  }
  return base64Decode(value.slice(BASE64_PREFIX.length));
}
function base64Decode(input) {
  if (globalThis.Buffer) {
    return Buffer.from(input, "base64");
  }
  return Uint8Array.from(
    globalThis.atob(input),
    (c) => c.codePointAt(0)
  );
}
function base64Encode(input) {
  if (globalThis.Buffer) {
    return Buffer.from(input).toString("base64");
  }
  return globalThis.btoa(String.fromCodePoint(...input));
}

const storageKeyProperties = [
  "has",
  "hasItem",
  "get",
  "getItem",
  "getItemRaw",
  "set",
  "setItem",
  "setItemRaw",
  "del",
  "remove",
  "removeItem",
  "getMeta",
  "setMeta",
  "removeMeta",
  "getKeys",
  "clear",
  "mount",
  "unmount"
];
function prefixStorage(storage, base) {
  base = normalizeBaseKey(base);
  if (!base) {
    return storage;
  }
  const nsStorage = { ...storage };
  for (const property of storageKeyProperties) {
    nsStorage[property] = (key = "", ...args) => (
      // @ts-ignore
      storage[property](base + key, ...args)
    );
  }
  nsStorage.getKeys = (key = "", ...arguments_) => storage.getKeys(base + key, ...arguments_).then((keys) => keys.map((key2) => key2.slice(base.length)));
  nsStorage.keys = nsStorage.getKeys;
  nsStorage.getItems = async (items, commonOptions) => {
    const prefixedItems = items.map(
      (item) => typeof item === "string" ? base + item : { ...item, key: base + item.key }
    );
    const results = await storage.getItems(prefixedItems, commonOptions);
    return results.map((entry) => ({
      key: entry.key.slice(base.length),
      value: entry.value
    }));
  };
  nsStorage.setItems = async (items, commonOptions) => {
    const prefixedItems = items.map((item) => ({
      key: base + item.key,
      value: item.value,
      options: item.options
    }));
    return storage.setItems(prefixedItems, commonOptions);
  };
  return nsStorage;
}
function normalizeKey$1(key) {
  if (!key) {
    return "";
  }
  return key.split("?")[0]?.replace(/[/\\]/g, ":").replace(/:+/g, ":").replace(/^:|:$/g, "") || "";
}
function joinKeys(...keys) {
  return normalizeKey$1(keys.join(":"));
}
function normalizeBaseKey(base) {
  base = normalizeKey$1(base);
  return base ? base + ":" : "";
}
function filterKeyByDepth(key, depth) {
  if (depth === void 0) {
    return true;
  }
  let substrCount = 0;
  let index = key.indexOf(":");
  while (index > -1) {
    substrCount++;
    index = key.indexOf(":", index + 1);
  }
  return substrCount <= depth;
}
function filterKeyByBase(key, base) {
  if (base) {
    return key.startsWith(base) && key[key.length - 1] !== "$";
  }
  return key[key.length - 1] !== "$";
}

function defineDriver$1(factory) {
  return factory;
}

const DRIVER_NAME$1 = "memory";
const memory = defineDriver$1(() => {
  const data = /* @__PURE__ */ new Map();
  return {
    name: DRIVER_NAME$1,
    getInstance: () => data,
    hasItem(key) {
      return data.has(key);
    },
    getItem(key) {
      return data.get(key) ?? null;
    },
    getItemRaw(key) {
      return data.get(key) ?? null;
    },
    setItem(key, value) {
      data.set(key, value);
    },
    setItemRaw(key, value) {
      data.set(key, value);
    },
    removeItem(key) {
      data.delete(key);
    },
    getKeys() {
      return [...data.keys()];
    },
    clear() {
      data.clear();
    },
    dispose() {
      data.clear();
    }
  };
});

function createStorage(options = {}) {
  const context = {
    mounts: { "": options.driver || memory() },
    mountpoints: [""],
    watching: false,
    watchListeners: [],
    unwatch: {}
  };
  const getMount = (key) => {
    for (const base of context.mountpoints) {
      if (key.startsWith(base)) {
        return {
          base,
          relativeKey: key.slice(base.length),
          driver: context.mounts[base]
        };
      }
    }
    return {
      base: "",
      relativeKey: key,
      driver: context.mounts[""]
    };
  };
  const getMounts = (base, includeParent) => {
    return context.mountpoints.filter(
      (mountpoint) => mountpoint.startsWith(base) || includeParent && base.startsWith(mountpoint)
    ).map((mountpoint) => ({
      relativeBase: base.length > mountpoint.length ? base.slice(mountpoint.length) : void 0,
      mountpoint,
      driver: context.mounts[mountpoint]
    }));
  };
  const onChange = (event, key) => {
    if (!context.watching) {
      return;
    }
    key = normalizeKey$1(key);
    for (const listener of context.watchListeners) {
      listener(event, key);
    }
  };
  const startWatch = async () => {
    if (context.watching) {
      return;
    }
    context.watching = true;
    for (const mountpoint in context.mounts) {
      context.unwatch[mountpoint] = await watch(
        context.mounts[mountpoint],
        onChange,
        mountpoint
      );
    }
  };
  const stopWatch = async () => {
    if (!context.watching) {
      return;
    }
    for (const mountpoint in context.unwatch) {
      await context.unwatch[mountpoint]();
    }
    context.unwatch = {};
    context.watching = false;
  };
  const runBatch = (items, commonOptions, cb) => {
    const batches = /* @__PURE__ */ new Map();
    const getBatch = (mount) => {
      let batch = batches.get(mount.base);
      if (!batch) {
        batch = {
          driver: mount.driver,
          base: mount.base,
          items: []
        };
        batches.set(mount.base, batch);
      }
      return batch;
    };
    for (const item of items) {
      const isStringItem = typeof item === "string";
      const key = normalizeKey$1(isStringItem ? item : item.key);
      const value = isStringItem ? void 0 : item.value;
      const options2 = isStringItem || !item.options ? commonOptions : { ...commonOptions, ...item.options };
      const mount = getMount(key);
      getBatch(mount).items.push({
        key,
        value,
        relativeKey: mount.relativeKey,
        options: options2
      });
    }
    return Promise.all([...batches.values()].map((batch) => cb(batch))).then(
      (r) => r.flat()
    );
  };
  const storage = {
    // Item
    hasItem(key, opts = {}) {
      key = normalizeKey$1(key);
      const { relativeKey, driver } = getMount(key);
      return asyncCall(driver.hasItem, relativeKey, opts);
    },
    getItem(key, opts = {}) {
      key = normalizeKey$1(key);
      const { relativeKey, driver } = getMount(key);
      return asyncCall(driver.getItem, relativeKey, opts).then(
        (value) => destr(value)
      );
    },
    getItems(items, commonOptions = {}) {
      return runBatch(items, commonOptions, (batch) => {
        if (batch.driver.getItems) {
          return asyncCall(
            batch.driver.getItems,
            batch.items.map((item) => ({
              key: item.relativeKey,
              options: item.options
            })),
            commonOptions
          ).then(
            (r) => r.map((item) => ({
              key: joinKeys(batch.base, item.key),
              value: destr(item.value)
            }))
          );
        }
        return Promise.all(
          batch.items.map((item) => {
            return asyncCall(
              batch.driver.getItem,
              item.relativeKey,
              item.options
            ).then((value) => ({
              key: item.key,
              value: destr(value)
            }));
          })
        );
      });
    },
    getItemRaw(key, opts = {}) {
      key = normalizeKey$1(key);
      const { relativeKey, driver } = getMount(key);
      if (driver.getItemRaw) {
        return asyncCall(driver.getItemRaw, relativeKey, opts);
      }
      return asyncCall(driver.getItem, relativeKey, opts).then(
        (value) => deserializeRaw(value)
      );
    },
    async setItem(key, value, opts = {}) {
      if (value === void 0) {
        return storage.removeItem(key);
      }
      key = normalizeKey$1(key);
      const { relativeKey, driver } = getMount(key);
      if (!driver.setItem) {
        return;
      }
      await asyncCall(driver.setItem, relativeKey, stringify(value), opts);
      if (!driver.watch) {
        onChange("update", key);
      }
    },
    async setItems(items, commonOptions) {
      await runBatch(items, commonOptions, async (batch) => {
        if (batch.driver.setItems) {
          return asyncCall(
            batch.driver.setItems,
            batch.items.map((item) => ({
              key: item.relativeKey,
              value: stringify(item.value),
              options: item.options
            })),
            commonOptions
          );
        }
        if (!batch.driver.setItem) {
          return;
        }
        await Promise.all(
          batch.items.map((item) => {
            return asyncCall(
              batch.driver.setItem,
              item.relativeKey,
              stringify(item.value),
              item.options
            );
          })
        );
      });
    },
    async setItemRaw(key, value, opts = {}) {
      if (value === void 0) {
        return storage.removeItem(key, opts);
      }
      key = normalizeKey$1(key);
      const { relativeKey, driver } = getMount(key);
      if (driver.setItemRaw) {
        await asyncCall(driver.setItemRaw, relativeKey, value, opts);
      } else if (driver.setItem) {
        await asyncCall(driver.setItem, relativeKey, serializeRaw(value), opts);
      } else {
        return;
      }
      if (!driver.watch) {
        onChange("update", key);
      }
    },
    async removeItem(key, opts = {}) {
      if (typeof opts === "boolean") {
        opts = { removeMeta: opts };
      }
      key = normalizeKey$1(key);
      const { relativeKey, driver } = getMount(key);
      if (!driver.removeItem) {
        return;
      }
      await asyncCall(driver.removeItem, relativeKey, opts);
      if (opts.removeMeta || opts.removeMata) {
        await asyncCall(driver.removeItem, relativeKey + "$", opts);
      }
      if (!driver.watch) {
        onChange("remove", key);
      }
    },
    // Meta
    async getMeta(key, opts = {}) {
      if (typeof opts === "boolean") {
        opts = { nativeOnly: opts };
      }
      key = normalizeKey$1(key);
      const { relativeKey, driver } = getMount(key);
      const meta = /* @__PURE__ */ Object.create(null);
      if (driver.getMeta) {
        Object.assign(meta, await asyncCall(driver.getMeta, relativeKey, opts));
      }
      if (!opts.nativeOnly) {
        const value = await asyncCall(
          driver.getItem,
          relativeKey + "$",
          opts
        ).then((value_) => destr(value_));
        if (value && typeof value === "object") {
          if (typeof value.atime === "string") {
            value.atime = new Date(value.atime);
          }
          if (typeof value.mtime === "string") {
            value.mtime = new Date(value.mtime);
          }
          Object.assign(meta, value);
        }
      }
      return meta;
    },
    setMeta(key, value, opts = {}) {
      return this.setItem(key + "$", value, opts);
    },
    removeMeta(key, opts = {}) {
      return this.removeItem(key + "$", opts);
    },
    // Keys
    async getKeys(base, opts = {}) {
      base = normalizeBaseKey(base);
      const mounts = getMounts(base, true);
      let maskedMounts = [];
      const allKeys = [];
      let allMountsSupportMaxDepth = true;
      for (const mount of mounts) {
        if (!mount.driver.flags?.maxDepth) {
          allMountsSupportMaxDepth = false;
        }
        const rawKeys = await asyncCall(
          mount.driver.getKeys,
          mount.relativeBase,
          opts
        );
        for (const key of rawKeys) {
          const fullKey = mount.mountpoint + normalizeKey$1(key);
          if (!maskedMounts.some((p) => fullKey.startsWith(p))) {
            allKeys.push(fullKey);
          }
        }
        maskedMounts = [
          mount.mountpoint,
          ...maskedMounts.filter((p) => !p.startsWith(mount.mountpoint))
        ];
      }
      const shouldFilterByDepth = opts.maxDepth !== void 0 && !allMountsSupportMaxDepth;
      return allKeys.filter(
        (key) => (!shouldFilterByDepth || filterKeyByDepth(key, opts.maxDepth)) && filterKeyByBase(key, base)
      );
    },
    // Utils
    async clear(base, opts = {}) {
      base = normalizeBaseKey(base);
      await Promise.all(
        getMounts(base, false).map(async (m) => {
          if (m.driver.clear) {
            return asyncCall(m.driver.clear, m.relativeBase, opts);
          }
          if (m.driver.removeItem) {
            const keys = await m.driver.getKeys(m.relativeBase || "", opts);
            return Promise.all(
              keys.map((key) => m.driver.removeItem(key, opts))
            );
          }
        })
      );
    },
    async dispose() {
      await Promise.all(
        Object.values(context.mounts).map((driver) => dispose(driver))
      );
    },
    async watch(callback) {
      await startWatch();
      context.watchListeners.push(callback);
      return async () => {
        context.watchListeners = context.watchListeners.filter(
          (listener) => listener !== callback
        );
        if (context.watchListeners.length === 0) {
          await stopWatch();
        }
      };
    },
    async unwatch() {
      context.watchListeners = [];
      await stopWatch();
    },
    // Mount
    mount(base, driver) {
      base = normalizeBaseKey(base);
      if (base && context.mounts[base]) {
        throw new Error(`already mounted at ${base}`);
      }
      if (base) {
        context.mountpoints.push(base);
        context.mountpoints.sort((a, b) => b.length - a.length);
      }
      context.mounts[base] = driver;
      if (context.watching) {
        Promise.resolve(watch(driver, onChange, base)).then((unwatcher) => {
          context.unwatch[base] = unwatcher;
        }).catch(console.error);
      }
      return storage;
    },
    async unmount(base, _dispose = true) {
      base = normalizeBaseKey(base);
      if (!base || !context.mounts[base]) {
        return;
      }
      if (context.watching && base in context.unwatch) {
        context.unwatch[base]?.();
        delete context.unwatch[base];
      }
      if (_dispose) {
        await dispose(context.mounts[base]);
      }
      context.mountpoints = context.mountpoints.filter((key) => key !== base);
      delete context.mounts[base];
    },
    getMount(key = "") {
      key = normalizeKey$1(key) + ":";
      const m = getMount(key);
      return {
        driver: m.driver,
        base: m.base
      };
    },
    getMounts(base = "", opts = {}) {
      base = normalizeKey$1(base);
      const mounts = getMounts(base, opts.parents);
      return mounts.map((m) => ({
        driver: m.driver,
        base: m.mountpoint
      }));
    },
    // Aliases
    keys: (base, opts = {}) => storage.getKeys(base, opts),
    get: (key, opts = {}) => storage.getItem(key, opts),
    set: (key, value, opts = {}) => storage.setItem(key, value, opts),
    has: (key, opts = {}) => storage.hasItem(key, opts),
    del: (key, opts = {}) => storage.removeItem(key, opts),
    remove: (key, opts = {}) => storage.removeItem(key, opts)
  };
  return storage;
}
function watch(driver, onChange, base) {
  return driver.watch ? driver.watch((event, key) => onChange(event, base + key)) : () => {
  };
}
async function dispose(driver) {
  if (typeof driver.dispose === "function") {
    await asyncCall(driver.dispose);
  }
}

const _assets = {

};

const normalizeKey = function normalizeKey(key) {
  if (!key) {
    return "";
  }
  return key.split("?")[0]?.replace(/[/\\]/g, ":").replace(/:+/g, ":").replace(/^:|:$/g, "") || "";
};

const assets = {
  getKeys() {
    return Promise.resolve(Object.keys(_assets))
  },
  hasItem (id) {
    id = normalizeKey(id);
    return Promise.resolve(id in _assets)
  },
  getItem (id) {
    id = normalizeKey(id);
    return Promise.resolve(_assets[id] ? _assets[id].import() : null)
  },
  getMeta (id) {
    id = normalizeKey(id);
    return Promise.resolve(_assets[id] ? _assets[id].meta : {})
  }
};

function defineDriver(factory) {
  return factory;
}
function createError(driver, message, opts) {
  const err = new Error(`[unstorage] [${driver}] ${message}`, opts);
  if (Error.captureStackTrace) {
    Error.captureStackTrace(err, createError);
  }
  return err;
}
function createRequiredError(driver, name) {
  if (Array.isArray(name)) {
    return createError(
      driver,
      `Missing some of the required options ${name.map((n) => "`" + n + "`").join(", ")}`
    );
  }
  return createError(driver, `Missing required option \`${name}\`.`);
}

function ignoreNotfound(err) {
  return err.code === "ENOENT" || err.code === "EISDIR" ? null : err;
}
function ignoreExists(err) {
  return err.code === "EEXIST" ? null : err;
}
async function writeFile(path, data, encoding) {
  await ensuredir(dirname(path));
  return promises$1.writeFile(path, data, encoding);
}
function readFile(path, encoding) {
  return promises$1.readFile(path, encoding).catch(ignoreNotfound);
}
function unlink(path) {
  return promises$1.unlink(path).catch(ignoreNotfound);
}
function readdir(dir) {
  return promises$1.readdir(dir, { withFileTypes: true }).catch(ignoreNotfound).then((r) => r || []);
}
async function ensuredir(dir) {
  if (existsSync(dir)) {
    return;
  }
  await ensuredir(dirname(dir)).catch(ignoreExists);
  await promises$1.mkdir(dir).catch(ignoreExists);
}
async function readdirRecursive(dir, ignore, maxDepth) {
  if (ignore && ignore(dir)) {
    return [];
  }
  const entries = await readdir(dir);
  const files = [];
  await Promise.all(
    entries.map(async (entry) => {
      const entryPath = resolve$1(dir, entry.name);
      if (entry.isDirectory()) {
        if (maxDepth === void 0 || maxDepth > 0) {
          const dirFiles = await readdirRecursive(
            entryPath,
            ignore,
            maxDepth === void 0 ? void 0 : maxDepth - 1
          );
          files.push(...dirFiles.map((f) => entry.name + "/" + f));
        }
      } else {
        if (!(ignore && ignore(entry.name))) {
          files.push(entry.name);
        }
      }
    })
  );
  return files;
}
async function rmRecursive(dir) {
  const entries = await readdir(dir);
  await Promise.all(
    entries.map((entry) => {
      const entryPath = resolve$1(dir, entry.name);
      if (entry.isDirectory()) {
        return rmRecursive(entryPath).then(() => promises$1.rmdir(entryPath));
      } else {
        return promises$1.unlink(entryPath);
      }
    })
  );
}

const PATH_TRAVERSE_RE = /\.\.:|\.\.$/;
const DRIVER_NAME = "fs-lite";
const unstorage_47drivers_47fs_45lite = defineDriver((opts = {}) => {
  if (!opts.base) {
    throw createRequiredError(DRIVER_NAME, "base");
  }
  opts.base = resolve$1(opts.base);
  const r = (key) => {
    if (PATH_TRAVERSE_RE.test(key)) {
      throw createError(
        DRIVER_NAME,
        `Invalid key: ${JSON.stringify(key)}. It should not contain .. segments`
      );
    }
    const resolved = join(opts.base, key.replace(/:/g, "/"));
    return resolved;
  };
  return {
    name: DRIVER_NAME,
    options: opts,
    flags: {
      maxDepth: true
    },
    hasItem(key) {
      return existsSync(r(key));
    },
    getItem(key) {
      return readFile(r(key), "utf8");
    },
    getItemRaw(key) {
      return readFile(r(key));
    },
    async getMeta(key) {
      const { atime, mtime, size, birthtime, ctime } = await promises$1.stat(r(key)).catch(() => ({}));
      return { atime, mtime, size, birthtime, ctime };
    },
    setItem(key, value) {
      if (opts.readOnly) {
        return;
      }
      return writeFile(r(key), value, "utf8");
    },
    setItemRaw(key, value) {
      if (opts.readOnly) {
        return;
      }
      return writeFile(r(key), value);
    },
    removeItem(key) {
      if (opts.readOnly) {
        return;
      }
      return unlink(r(key));
    },
    getKeys(_base, topts) {
      return readdirRecursive(r("."), opts.ignore, topts?.maxDepth);
    },
    async clear() {
      if (opts.readOnly || opts.noClear) {
        return;
      }
      await rmRecursive(r("."));
    }
  };
});

const storage = createStorage({});

storage.mount('/assets', assets);

storage.mount('data', unstorage_47drivers_47fs_45lite({"driver":"fsLite","base":"./.data/kv"}));

function useStorage(base = "") {
  return base ? prefixStorage(storage, base) : storage;
}

const e=globalThis.process?.getBuiltinModule?.("crypto")?.hash,r="sha256",s="base64url";function digest(t){if(e)return e(r,t,s);const o=createHash(r).update(t);return globalThis.process?.versions?.webcontainer?o.digest().toString(s):o.digest(s)}

const Hasher = /* @__PURE__ */ (() => {
  class Hasher2 {
    buff = "";
    #context = /* @__PURE__ */ new Map();
    write(str) {
      this.buff += str;
    }
    dispatch(value) {
      const type = value === null ? "null" : typeof value;
      return this[type](value);
    }
    object(object) {
      if (object && typeof object.toJSON === "function") {
        return this.object(object.toJSON());
      }
      const objString = Object.prototype.toString.call(object);
      let objType = "";
      const objectLength = objString.length;
      objType = objectLength < 10 ? "unknown:[" + objString + "]" : objString.slice(8, objectLength - 1);
      objType = objType.toLowerCase();
      let objectNumber = null;
      if ((objectNumber = this.#context.get(object)) === void 0) {
        this.#context.set(object, this.#context.size);
      } else {
        return this.dispatch("[CIRCULAR:" + objectNumber + "]");
      }
      if (typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(object)) {
        this.write("buffer:");
        return this.write(object.toString("utf8"));
      }
      if (objType !== "object" && objType !== "function" && objType !== "asyncfunction") {
        if (this[objType]) {
          this[objType](object);
        } else {
          this.unknown(object, objType);
        }
      } else {
        const keys = Object.keys(object).sort();
        const extraKeys = [];
        this.write("object:" + (keys.length + extraKeys.length) + ":");
        const dispatchForKey = (key) => {
          this.dispatch(key);
          this.write(":");
          this.dispatch(object[key]);
          this.write(",");
        };
        for (const key of keys) {
          dispatchForKey(key);
        }
        for (const key of extraKeys) {
          dispatchForKey(key);
        }
      }
    }
    array(arr, unordered) {
      unordered = unordered === void 0 ? false : unordered;
      this.write("array:" + arr.length + ":");
      if (!unordered || arr.length <= 1) {
        for (const entry of arr) {
          this.dispatch(entry);
        }
        return;
      }
      const contextAdditions = /* @__PURE__ */ new Map();
      const entries = arr.map((entry) => {
        const hasher = new Hasher2();
        hasher.dispatch(entry);
        for (const [key, value] of hasher.#context) {
          contextAdditions.set(key, value);
        }
        return hasher.toString();
      });
      this.#context = contextAdditions;
      entries.sort();
      return this.array(entries, false);
    }
    date(date) {
      return this.write("date:" + date.toJSON());
    }
    symbol(sym) {
      return this.write("symbol:" + sym.toString());
    }
    unknown(value, type) {
      this.write(type);
      if (!value) {
        return;
      }
      this.write(":");
      if (value && typeof value.entries === "function") {
        return this.array(
          [...value.entries()],
          true
          /* ordered */
        );
      }
    }
    error(err) {
      return this.write("error:" + err.toString());
    }
    boolean(bool) {
      return this.write("bool:" + bool);
    }
    string(string) {
      this.write("string:" + string.length + ":");
      this.write(string);
    }
    function(fn) {
      this.write("fn:");
      if (isNativeFunction(fn)) {
        this.dispatch("[native]");
      } else {
        this.dispatch(fn.toString());
      }
    }
    number(number) {
      return this.write("number:" + number);
    }
    null() {
      return this.write("Null");
    }
    undefined() {
      return this.write("Undefined");
    }
    regexp(regex) {
      return this.write("regex:" + regex.toString());
    }
    arraybuffer(arr) {
      this.write("arraybuffer:");
      return this.dispatch(new Uint8Array(arr));
    }
    url(url) {
      return this.write("url:" + url.toString());
    }
    map(map) {
      this.write("map:");
      const arr = [...map];
      return this.array(arr, false);
    }
    set(set) {
      this.write("set:");
      const arr = [...set];
      return this.array(arr, false);
    }
    bigint(number) {
      return this.write("bigint:" + number.toString());
    }
  }
  for (const type of [
    "uint8array",
    "uint8clampedarray",
    "unt8array",
    "uint16array",
    "unt16array",
    "uint32array",
    "unt32array",
    "float32array",
    "float64array"
  ]) {
    Hasher2.prototype[type] = function(arr) {
      this.write(type + ":");
      return this.array([...arr], false);
    };
  }
  function isNativeFunction(f) {
    if (typeof f !== "function") {
      return false;
    }
    return Function.prototype.toString.call(f).slice(
      -15
      /* "[native code] }".length */
    ) === "[native code] }";
  }
  return Hasher2;
})();
function serialize(object) {
  const hasher = new Hasher();
  hasher.dispatch(object);
  return hasher.buff;
}
function hash(value) {
  return digest(typeof value === "string" ? value : serialize(value)).replace(/[-_]/g, "").slice(0, 10);
}

function defaultCacheOptions() {
  return {
    name: "_",
    base: "/cache",
    swr: true,
    maxAge: 1
  };
}
function defineCachedFunction(fn, opts = {}) {
  opts = { ...defaultCacheOptions(), ...opts };
  const pending = {};
  const group = opts.group || "nitro/functions";
  const name = opts.name || fn.name || "_";
  const integrity = opts.integrity || hash([fn, opts]);
  const validate = opts.validate || ((entry) => entry.value !== void 0);
  async function get(key, resolver, shouldInvalidateCache, event) {
    const cacheKey = [opts.base, group, name, key + ".json"].filter(Boolean).join(":").replace(/:\/$/, ":index");
    let entry = await useStorage().getItem(cacheKey).catch((error) => {
      console.error(`[cache] Cache read error.`, error);
      useNitroApp().captureError(error, { event, tags: ["cache"] });
    }) || {};
    if (typeof entry !== "object") {
      entry = {};
      const error = new Error("Malformed data read from cache.");
      console.error("[cache]", error);
      useNitroApp().captureError(error, { event, tags: ["cache"] });
    }
    const ttl = (opts.maxAge ?? 0) * 1e3;
    if (ttl) {
      entry.expires = Date.now() + ttl;
    }
    const expired = shouldInvalidateCache || entry.integrity !== integrity || ttl && Date.now() - (entry.mtime || 0) > ttl || validate(entry) === false;
    const _resolve = async () => {
      const isPending = pending[key];
      if (!isPending) {
        if (entry.value !== void 0 && (opts.staleMaxAge || 0) >= 0 && opts.swr === false) {
          entry.value = void 0;
          entry.integrity = void 0;
          entry.mtime = void 0;
          entry.expires = void 0;
        }
        pending[key] = Promise.resolve(resolver());
      }
      try {
        entry.value = await pending[key];
      } catch (error) {
        if (!isPending) {
          delete pending[key];
        }
        throw error;
      }
      if (!isPending) {
        entry.mtime = Date.now();
        entry.integrity = integrity;
        delete pending[key];
        if (validate(entry) !== false) {
          let setOpts;
          if (opts.maxAge && !opts.swr) {
            setOpts = { ttl: opts.maxAge };
          }
          const promise = useStorage().setItem(cacheKey, entry, setOpts).catch((error) => {
            console.error(`[cache] Cache write error.`, error);
            useNitroApp().captureError(error, { event, tags: ["cache"] });
          });
          if (event?.waitUntil) {
            event.waitUntil(promise);
          }
        }
      }
    };
    const _resolvePromise = expired ? _resolve() : Promise.resolve();
    if (entry.value === void 0) {
      await _resolvePromise;
    } else if (expired && event && event.waitUntil) {
      event.waitUntil(_resolvePromise);
    }
    if (opts.swr && validate(entry) !== false) {
      _resolvePromise.catch((error) => {
        console.error(`[cache] SWR handler error.`, error);
        useNitroApp().captureError(error, { event, tags: ["cache"] });
      });
      return entry;
    }
    return _resolvePromise.then(() => entry);
  }
  return async (...args) => {
    const shouldBypassCache = await opts.shouldBypassCache?.(...args);
    if (shouldBypassCache) {
      return fn(...args);
    }
    const key = await (opts.getKey || getKey)(...args);
    const shouldInvalidateCache = await opts.shouldInvalidateCache?.(...args);
    const entry = await get(
      key,
      () => fn(...args),
      shouldInvalidateCache,
      args[0] && isEvent(args[0]) ? args[0] : void 0
    );
    let value = entry.value;
    if (opts.transform) {
      value = await opts.transform(entry, ...args) || value;
    }
    return value;
  };
}
function cachedFunction(fn, opts = {}) {
  return defineCachedFunction(fn, opts);
}
function getKey(...args) {
  return args.length > 0 ? hash(args) : "";
}
function escapeKey(key) {
  return String(key).replace(/\W/g, "");
}
function defineCachedEventHandler(handler, opts = defaultCacheOptions()) {
  const variableHeaderNames = (opts.varies || []).filter(Boolean).map((h) => h.toLowerCase()).sort();
  const _opts = {
    ...opts,
    getKey: async (event) => {
      const customKey = await opts.getKey?.(event);
      if (customKey) {
        return escapeKey(customKey);
      }
      const _path = event.node.req.originalUrl || event.node.req.url || event.path;
      let _pathname;
      try {
        _pathname = escapeKey(decodeURI(parseURL(_path).pathname)).slice(0, 16) || "index";
      } catch {
        _pathname = "-";
      }
      const _hashedPath = `${_pathname}.${hash(_path)}`;
      const _headers = variableHeaderNames.map((header) => [header, event.node.req.headers[header]]).map(([name, value]) => `${escapeKey(name)}.${hash(value)}`);
      return [_hashedPath, ..._headers].join(":");
    },
    validate: (entry) => {
      if (!entry.value) {
        return false;
      }
      if (entry.value.code >= 400) {
        return false;
      }
      if (entry.value.body === void 0) {
        return false;
      }
      if (entry.value.headers.etag === "undefined" || entry.value.headers["last-modified"] === "undefined") {
        return false;
      }
      return true;
    },
    group: opts.group || "nitro/handlers",
    integrity: opts.integrity || hash([handler, opts])
  };
  const _cachedHandler = cachedFunction(
    async (incomingEvent) => {
      const variableHeaders = {};
      for (const header of variableHeaderNames) {
        const value = incomingEvent.node.req.headers[header];
        if (value !== void 0) {
          variableHeaders[header] = value;
        }
      }
      const reqProxy = cloneWithProxy(incomingEvent.node.req, {
        headers: variableHeaders
      });
      const resHeaders = {};
      let _resSendBody;
      const resProxy = cloneWithProxy(incomingEvent.node.res, {
        statusCode: 200,
        writableEnded: false,
        writableFinished: false,
        headersSent: false,
        closed: false,
        getHeader(name) {
          return resHeaders[name];
        },
        setHeader(name, value) {
          resHeaders[name] = value;
          return this;
        },
        getHeaderNames() {
          return Object.keys(resHeaders);
        },
        hasHeader(name) {
          return name in resHeaders;
        },
        removeHeader(name) {
          delete resHeaders[name];
        },
        getHeaders() {
          return resHeaders;
        },
        end(chunk, arg2, arg3) {
          if (typeof chunk === "string") {
            _resSendBody = chunk;
          }
          if (typeof arg2 === "function") {
            arg2();
          }
          if (typeof arg3 === "function") {
            arg3();
          }
          return this;
        },
        write(chunk, arg2, arg3) {
          if (typeof chunk === "string") {
            _resSendBody = chunk;
          }
          if (typeof arg2 === "function") {
            arg2(void 0);
          }
          if (typeof arg3 === "function") {
            arg3();
          }
          return true;
        },
        writeHead(statusCode, headers2) {
          this.statusCode = statusCode;
          if (headers2) {
            if (Array.isArray(headers2) || typeof headers2 === "string") {
              throw new TypeError("Raw headers  is not supported.");
            }
            for (const header in headers2) {
              const value = headers2[header];
              if (value !== void 0) {
                this.setHeader(
                  header,
                  value
                );
              }
            }
          }
          return this;
        }
      });
      const event = createEvent(reqProxy, resProxy);
      event.fetch = (url, fetchOptions) => fetchWithEvent(event, url, fetchOptions, {
        fetch: useNitroApp().localFetch
      });
      event.$fetch = (url, fetchOptions) => fetchWithEvent(event, url, fetchOptions, {
        fetch: globalThis.$fetch
      });
      event.waitUntil = incomingEvent.waitUntil;
      event.context = incomingEvent.context;
      event.context.cache = {
        options: _opts
      };
      const body = await handler(event) || _resSendBody;
      const headers = event.node.res.getHeaders();
      headers.etag = String(
        headers.Etag || headers.etag || `W/"${hash(body)}"`
      );
      headers["last-modified"] = String(
        headers["Last-Modified"] || headers["last-modified"] || (/* @__PURE__ */ new Date()).toUTCString()
      );
      const cacheControl = [];
      if (opts.swr) {
        if (opts.maxAge) {
          cacheControl.push(`s-maxage=${opts.maxAge}`);
        }
        if (opts.staleMaxAge) {
          cacheControl.push(`stale-while-revalidate=${opts.staleMaxAge}`);
        } else {
          cacheControl.push("stale-while-revalidate");
        }
      } else if (opts.maxAge) {
        cacheControl.push(`max-age=${opts.maxAge}`);
      }
      if (cacheControl.length > 0) {
        headers["cache-control"] = cacheControl.join(", ");
      }
      const cacheEntry = {
        code: event.node.res.statusCode,
        headers,
        body
      };
      return cacheEntry;
    },
    _opts
  );
  return defineEventHandler(async (event) => {
    if (opts.headersOnly) {
      if (handleCacheHeaders(event, { maxAge: opts.maxAge })) {
        return;
      }
      return handler(event);
    }
    const response = await _cachedHandler(
      event
    );
    if (event.node.res.headersSent || event.node.res.writableEnded) {
      return response.body;
    }
    if (handleCacheHeaders(event, {
      modifiedTime: new Date(response.headers["last-modified"]),
      etag: response.headers.etag,
      maxAge: opts.maxAge
    })) {
      return;
    }
    event.node.res.statusCode = response.code;
    for (const name in response.headers) {
      const value = response.headers[name];
      if (name === "set-cookie") {
        event.node.res.appendHeader(
          name,
          splitCookiesString(value)
        );
      } else {
        if (value !== void 0) {
          event.node.res.setHeader(name, value);
        }
      }
    }
    return response.body;
  });
}
function cloneWithProxy(obj, overrides) {
  return new Proxy(obj, {
    get(target, property, receiver) {
      if (property in overrides) {
        return overrides[property];
      }
      return Reflect.get(target, property, receiver);
    },
    set(target, property, value, receiver) {
      if (property in overrides) {
        overrides[property] = value;
        return true;
      }
      return Reflect.set(target, property, value, receiver);
    }
  });
}
const cachedEventHandler = defineCachedEventHandler;

function klona(x) {
	if (typeof x !== 'object') return x;

	var k, tmp, str=Object.prototype.toString.call(x);

	if (str === '[object Object]') {
		if (x.constructor !== Object && typeof x.constructor === 'function') {
			tmp = new x.constructor();
			for (k in x) {
				if (x.hasOwnProperty(k) && tmp[k] !== x[k]) {
					tmp[k] = klona(x[k]);
				}
			}
		} else {
			tmp = {}; // null
			for (k in x) {
				if (k === '__proto__') {
					Object.defineProperty(tmp, k, {
						value: klona(x[k]),
						configurable: true,
						enumerable: true,
						writable: true,
					});
				} else {
					tmp[k] = klona(x[k]);
				}
			}
		}
		return tmp;
	}

	if (str === '[object Array]') {
		k = x.length;
		for (tmp=Array(k); k--;) {
			tmp[k] = klona(x[k]);
		}
		return tmp;
	}

	if (str === '[object Set]') {
		tmp = new Set;
		x.forEach(function (val) {
			tmp.add(klona(val));
		});
		return tmp;
	}

	if (str === '[object Map]') {
		tmp = new Map;
		x.forEach(function (val, key) {
			tmp.set(klona(key), klona(val));
		});
		return tmp;
	}

	if (str === '[object Date]') {
		return new Date(+x);
	}

	if (str === '[object RegExp]') {
		tmp = new RegExp(x.source, x.flags);
		tmp.lastIndex = x.lastIndex;
		return tmp;
	}

	if (str === '[object DataView]') {
		return new x.constructor( klona(x.buffer) );
	}

	if (str === '[object ArrayBuffer]') {
		return x.slice(0);
	}

	// ArrayBuffer.isView(x)
	// ~> `new` bcuz `Buffer.slice` => ref
	if (str.slice(-6) === 'Array]') {
		return new x.constructor(x);
	}

	return x;
}

const inlineAppConfig = {
  "nuxt": {}
};



const appConfig = defuFn(inlineAppConfig);

const NUMBER_CHAR_RE = /\d/;
const STR_SPLITTERS = ["-", "_", "/", "."];
function isUppercase(char = "") {
  if (NUMBER_CHAR_RE.test(char)) {
    return void 0;
  }
  return char !== char.toLowerCase();
}
function splitByCase(str, separators) {
  const splitters = STR_SPLITTERS;
  const parts = [];
  if (!str || typeof str !== "string") {
    return parts;
  }
  let buff = "";
  let previousUpper;
  let previousSplitter;
  for (const char of str) {
    const isSplitter = splitters.includes(char);
    if (isSplitter === true) {
      parts.push(buff);
      buff = "";
      previousUpper = void 0;
      continue;
    }
    const isUpper = isUppercase(char);
    if (previousSplitter === false) {
      if (previousUpper === false && isUpper === true) {
        parts.push(buff);
        buff = char;
        previousUpper = isUpper;
        continue;
      }
      if (previousUpper === true && isUpper === false && buff.length > 1) {
        const lastChar = buff.at(-1);
        parts.push(buff.slice(0, Math.max(0, buff.length - 1)));
        buff = lastChar + char;
        previousUpper = isUpper;
        continue;
      }
    }
    buff += char;
    previousUpper = isUpper;
    previousSplitter = isSplitter;
  }
  parts.push(buff);
  return parts;
}
function kebabCase(str, joiner) {
  return str ? (Array.isArray(str) ? str : splitByCase(str)).map((p) => p.toLowerCase()).join(joiner) : "";
}
function snakeCase(str) {
  return kebabCase(str || "", "_");
}

function getEnv(key, opts) {
  const envKey = snakeCase(key).toUpperCase();
  return destr(
    process.env[opts.prefix + envKey] ?? process.env[opts.altPrefix + envKey]
  );
}
function _isObject(input) {
  return typeof input === "object" && !Array.isArray(input);
}
function applyEnv(obj, opts, parentKey = "") {
  for (const key in obj) {
    const subKey = parentKey ? `${parentKey}_${key}` : key;
    const envValue = getEnv(subKey, opts);
    if (_isObject(obj[key])) {
      if (_isObject(envValue)) {
        obj[key] = { ...obj[key], ...envValue };
        applyEnv(obj[key], opts, subKey);
      } else if (envValue === void 0) {
        applyEnv(obj[key], opts, subKey);
      } else {
        obj[key] = envValue ?? obj[key];
      }
    } else {
      obj[key] = envValue ?? obj[key];
    }
    if (opts.envExpansion && typeof obj[key] === "string") {
      obj[key] = _expandFromEnv(obj[key]);
    }
  }
  return obj;
}
const envExpandRx = /\{\{([^{}]*)\}\}/g;
function _expandFromEnv(value) {
  return value.replace(envExpandRx, (match, key) => {
    return process.env[key] || match;
  });
}

const _inlineRuntimeConfig = {
  "app": {
    "baseURL": "/",
    "buildId": "0f045aff-3e49-49ce-9392-2cfaf8acf3c5",
    "buildAssetsDir": "/_nuxt/",
    "cdnURL": ""
  },
  "nitro": {
    "envPrefix": "NUXT_",
    "routeRules": {
      "/__nuxt_error": {
        "cache": false,
        "isr": false
      },
      "/_nuxt/builds/meta/**": {
        "headers": {
          "cache-control": "public, max-age=31536000, immutable"
        }
      },
      "/_nuxt/builds/**": {
        "headers": {
          "cache-control": "public, max-age=1, immutable"
        }
      },
      "/_nuxt/**": {
        "headers": {
          "cache-control": "public, max-age=31536000, immutable"
        }
      }
    }
  },
  "public": {},
  "jwtSecret": "",
  "databaseUrl": "postgresql://neondb_owner:npg_Qk3y4hDzxJBb@ep-cold-surf-a1b6ly7y-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require",
  "ipx": {
    "baseURL": "/_ipx",
    "alias": {},
    "fs": {
      "dir": "../../static"
    },
    "http": {
      "domains": []
    }
  }
};
const envOptions = {
  prefix: "NITRO_",
  altPrefix: _inlineRuntimeConfig.nitro.envPrefix ?? process.env.NITRO_ENV_PREFIX ?? "_",
  envExpansion: _inlineRuntimeConfig.nitro.envExpansion ?? process.env.NITRO_ENV_EXPANSION ?? false
};
const _sharedRuntimeConfig = _deepFreeze(
  applyEnv(klona(_inlineRuntimeConfig), envOptions)
);
function useRuntimeConfig(event) {
  if (!event) {
    return _sharedRuntimeConfig;
  }
  if (event.context.nitro.runtimeConfig) {
    return event.context.nitro.runtimeConfig;
  }
  const runtimeConfig = klona(_inlineRuntimeConfig);
  applyEnv(runtimeConfig, envOptions);
  event.context.nitro.runtimeConfig = runtimeConfig;
  return runtimeConfig;
}
_deepFreeze(klona(appConfig));
function _deepFreeze(object) {
  const propNames = Object.getOwnPropertyNames(object);
  for (const name of propNames) {
    const value = object[name];
    if (value && typeof value === "object") {
      _deepFreeze(value);
    }
  }
  return Object.freeze(object);
}
new Proxy(/* @__PURE__ */ Object.create(null), {
  get: (_, prop) => {
    console.warn(
      "Please use `useRuntimeConfig()` instead of accessing config directly."
    );
    const runtimeConfig = useRuntimeConfig();
    if (prop in runtimeConfig) {
      return runtimeConfig[prop];
    }
    return void 0;
  }
});

function createContext(opts = {}) {
  let currentInstance;
  let isSingleton = false;
  const checkConflict = (instance) => {
    if (currentInstance && currentInstance !== instance) {
      throw new Error("Context conflict");
    }
  };
  let als;
  if (opts.asyncContext) {
    const _AsyncLocalStorage = opts.AsyncLocalStorage || globalThis.AsyncLocalStorage;
    if (_AsyncLocalStorage) {
      als = new _AsyncLocalStorage();
    } else {
      console.warn("[unctx] `AsyncLocalStorage` is not provided.");
    }
  }
  const _getCurrentInstance = () => {
    if (als) {
      const instance = als.getStore();
      if (instance !== void 0) {
        return instance;
      }
    }
    return currentInstance;
  };
  return {
    use: () => {
      const _instance = _getCurrentInstance();
      if (_instance === void 0) {
        throw new Error("Context is not available");
      }
      return _instance;
    },
    tryUse: () => {
      return _getCurrentInstance();
    },
    set: (instance, replace) => {
      if (!replace) {
        checkConflict(instance);
      }
      currentInstance = instance;
      isSingleton = true;
    },
    unset: () => {
      currentInstance = void 0;
      isSingleton = false;
    },
    call: (instance, callback) => {
      checkConflict(instance);
      currentInstance = instance;
      try {
        return als ? als.run(instance, callback) : callback();
      } finally {
        if (!isSingleton) {
          currentInstance = void 0;
        }
      }
    },
    async callAsync(instance, callback) {
      currentInstance = instance;
      const onRestore = () => {
        currentInstance = instance;
      };
      const onLeave = () => currentInstance === instance ? onRestore : void 0;
      asyncHandlers.add(onLeave);
      try {
        const r = als ? als.run(instance, callback) : callback();
        if (!isSingleton) {
          currentInstance = void 0;
        }
        return await r;
      } finally {
        asyncHandlers.delete(onLeave);
      }
    }
  };
}
function createNamespace(defaultOpts = {}) {
  const contexts = {};
  return {
    get(key, opts = {}) {
      if (!contexts[key]) {
        contexts[key] = createContext({ ...defaultOpts, ...opts });
      }
      return contexts[key];
    }
  };
}
const _globalThis = typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : typeof global !== "undefined" ? global : {};
const globalKey = "__unctx__";
const defaultNamespace = _globalThis[globalKey] || (_globalThis[globalKey] = createNamespace());
const getContext = (key, opts = {}) => defaultNamespace.get(key, opts);
const asyncHandlersKey = "__unctx_async_handlers__";
const asyncHandlers = _globalThis[asyncHandlersKey] || (_globalThis[asyncHandlersKey] = /* @__PURE__ */ new Set());
function executeAsync(function_) {
  const restores = [];
  for (const leaveHandler of asyncHandlers) {
    const restore2 = leaveHandler();
    if (restore2) {
      restores.push(restore2);
    }
  }
  const restore = () => {
    for (const restore2 of restores) {
      restore2();
    }
  };
  let awaitable = function_();
  if (awaitable && typeof awaitable === "object" && "catch" in awaitable) {
    awaitable = awaitable.catch((error) => {
      restore();
      throw error;
    });
  }
  return [awaitable, restore];
}

getContext("nitro-app", {
  asyncContext: false,
  AsyncLocalStorage: void 0
});

const config = useRuntimeConfig();
const _routeRulesMatcher = toRouteMatcher(
  createRouter$1({ routes: config.nitro.routeRules })
);
function createRouteRulesHandler(ctx) {
  return eventHandler((event) => {
    const routeRules = getRouteRules(event);
    if (routeRules.headers) {
      setHeaders(event, routeRules.headers);
    }
    if (routeRules.redirect) {
      let target = routeRules.redirect.to;
      if (target.endsWith("/**")) {
        let targetPath = event.path;
        const strpBase = routeRules.redirect._redirectStripBase;
        if (strpBase) {
          targetPath = withoutBase(targetPath, strpBase);
        }
        target = joinURL(target.slice(0, -3), targetPath);
      } else if (event.path.includes("?")) {
        const query = getQuery$1(event.path);
        target = withQuery(target, query);
      }
      return sendRedirect(event, target, routeRules.redirect.statusCode);
    }
    if (routeRules.proxy) {
      let target = routeRules.proxy.to;
      if (target.endsWith("/**")) {
        let targetPath = event.path;
        const strpBase = routeRules.proxy._proxyStripBase;
        if (strpBase) {
          targetPath = withoutBase(targetPath, strpBase);
        }
        target = joinURL(target.slice(0, -3), targetPath);
      } else if (event.path.includes("?")) {
        const query = getQuery$1(event.path);
        target = withQuery(target, query);
      }
      return proxyRequest(event, target, {
        fetch: ctx.localFetch,
        ...routeRules.proxy
      });
    }
  });
}
function getRouteRules(event) {
  event.context._nitro = event.context._nitro || {};
  if (!event.context._nitro.routeRules) {
    event.context._nitro.routeRules = getRouteRulesForPath(
      withoutBase(event.path.split("?")[0], useRuntimeConfig().app.baseURL)
    );
  }
  return event.context._nitro.routeRules;
}
function getRouteRulesForPath(path) {
  return defu({}, ..._routeRulesMatcher.matchAll(path).reverse());
}

function joinHeaders(value) {
  return Array.isArray(value) ? value.join(", ") : String(value);
}
function normalizeFetchResponse(response) {
  if (!response.headers.has("set-cookie")) {
    return response;
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: normalizeCookieHeaders(response.headers)
  });
}
function normalizeCookieHeader(header = "") {
  return splitCookiesString(joinHeaders(header));
}
function normalizeCookieHeaders(headers) {
  const outgoingHeaders = new Headers();
  for (const [name, header] of headers) {
    if (name === "set-cookie") {
      for (const cookie of normalizeCookieHeader(header)) {
        outgoingHeaders.append("set-cookie", cookie);
      }
    } else {
      outgoingHeaders.set(name, joinHeaders(header));
    }
  }
  return outgoingHeaders;
}

function isJsonRequest(event) {
  if (hasReqHeader(event, "accept", "text/html")) {
    return false;
  }
  return hasReqHeader(event, "accept", "application/json") || hasReqHeader(event, "user-agent", "curl/") || hasReqHeader(event, "user-agent", "httpie/") || hasReqHeader(event, "sec-fetch-mode", "cors") || event.path.startsWith("/api/") || event.path.endsWith(".json");
}
function hasReqHeader(event, name, includes) {
  const value = getRequestHeader(event, name);
  return value && typeof value === "string" && value.toLowerCase().includes(includes);
}

const errorHandler$0 = (async function errorhandler(error, event, { defaultHandler }) {
  if (event.handled || isJsonRequest(event)) {
    return;
  }
  const defaultRes = await defaultHandler(error, event, { json: true });
  const statusCode = error.statusCode || 500;
  if (statusCode === 404 && defaultRes.status === 302) {
    setResponseHeaders(event, defaultRes.headers);
    setResponseStatus(event, defaultRes.status, defaultRes.statusText);
    return send(event, JSON.stringify(defaultRes.body, null, 2));
  }
  const errorObject = defaultRes.body;
  const url = new URL(errorObject.url);
  errorObject.url = withoutBase(url.pathname, useRuntimeConfig(event).app.baseURL) + url.search + url.hash;
  errorObject.message ||= "Server Error";
  errorObject.data ||= error.data;
  errorObject.statusMessage ||= error.statusMessage;
  delete defaultRes.headers["content-type"];
  delete defaultRes.headers["content-security-policy"];
  setResponseHeaders(event, defaultRes.headers);
  const reqHeaders = getRequestHeaders(event);
  const isRenderingError = event.path.startsWith("/__nuxt_error") || !!reqHeaders["x-nuxt-error"];
  const res = isRenderingError ? null : await useNitroApp().localFetch(
    withQuery(joinURL(useRuntimeConfig(event).app.baseURL, "/__nuxt_error"), errorObject),
    {
      headers: { ...reqHeaders, "x-nuxt-error": "true" },
      redirect: "manual"
    }
  ).catch(() => null);
  if (event.handled) {
    return;
  }
  if (!res) {
    const { template } = await import('../_/error-500.mjs');
    setResponseHeader(event, "Content-Type", "text/html;charset=UTF-8");
    return send(event, template(errorObject));
  }
  const html = await res.text();
  for (const [header, value] of res.headers.entries()) {
    if (header === "set-cookie") {
      appendResponseHeader(event, header, value);
      continue;
    }
    setResponseHeader(event, header, value);
  }
  setResponseStatus(event, res.status && res.status !== 200 ? res.status : defaultRes.status, res.statusText || defaultRes.statusText);
  return send(event, html);
});

function defineNitroErrorHandler(handler) {
  return handler;
}

const errorHandler$1 = defineNitroErrorHandler(
  function defaultNitroErrorHandler(error, event) {
    const res = defaultHandler(error, event);
    setResponseHeaders(event, res.headers);
    setResponseStatus(event, res.status, res.statusText);
    return send(event, JSON.stringify(res.body, null, 2));
  }
);
function defaultHandler(error, event, opts) {
  const isSensitive = error.unhandled || error.fatal;
  const statusCode = error.statusCode || 500;
  const statusMessage = error.statusMessage || "Server Error";
  const url = getRequestURL(event, { xForwardedHost: true, xForwardedProto: true });
  if (statusCode === 404) {
    const baseURL = "/";
    if (/^\/[^/]/.test(baseURL) && !url.pathname.startsWith(baseURL)) {
      const redirectTo = `${baseURL}${url.pathname.slice(1)}${url.search}`;
      return {
        status: 302,
        statusText: "Found",
        headers: { location: redirectTo },
        body: `Redirecting...`
      };
    }
  }
  if (isSensitive && !opts?.silent) {
    const tags = [error.unhandled && "[unhandled]", error.fatal && "[fatal]"].filter(Boolean).join(" ");
    console.error(`[request error] ${tags} [${event.method}] ${url}
`, error);
  }
  const headers = {
    "content-type": "application/json",
    // Prevent browser from guessing the MIME types of resources.
    "x-content-type-options": "nosniff",
    // Prevent error page from being embedded in an iframe
    "x-frame-options": "DENY",
    // Prevent browsers from sending the Referer header
    "referrer-policy": "no-referrer",
    // Disable the execution of any js
    "content-security-policy": "script-src 'none'; frame-ancestors 'none';"
  };
  setResponseStatus(event, statusCode, statusMessage);
  if (statusCode === 404 || !getResponseHeader(event, "cache-control")) {
    headers["cache-control"] = "no-cache";
  }
  const body = {
    error: true,
    url: url.href,
    statusCode,
    statusMessage,
    message: isSensitive ? "Server Error" : error.message,
    data: isSensitive ? void 0 : error.data
  };
  return {
    status: statusCode,
    statusText: statusMessage,
    headers,
    body
  };
}

const errorHandlers = [errorHandler$0, errorHandler$1];

async function errorHandler(error, event) {
  for (const handler of errorHandlers) {
    try {
      await handler(error, event, { defaultHandler });
      if (event.handled) {
        return; // Response handled
      }
    } catch(error) {
      // Handler itself thrown, log and continue
      console.error(error);
    }
  }
  // H3 will handle fallback
}

const script = "\"use strict\";(()=>{const t=window,e=document.documentElement,c=[\"dark\",\"light\"],n=getStorageValue(\"localStorage\",\"nuxt-color-mode\")||\"system\";let i=n===\"system\"?u():n;const r=e.getAttribute(\"data-color-mode-forced\");r&&(i=r),l(i),t[\"__NUXT_COLOR_MODE__\"]={preference:n,value:i,getColorScheme:u,addColorScheme:l,removeColorScheme:d};function l(o){const s=\"\"+o+\"\",a=\"\";e.classList?e.classList.add(s):e.className+=\" \"+s,a&&e.setAttribute(\"data-\"+a,o)}function d(o){const s=\"\"+o+\"\",a=\"\";e.classList?e.classList.remove(s):e.className=e.className.replace(new RegExp(s,\"g\"),\"\"),a&&e.removeAttribute(\"data-\"+a)}function f(o){return t.matchMedia(\"(prefers-color-scheme\"+o+\")\")}function u(){if(t.matchMedia&&f(\"\").media!==\"not all\"){for(const o of c)if(f(\":\"+o).matches)return o}return\"light\"}})();function getStorageValue(t,e){switch(t){case\"localStorage\":return window.localStorage.getItem(e);case\"sessionStorage\":return window.sessionStorage.getItem(e);case\"cookie\":return getCookie(e);default:return null}}function getCookie(t){const c=(\"; \"+window.document.cookie).split(\"; \"+t+\"=\");if(c.length===2)return c.pop()?.split(\";\").shift()}";

const _jhC4XDhOuEBHG3_HuRNxAV7Q0Y_Iz57DP81fx88xw = (function(nitro) {
  nitro.hooks.hook("render:html", (htmlContext) => {
    htmlContext.head.push(`<script>${script}<\/script>`);
  });
});

const plugins = [
  _jhC4XDhOuEBHG3_HuRNxAV7Q0Y_Iz57DP81fx88xw
];

const protectedRoutes = ["/dashboard", "/profile", "/invoices", "/settings"];
const guestOnlyRoutes = ["/login", "/signup"];
const _64KrsE = defineEventHandler(async (event) => {
  const url = event.node.req.url || "";
  if (url.startsWith("/api") || url.startsWith("/_nuxt") || url.startsWith("/favicon")) {
    return;
  }
  const token = getCookie(event, "auth-token");
  let isAuthenticated = false;
  if (token) {
    try {
      const config = useRuntimeConfig();
      const secret = new TextEncoder().encode(config.jwtSecret);
      await jose.jwtVerify(token, secret);
      isAuthenticated = true;
    } catch (error) {
      setCookie(event, "auth-token", "", {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 0
      });
      isAuthenticated = false;
    }
  }
  const isProtectedRoute = protectedRoutes.some(
    (route) => url.startsWith(route)
  );
  if (isProtectedRoute && !isAuthenticated) {
    await sendRedirect(event, "/login");
    return;
  }
  const isGuestOnlyRoute = guestOnlyRoutes.some(
    (route) => url.startsWith(route)
  );
  if (isGuestOnlyRoute && isAuthenticated) {
    await sendRedirect(event, "/dashboard");
    return;
  }
});

const _SxA8c9 = defineEventHandler(() => {});

const _DRIVE_LETTER_START_RE = /^[A-Za-z]:\//;
function normalizeWindowsPath(input = "") {
  if (!input) {
    return input;
  }
  return input.replace(/\\/g, "/").replace(_DRIVE_LETTER_START_RE, (r) => r.toUpperCase());
}
const _IS_ABSOLUTE_RE = /^[/\\](?![/\\])|^[/\\]{2}(?!\.)|^[A-Za-z]:[/\\]/;
const _ROOT_FOLDER_RE = /^\/([A-Za-z]:)?$/;
function cwd() {
  if (typeof process !== "undefined" && typeof process.cwd === "function") {
    return process.cwd().replace(/\\/g, "/");
  }
  return "/";
}
const resolve = function(...arguments_) {
  arguments_ = arguments_.map((argument) => normalizeWindowsPath(argument));
  let resolvedPath = "";
  let resolvedAbsolute = false;
  for (let index = arguments_.length - 1; index >= -1 && !resolvedAbsolute; index--) {
    const path = index >= 0 ? arguments_[index] : cwd();
    if (!path || path.length === 0) {
      continue;
    }
    resolvedPath = `${path}/${resolvedPath}`;
    resolvedAbsolute = isAbsolute(path);
  }
  resolvedPath = normalizeString(resolvedPath, !resolvedAbsolute);
  if (resolvedAbsolute && !isAbsolute(resolvedPath)) {
    return `/${resolvedPath}`;
  }
  return resolvedPath.length > 0 ? resolvedPath : ".";
};
function normalizeString(path, allowAboveRoot) {
  let res = "";
  let lastSegmentLength = 0;
  let lastSlash = -1;
  let dots = 0;
  let char = null;
  for (let index = 0; index <= path.length; ++index) {
    if (index < path.length) {
      char = path[index];
    } else if (char === "/") {
      break;
    } else {
      char = "/";
    }
    if (char === "/") {
      if (lastSlash === index - 1 || dots === 1) ; else if (dots === 2) {
        if (res.length < 2 || lastSegmentLength !== 2 || res[res.length - 1] !== "." || res[res.length - 2] !== ".") {
          if (res.length > 2) {
            const lastSlashIndex = res.lastIndexOf("/");
            if (lastSlashIndex === -1) {
              res = "";
              lastSegmentLength = 0;
            } else {
              res = res.slice(0, lastSlashIndex);
              lastSegmentLength = res.length - 1 - res.lastIndexOf("/");
            }
            lastSlash = index;
            dots = 0;
            continue;
          } else if (res.length > 0) {
            res = "";
            lastSegmentLength = 0;
            lastSlash = index;
            dots = 0;
            continue;
          }
        }
        if (allowAboveRoot) {
          res += res.length > 0 ? "/.." : "..";
          lastSegmentLength = 2;
        }
      } else {
        if (res.length > 0) {
          res += `/${path.slice(lastSlash + 1, index)}`;
        } else {
          res = path.slice(lastSlash + 1, index);
        }
        lastSegmentLength = index - lastSlash - 1;
      }
      lastSlash = index;
      dots = 0;
    } else if (char === "." && dots !== -1) {
      ++dots;
    } else {
      dots = -1;
    }
  }
  return res;
}
const isAbsolute = function(p) {
  return _IS_ABSOLUTE_RE.test(p);
};
const relative = function(from, to) {
  const _from = resolve(from).replace(_ROOT_FOLDER_RE, "$1").split("/");
  const _to = resolve(to).replace(_ROOT_FOLDER_RE, "$1").split("/");
  if (_to[0][1] === ":" && _from[0][1] === ":" && _from[0] !== _to[0]) {
    return _to.join("/");
  }
  const _fromCopy = [..._from];
  for (const segment of _fromCopy) {
    if (_to[0] !== segment) {
      break;
    }
    _from.shift();
    _to.shift();
  }
  return [..._from.map(() => ".."), ..._to].join("/");
};

function defineRenderHandler(render) {
  const runtimeConfig = useRuntimeConfig();
  return eventHandler(async (event) => {
    const nitroApp = useNitroApp();
    const ctx = { event, render, response: void 0 };
    await nitroApp.hooks.callHook("render:before", ctx);
    if (!ctx.response) {
      if (event.path === `${runtimeConfig.app.baseURL}favicon.ico`) {
        setResponseHeader(event, "Content-Type", "image/x-icon");
        return send(
          event,
          "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
        );
      }
      ctx.response = await ctx.render(event);
      if (!ctx.response) {
        const _currentStatus = getResponseStatus(event);
        setResponseStatus(event, _currentStatus === 200 ? 500 : _currentStatus);
        return send(
          event,
          "No response returned from render handler: " + event.path
        );
      }
    }
    await nitroApp.hooks.callHook("render:response", ctx.response, ctx);
    if (ctx.response.headers) {
      setResponseHeaders(event, ctx.response.headers);
    }
    if (ctx.response.statusCode || ctx.response.statusMessage) {
      setResponseStatus(
        event,
        ctx.response.statusCode,
        ctx.response.statusMessage
      );
    }
    return ctx.response.body;
  });
}

function baseURL() {
  return useRuntimeConfig().app.baseURL;
}
function buildAssetsDir() {
  return useRuntimeConfig().app.buildAssetsDir;
}
function buildAssetsURL(...path) {
  return joinRelativeURL(publicAssetsURL(), buildAssetsDir(), ...path);
}
function publicAssetsURL(...path) {
  const app = useRuntimeConfig().app;
  const publicBase = app.cdnURL || app.baseURL;
  return path.length ? joinRelativeURL(publicBase, ...path) : publicBase;
}

function getDefaultExportFromNamespaceIfNotNamed (n) {
	return n && Object.prototype.hasOwnProperty.call(n, 'default') && Object.keys(n).length === 1 ? n['default'] : n;
}

var prisma$1 = {};

const require$$0 = /*@__PURE__*/getDefaultExportFromNamespaceIfNotNamed(node_os);

const require$$1$1 = /*@__PURE__*/getDefaultExportFromNamespaceIfNotNamed(node_tty);

const require$$2$1 = /*@__PURE__*/getDefaultExportFromNamespaceIfNotNamed(node_fs);

const require$$3 = /*@__PURE__*/getDefaultExportFromNamespaceIfNotNamed(node_path);

const require$$4 = /*@__PURE__*/getDefaultExportFromNamespaceIfNotNamed(nodeCrypto);

const require$$5 = /*@__PURE__*/getDefaultExportFromNamespaceIfNotNamed(node_child_process);

const require$$6 = /*@__PURE__*/getDefaultExportFromNamespaceIfNotNamed(promises);

const require$$7 = /*@__PURE__*/getDefaultExportFromNamespaceIfNotNamed(node_util);

const require$$8 = /*@__PURE__*/getDefaultExportFromNamespaceIfNotNamed(node_process);

const require$$9 = /*@__PURE__*/getDefaultExportFromNamespaceIfNotNamed(node_async_hooks);

const require$$10 = /*@__PURE__*/getDefaultExportFromNamespaceIfNotNamed(node_events);

var __defProp = Object.defineProperty;
var __typeError = (msg) => {
  throw TypeError(msg);
};
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var __privateMethod = (obj, member, method) => (__accessCheck(obj, member, "access private method"), method);
var _a2, _b, _c2, _d2, _e, _f2, _g, _h, _i2, _j, _k, _l2, _m2, _n2, _o2, _p2, _q, _r2, _s2, _t2, _u2, _v, _w, _x, _y, _z, _A, _B, _C, _D, _E, _F, _G, _H, _e2, _I, _e3, _J, _e4, _K, _Hn_instances, e_fn, _L;
var xu = Object.create;
var Vt = Object.defineProperty;
var vu = Object.getOwnPropertyDescriptor;
var Pu = Object.getOwnPropertyNames;
var Tu = Object.getPrototypeOf, Su = Object.prototype.hasOwnProperty;
var Oo = (e10, r) => () => (e10 && (r = e10(e10 = 0)), r);
var ne = (e10, r) => () => (r || e10((r = { exports: {} }).exports, r), r.exports), tr = (e10, r) => {
  for (var t in r) Vt(e10, t, { get: r[t], enumerable: true });
}, ko = (e10, r, t, n) => {
  if (r && typeof r == "object" || typeof r == "function") for (let i of Pu(r)) !Su.call(e10, i) && i !== t && Vt(e10, i, { get: () => r[i], enumerable: !(n = vu(r, i)) || n.enumerable });
  return e10;
};
var A = (e10, r, t) => (t = e10 != null ? xu(Tu(e10)) : {}, ko(r || !e10 || !e10.__esModule ? Vt(t, "default", { value: e10, enumerable: true }) : t, e10)), Ru = (e10) => ko(Vt({}, "__esModule", { value: true }), e10);
var hi = ne((Mg, os) => {
  os.exports = (e10, r = process.argv) => {
    let t = e10.startsWith("-") ? "" : e10.length === 1 ? "-" : "--", n = r.indexOf(t + e10), i = r.indexOf("--");
    return n !== -1 && (i === -1 || n < i);
  };
});
var ls = ne(($g, as) => {
  var Vc = require$$0, ss = require$$1$1, de = hi(), { env: G } = process, Qe;
  de("no-color") || de("no-colors") || de("color=false") || de("color=never") ? Qe = 0 : (de("color") || de("colors") || de("color=true") || de("color=always")) && (Qe = 1);
  "FORCE_COLOR" in G && (G.FORCE_COLOR === "true" ? Qe = 1 : G.FORCE_COLOR === "false" ? Qe = 0 : Qe = G.FORCE_COLOR.length === 0 ? 1 : Math.min(parseInt(G.FORCE_COLOR, 10), 3));
  function yi(e10) {
    return e10 === 0 ? false : { level: e10, hasBasic: true, has256: e10 >= 2, has16m: e10 >= 3 };
  }
  function bi(e10, r) {
    if (Qe === 0) return 0;
    if (de("color=16m") || de("color=full") || de("color=truecolor")) return 3;
    if (de("color=256")) return 2;
    if (e10 && !r && Qe === void 0) return 0;
    let t = Qe || 0;
    if (G.TERM === "dumb") return t;
    if (process.platform === "win32") {
      let n = Vc.release().split(".");
      return Number(n[0]) >= 10 && Number(n[2]) >= 10586 ? Number(n[2]) >= 14931 ? 3 : 2 : 1;
    }
    if ("CI" in G) return ["TRAVIS", "CIRCLECI", "APPVEYOR", "GITLAB_CI", "GITHUB_ACTIONS", "BUILDKITE"].some((n) => n in G) || G.CI_NAME === "codeship" ? 1 : t;
    if ("TEAMCITY_VERSION" in G) return /^(9\.(0*[1-9]\d*)\.|\d{2,}\.)/.test(G.TEAMCITY_VERSION) ? 1 : 0;
    if (G.COLORTERM === "truecolor") return 3;
    if ("TERM_PROGRAM" in G) {
      let n = parseInt((G.TERM_PROGRAM_VERSION || "").split(".")[0], 10);
      switch (G.TERM_PROGRAM) {
        case "iTerm.app":
          return n >= 3 ? 3 : 2;
        case "Apple_Terminal":
          return 2;
      }
    }
    return /-256(color)?$/i.test(G.TERM) ? 2 : /^screen|^xterm|^vt100|^vt220|^rxvt|color|ansi|cygwin|linux/i.test(G.TERM) || "COLORTERM" in G ? 1 : t;
  }
  function jc(e10) {
    let r = bi(e10, e10 && e10.isTTY);
    return yi(r);
  }
  as.exports = { supportsColor: jc, stdout: yi(bi(true, ss.isatty(1))), stderr: yi(bi(true, ss.isatty(2))) };
});
var ps = ne((qg, cs) => {
  var Bc = ls(), br = hi();
  function us(e10) {
    if (/^\d{3,4}$/.test(e10)) {
      let t = /(\d{1,2})(\d{2})/.exec(e10) || [];
      return { major: 0, minor: parseInt(t[1], 10), patch: parseInt(t[2], 10) };
    }
    let r = (e10 || "").split(".").map((t) => parseInt(t, 10));
    return { major: r[0], minor: r[1], patch: r[2] };
  }
  function Ei(e10) {
    let { CI: r, FORCE_HYPERLINK: t, NETLIFY: n, TEAMCITY_VERSION: i, TERM_PROGRAM: o, TERM_PROGRAM_VERSION: s, VTE_VERSION: a, TERM: l } = process.env;
    if (t) return !(t.length > 0 && parseInt(t, 10) === 0);
    if (br("no-hyperlink") || br("no-hyperlinks") || br("hyperlink=false") || br("hyperlink=never")) return false;
    if (br("hyperlink=true") || br("hyperlink=always") || n) return true;
    if (!Bc.supportsColor(e10) || e10 && !e10.isTTY) return false;
    if ("WT_SESSION" in process.env) return true;
    if (process.platform === "win32" || r || i) return false;
    if (o) {
      let u = us(s || "");
      switch (o) {
        case "iTerm.app":
          return u.major === 3 ? u.minor >= 1 : u.major > 3;
        case "WezTerm":
          return u.major >= 20200620;
        case "vscode":
          return u.major > 1 || u.major === 1 && u.minor >= 72;
        case "ghostty":
          return true;
      }
    }
    if (a) {
      if (a === "0.50.0") return false;
      let u = us(a);
      return u.major > 0 || u.minor >= 50;
    }
    switch (l) {
      case "alacritty":
        return true;
    }
    return false;
  }
  cs.exports = { supportsHyperlink: Ei, stdout: Ei(process.stdout), stderr: Ei(process.stderr) };
});
var ds = ne((Zg, Uc) => {
  Uc.exports = { name: "@prisma/internals", version: "6.15.0", description: "This package is intended for Prisma's internal use", main: "dist/index.js", types: "dist/index.d.ts", repository: { type: "git", url: "https://github.com/prisma/prisma.git", directory: "packages/internals" }, homepage: "https://www.prisma.io", author: "Tim Suchanek <suchanek@prisma.io>", bugs: "https://github.com/prisma/prisma/issues", license: "Apache-2.0", scripts: { dev: "DEV=true tsx helpers/build.ts", build: "tsx helpers/build.ts", test: "dotenv -e ../../.db.env -- jest --silent", prepublishOnly: "pnpm run build" }, files: ["README.md", "dist", "!**/libquery_engine*", "!dist/get-generators/engines/*", "scripts"], devDependencies: { "@babel/helper-validator-identifier": "7.25.9", "@opentelemetry/api": "1.9.0", "@swc/core": "1.11.5", "@swc/jest": "0.2.37", "@types/babel__helper-validator-identifier": "7.15.2", "@types/jest": "29.5.14", "@types/node": "18.19.76", "@types/resolve": "1.20.6", archiver: "6.0.2", "checkpoint-client": "1.1.33", "cli-truncate": "4.0.0", dotenv: "16.5.0", empathic: "2.0.0", esbuild: "0.25.5", "escape-string-regexp": "5.0.0", execa: "5.1.1", "fast-glob": "3.3.3", "find-up": "7.0.0", "fp-ts": "2.16.9", "fs-extra": "11.3.0", "fs-jetpack": "5.1.0", "global-dirs": "4.0.0", globby: "11.1.0", "identifier-regex": "1.0.0", "indent-string": "4.0.0", "is-windows": "1.0.2", "is-wsl": "3.1.0", jest: "29.7.0", "jest-junit": "16.0.0", kleur: "4.1.5", "mock-stdin": "1.0.0", "new-github-issue-url": "0.2.1", "node-fetch": "3.3.2", "npm-packlist": "5.1.3", open: "7.4.2", "p-map": "4.0.0", resolve: "1.22.10", "string-width": "7.2.0", "strip-ansi": "6.0.1", "strip-indent": "4.0.0", "temp-dir": "2.0.0", tempy: "1.0.1", "terminal-link": "4.0.0", tmp: "0.2.3", "ts-node": "10.9.2", "ts-pattern": "5.6.2", "ts-toolbelt": "9.6.0", typescript: "5.4.5", yarn: "1.22.22" }, dependencies: { "@prisma/config": "workspace:*", "@prisma/debug": "workspace:*", "@prisma/dmmf": "workspace:*", "@prisma/driver-adapter-utils": "workspace:*", "@prisma/engines": "workspace:*", "@prisma/fetch-engine": "workspace:*", "@prisma/generator": "workspace:*", "@prisma/generator-helper": "workspace:*", "@prisma/get-platform": "workspace:*", "@prisma/prisma-schema-wasm": "6.15.0-5.85179d7826409ee107a6ba334b5e305ae3fba9fb", "@prisma/schema-engine-wasm": "6.15.0-5.85179d7826409ee107a6ba334b5e305ae3fba9fb", "@prisma/schema-files-loader": "workspace:*", arg: "5.0.2", prompts: "2.4.2" }, peerDependencies: { typescript: ">=5.1.0" }, peerDependenciesMeta: { typescript: { optional: true } }, sideEffects: false };
});
var Ti = ne((Eh, Hc) => {
  Hc.exports = { name: "@prisma/engines-version", version: "6.15.0-5.85179d7826409ee107a6ba334b5e305ae3fba9fb", main: "index.js", types: "index.d.ts", license: "Apache-2.0", author: "Tim Suchanek <suchanek@prisma.io>", prisma: { enginesVersion: "85179d7826409ee107a6ba334b5e305ae3fba9fb" }, repository: { type: "git", url: "https://github.com/prisma/engines-wrapper.git", directory: "packages/engines-version" }, devDependencies: { "@types/node": "18.19.76", typescript: "4.9.5" }, files: ["index.js", "index.d.ts"], scripts: { build: "tsc -d" } };
});
var nn = ne((tn) => {
  Object.defineProperty(tn, "__esModule", { value: true });
  tn.enginesVersion = void 0;
  tn.enginesVersion = Ti().prisma.enginesVersion;
});
var ys = ne((_h2, hs) => {
  hs.exports = (e10) => {
    let r = e10.match(/^[ \t]*(?=\S)/gm);
    return r ? r.reduce((t, n) => Math.min(t, n.length), 1 / 0) : 0;
  };
});
var Di = ne((Fh, ws) => {
  ws.exports = (e10, r = 1, t) => {
    if (t = { indent: " ", includeEmptyLines: false, ...t }, typeof e10 != "string") throw new TypeError(`Expected \`input\` to be a \`string\`, got \`${typeof e10}\``);
    if (typeof r != "number") throw new TypeError(`Expected \`count\` to be a \`number\`, got \`${typeof r}\``);
    if (typeof t.indent != "string") throw new TypeError(`Expected \`options.indent\` to be a \`string\`, got \`${typeof t.indent}\``);
    if (r === 0) return e10;
    let n = t.includeEmptyLines ? /^/gm : /^(?!\s*$)/gm;
    return e10.replace(n, t.indent.repeat(r));
  };
});
var Ts = ne((qh, Ps) => {
  Ps.exports = ({ onlyFirst: e10 = false } = {}) => {
    let r = ["[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]+)*|[a-zA-Z\\d]+(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\\u0007)", "(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))"].join("|");
    return new RegExp(r, e10 ? void 0 : "g");
  };
});
var Ni = ne((Vh, Ss) => {
  var op = Ts();
  Ss.exports = (e10) => typeof e10 == "string" ? e10.replace(op(), "") : e10;
});
var Rs = ne((Gh, sp) => {
  sp.exports = { name: "dotenv", version: "16.5.0", description: "Loads environment variables from .env file", main: "lib/main.js", types: "lib/main.d.ts", exports: { ".": { types: "./lib/main.d.ts", require: "./lib/main.js", default: "./lib/main.js" }, "./config": "./config.js", "./config.js": "./config.js", "./lib/env-options": "./lib/env-options.js", "./lib/env-options.js": "./lib/env-options.js", "./lib/cli-options": "./lib/cli-options.js", "./lib/cli-options.js": "./lib/cli-options.js", "./package.json": "./package.json" }, scripts: { "dts-check": "tsc --project tests/types/tsconfig.json", lint: "standard", pretest: "npm run lint && npm run dts-check", test: "tap run --allow-empty-coverage --disable-coverage --timeout=60000", "test:coverage": "tap run --show-full-coverage --timeout=60000 --coverage-report=lcov", prerelease: "npm test", release: "standard-version" }, repository: { type: "git", url: "git://github.com/motdotla/dotenv.git" }, homepage: "https://github.com/motdotla/dotenv#readme", funding: "https://dotenvx.com", keywords: ["dotenv", "env", ".env", "environment", "variables", "config", "settings"], readmeFilename: "README.md", license: "BSD-2-Clause", devDependencies: { "@types/node": "^18.11.3", decache: "^4.6.2", sinon: "^14.0.1", standard: "^17.0.0", "standard-version": "^9.5.0", tap: "^19.2.0", typescript: "^4.8.4" }, engines: { node: ">=12" }, browser: { fs: false } };
});
var Os = ne((Qh, _e5) => {
  var Fi = require$$2$1, Mi = require$$3, ap = require$$0, lp = require$$4, up = Rs(), Cs = up.version, cp = /(?:^|^)\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)/mg;
  function pp(e10) {
    let r = {}, t = e10.toString();
    t = t.replace(/\r\n?/mg, `
`);
    let n;
    for (; (n = cp.exec(t)) != null; ) {
      let i = n[1], o = n[2] || "";
      o = o.trim();
      let s = o[0];
      o = o.replace(/^(['"`])([\s\S]*)\1$/mg, "$2"), s === '"' && (o = o.replace(/\\n/g, `
`), o = o.replace(/\\r/g, "\r")), r[i] = o;
    }
    return r;
  }
  function dp(e10) {
    let r = Ds(e10), t = B.configDotenv({ path: r });
    if (!t.parsed) {
      let s = new Error(`MISSING_DATA: Cannot parse ${r} for an unknown reason`);
      throw s.code = "MISSING_DATA", s;
    }
    let n = Is(e10).split(","), i = n.length, o;
    for (let s = 0; s < i; s++) try {
      let a = n[s].trim(), l = fp(t, a);
      o = B.decrypt(l.ciphertext, l.key);
      break;
    } catch (a) {
      if (s + 1 >= i) throw a;
    }
    return B.parse(o);
  }
  function mp(e10) {
    console.log(`[dotenv@${Cs}][WARN] ${e10}`);
  }
  function it(e10) {
    console.log(`[dotenv@${Cs}][DEBUG] ${e10}`);
  }
  function Is(e10) {
    return e10 && e10.DOTENV_KEY && e10.DOTENV_KEY.length > 0 ? e10.DOTENV_KEY : process.env.DOTENV_KEY && process.env.DOTENV_KEY.length > 0 ? process.env.DOTENV_KEY : "";
  }
  function fp(e10, r) {
    let t;
    try {
      t = new URL(r);
    } catch (a) {
      if (a.code === "ERR_INVALID_URL") {
        let l = new Error("INVALID_DOTENV_KEY: Wrong format. Must be in valid uri format like dotenv://:key_1234@dotenvx.com/vault/.env.vault?environment=development");
        throw l.code = "INVALID_DOTENV_KEY", l;
      }
      throw a;
    }
    let n = t.password;
    if (!n) {
      let a = new Error("INVALID_DOTENV_KEY: Missing key part");
      throw a.code = "INVALID_DOTENV_KEY", a;
    }
    let i = t.searchParams.get("environment");
    if (!i) {
      let a = new Error("INVALID_DOTENV_KEY: Missing environment part");
      throw a.code = "INVALID_DOTENV_KEY", a;
    }
    let o = `DOTENV_VAULT_${i.toUpperCase()}`, s = e10.parsed[o];
    if (!s) {
      let a = new Error(`NOT_FOUND_DOTENV_ENVIRONMENT: Cannot locate environment ${o} in your .env.vault file.`);
      throw a.code = "NOT_FOUND_DOTENV_ENVIRONMENT", a;
    }
    return { ciphertext: s, key: n };
  }
  function Ds(e10) {
    let r = null;
    if (e10 && e10.path && e10.path.length > 0) if (Array.isArray(e10.path)) for (let t of e10.path) Fi.existsSync(t) && (r = t.endsWith(".vault") ? t : `${t}.vault`);
    else r = e10.path.endsWith(".vault") ? e10.path : `${e10.path}.vault`;
    else r = Mi.resolve(process.cwd(), ".env.vault");
    return Fi.existsSync(r) ? r : null;
  }
  function As(e10) {
    return e10[0] === "~" ? Mi.join(ap.homedir(), e10.slice(1)) : e10;
  }
  function gp(e10) {
    !!(e10 && e10.debug) && it("Loading env from encrypted .env.vault");
    let t = B._parseVault(e10), n = process.env;
    return e10 && e10.processEnv != null && (n = e10.processEnv), B.populate(n, t, e10), { parsed: t };
  }
  function hp(e10) {
    let r = Mi.resolve(process.cwd(), ".env"), t = "utf8", n = !!(e10 && e10.debug);
    e10 && e10.encoding ? t = e10.encoding : n && it("No encoding is specified. UTF-8 is used by default");
    let i = [r];
    if (e10 && e10.path) if (!Array.isArray(e10.path)) i = [As(e10.path)];
    else {
      i = [];
      for (let l of e10.path) i.push(As(l));
    }
    let o, s = {};
    for (let l of i) try {
      let u = B.parse(Fi.readFileSync(l, { encoding: t }));
      B.populate(s, u, e10);
    } catch (u) {
      n && it(`Failed to load ${l} ${u.message}`), o = u;
    }
    let a = process.env;
    return e10 && e10.processEnv != null && (a = e10.processEnv), B.populate(a, s, e10), o ? { parsed: s, error: o } : { parsed: s };
  }
  function yp(e10) {
    if (Is(e10).length === 0) return B.configDotenv(e10);
    let r = Ds(e10);
    return r ? B._configVault(e10) : (mp(`You set DOTENV_KEY but you are missing a .env.vault file at ${r}. Did you forget to build it?`), B.configDotenv(e10));
  }
  function bp(e10, r) {
    let t = Buffer.from(r.slice(-64), "hex"), n = Buffer.from(e10, "base64"), i = n.subarray(0, 12), o = n.subarray(-16);
    n = n.subarray(12, -16);
    try {
      let s = lp.createDecipheriv("aes-256-gcm", t, i);
      return s.setAuthTag(o), `${s.update(n)}${s.final()}`;
    } catch (s) {
      let a = s instanceof RangeError, l = s.message === "Invalid key length", u = s.message === "Unsupported state or unable to authenticate data";
      if (a || l) {
        let c = new Error("INVALID_DOTENV_KEY: It must be 64 characters long (or more)");
        throw c.code = "INVALID_DOTENV_KEY", c;
      } else if (u) {
        let c = new Error("DECRYPTION_FAILED: Please check your DOTENV_KEY");
        throw c.code = "DECRYPTION_FAILED", c;
      } else throw s;
    }
  }
  function Ep(e10, r, t = {}) {
    let n = !!(t && t.debug), i = !!(t && t.override);
    if (typeof r != "object") {
      let o = new Error("OBJECT_REQUIRED: Please check the processEnv argument being passed to populate");
      throw o.code = "OBJECT_REQUIRED", o;
    }
    for (let o of Object.keys(r)) Object.prototype.hasOwnProperty.call(e10, o) ? (i === true && (e10[o] = r[o]), n && it(i === true ? `"${o}" is already defined and WAS overwritten` : `"${o}" is already defined and was NOT overwritten`)) : e10[o] = r[o];
  }
  var B = { configDotenv: hp, _configVault: gp, _parseVault: dp, config: yp, decrypt: bp, parse: pp, populate: Ep };
  _e5.exports.configDotenv = B.configDotenv;
  _e5.exports._configVault = B._configVault;
  _e5.exports._parseVault = B._parseVault;
  _e5.exports.config = B.config;
  _e5.exports.decrypt = B.decrypt;
  _e5.exports.parse = B.parse;
  _e5.exports.populate = B.populate;
  _e5.exports = B;
});
var Ls = ne((zh, un) => {
  un.exports = (e10 = {}) => {
    let r;
    if (e10.repoUrl) r = e10.repoUrl;
    else if (e10.user && e10.repo) r = `https://github.com/${e10.user}/${e10.repo}`;
    else throw new Error("You need to specify either the `repoUrl` option or both the `user` and `repo` options");
    let t = new URL(`${r}/issues/new`), n = ["body", "title", "labels", "template", "milestone", "assignee", "projects"];
    for (let i of n) {
      let o = e10[i];
      if (o !== void 0) {
        if (i === "labels" || i === "projects") {
          if (!Array.isArray(o)) throw new TypeError(`The \`${i}\` option should be an array`);
          o = o.join(",");
        }
        t.searchParams.set(i, o);
      }
    }
    return t.toString();
  };
  un.exports.default = un.exports;
});
var Ki = ne((Sb, ia) => {
  ia.exports = /* @__PURE__ */ (function() {
    function e10(r, t, n, i, o) {
      return r < t || n < t ? r > n ? n + 1 : r + 1 : i === o ? t : t + 1;
    }
    return function(r, t) {
      if (r === t) return 0;
      if (r.length > t.length) {
        var n = r;
        r = t, t = n;
      }
      for (var i = r.length, o = t.length; i > 0 && r.charCodeAt(i - 1) === t.charCodeAt(o - 1); ) i--, o--;
      for (var s = 0; s < i && r.charCodeAt(s) === t.charCodeAt(s); ) s++;
      if (i -= s, o -= s, i === 0 || o < 3) return o;
      var a = 0, l, u, c, p, d, f, h, g, D, T, S, b, O = [];
      for (l = 0; l < i; l++) O.push(l + 1), O.push(r.charCodeAt(s + l));
      for (var me = O.length - 1; a < o - 3; ) for (D = t.charCodeAt(s + (u = a)), T = t.charCodeAt(s + (c = a + 1)), S = t.charCodeAt(s + (p = a + 2)), b = t.charCodeAt(s + (d = a + 3)), f = a += 4, l = 0; l < me; l += 2) h = O[l], g = O[l + 1], u = e10(h, u, c, D, g), c = e10(u, c, p, T, g), p = e10(c, p, d, S, g), f = e10(p, d, f, b, g), O[l] = f, d = p, p = c, c = u, u = h;
      for (; a < o; ) for (D = t.charCodeAt(s + (u = a)), f = ++a, l = 0; l < me; l += 2) h = O[l], O[l] = f = e10(h, u, f, D, O[l + 1]), u = h;
      return f;
    };
  })();
});
var ua = Oo(() => {
});
var ca = Oo(() => {
});
var Qf = {};
tr(Qf, { DMMF: () => ut, Debug: () => N, Decimal: () => Fe, Extensions: () => ni, MetricsClient: () => Nr, PrismaClientInitializationError: () => P, PrismaClientKnownRequestError: () => z, PrismaClientRustPanicError: () => le, PrismaClientUnknownRequestError: () => V, PrismaClientValidationError: () => Z, Public: () => ii, Sql: () => oe, createParam: () => Ra, defineDmmfProperty: () => ka, deserializeJsonResponse: () => qr, deserializeRawResult: () => Xn, dmmfToRuntimeDataModel: () => $s, empty: () => La, getPrismaClient: () => bu, getRuntime: () => Gn, join: () => Na, makeStrictEnum: () => Eu, makeTypedQueryFactory: () => _a, objectEnumValues: () => Dn, raw: () => no, serializeJsonQuery: () => Mn, skip: () => Fn, sqltag: () => io, warnEnvConflicts: () => wu, warnOnce: () => st });
var library = Ru(Qf);
var ni = {};
tr(ni, { defineExtension: () => _o, getExtensionContext: () => No });
function _o(e10) {
  return typeof e10 == "function" ? e10 : (r) => r.$extends(e10);
}
function No(e10) {
  return e10;
}
var ii = {};
tr(ii, { validator: () => Lo });
function Lo(...e10) {
  return (r) => r;
}
var jt = {};
tr(jt, { $: () => Vo, bgBlack: () => Fu, bgBlue: () => Vu, bgCyan: () => Bu, bgGreen: () => $u, bgMagenta: () => ju, bgRed: () => Mu, bgWhite: () => Uu, bgYellow: () => qu, black: () => ku, blue: () => nr, bold: () => W, cyan: () => De, dim: () => Ce, gray: () => Kr, green: () => qe, grey: () => Lu, hidden: () => Du, inverse: () => Iu, italic: () => Cu, magenta: () => _u, red: () => ce, reset: () => Au, strikethrough: () => Ou, underline: () => Y, white: () => Nu, yellow: () => Ie });
var oi, Fo, Mo, $o, qo = true;
typeof process < "u" && ({ FORCE_COLOR: oi, NODE_DISABLE_COLORS: Fo, NO_COLOR: Mo, TERM: $o } = process.env || {}, qo = process.stdout && process.stdout.isTTY);
var Vo = { enabled: !Fo && Mo == null && $o !== "dumb" && (oi != null && oi !== "0" || qo) };
function F(e10, r) {
  let t = new RegExp(`\\x1b\\[${r}m`, "g"), n = `\x1B[${e10}m`, i = `\x1B[${r}m`;
  return function(o) {
    return !Vo.enabled || o == null ? o : n + (~("" + o).indexOf(i) ? o.replace(t, i + n) : o) + i;
  };
}
var Au = F(0, 0), W = F(1, 22), Ce = F(2, 22), Cu = F(3, 23), Y = F(4, 24), Iu = F(7, 27), Du = F(8, 28), Ou = F(9, 29), ku = F(30, 39), ce = F(31, 39), qe = F(32, 39), Ie = F(33, 39), nr = F(34, 39), _u = F(35, 39), De = F(36, 39), Nu = F(37, 39), Kr = F(90, 39), Lu = F(90, 39), Fu = F(40, 49), Mu = F(41, 49), $u = F(42, 49), qu = F(43, 49), Vu = F(44, 49), ju = F(45, 49), Bu = F(46, 49), Uu = F(47, 49);
var Gu = 100, jo = ["green", "yellow", "blue", "magenta", "cyan", "red"], Hr = [], Bo = Date.now(), Qu = 0, si = typeof process < "u" ? process.env : {};
(_b = globalThis.DEBUG) != null ? _b : globalThis.DEBUG = (_a2 = si.DEBUG) != null ? _a2 : "";
(_c2 = globalThis.DEBUG_COLORS) != null ? _c2 : globalThis.DEBUG_COLORS = si.DEBUG_COLORS ? si.DEBUG_COLORS === "true" : true;
var Yr = { enable(e10) {
  typeof e10 == "string" && (globalThis.DEBUG = e10);
}, disable() {
  let e10 = globalThis.DEBUG;
  return globalThis.DEBUG = "", e10;
}, enabled(e10) {
  let r = globalThis.DEBUG.split(",").map((i) => i.replace(/[.+?^${}()|[\]\\]/g, "\\$&")), t = r.some((i) => i === "" || i[0] === "-" ? false : e10.match(RegExp(i.split("*").join(".*") + "$"))), n = r.some((i) => i === "" || i[0] !== "-" ? false : e10.match(RegExp(i.slice(1).split("*").join(".*") + "$")));
  return t && !n;
}, log: (...e10) => {
  var _a3;
  let [r, t, ...n] = e10;
  ((_a3 = console.warn) != null ? _a3 : console.log)(`${r} ${t}`, ...n);
}, formatters: {} };
function Wu(e10) {
  let r = { color: jo[Qu++ % jo.length], enabled: Yr.enabled(e10), namespace: e10, log: Yr.log, extend: () => {
  } }, t = (...n) => {
    let { enabled: i, namespace: o, color: s, log: a } = r;
    if (n.length !== 0 && Hr.push([o, ...n]), Hr.length > Gu && Hr.shift(), Yr.enabled(o) || i) {
      let l = n.map((c) => typeof c == "string" ? c : Ju(c)), u = `+${Date.now() - Bo}ms`;
      Bo = Date.now(), globalThis.DEBUG_COLORS ? a(jt[s](W(o)), ...l, jt[s](u)) : a(o, ...l, u);
    }
  };
  return new Proxy(t, { get: (n, i) => r[i], set: (n, i, o) => r[i] = o });
}
var N = new Proxy(Wu, { get: (e10, r) => Yr[r], set: (e10, r, t) => Yr[r] = t });
function Ju(e10, r = 2) {
  let t = /* @__PURE__ */ new Set();
  return JSON.stringify(e10, (n, i) => {
    if (typeof i == "object" && i !== null) {
      if (t.has(i)) return "[Circular *]";
      t.add(i);
    } else if (typeof i == "bigint") return i.toString();
    return i;
  }, r);
}
function Uo(e10 = 7500) {
  let r = Hr.map(([t, ...n]) => `${t} ${n.map((i) => typeof i == "string" ? i : JSON.stringify(i)).join(" ")}`).join(`
`);
  return r.length < e10 ? r : r.slice(-e10);
}
function Go() {
  Hr.length = 0;
}
var gr = N;
var Qo = A(require$$2$1);
function ai() {
  let e10 = process.env.PRISMA_QUERY_ENGINE_LIBRARY;
  if (!(e10 && Qo.default.existsSync(e10)) && process.arch === "ia32") throw new Error('The default query engine type (Node-API, "library") is currently not supported for 32bit Node. Please set `engineType = "binary"` in the "generator" block of your "schema.prisma" file (or use the environment variables "PRISMA_CLIENT_ENGINE_TYPE=binary" and/or "PRISMA_CLI_QUERY_ENGINE_TYPE=binary".)');
}
var li = ["darwin", "darwin-arm64", "debian-openssl-1.0.x", "debian-openssl-1.1.x", "debian-openssl-3.0.x", "rhel-openssl-1.0.x", "rhel-openssl-1.1.x", "rhel-openssl-3.0.x", "linux-arm64-openssl-1.1.x", "linux-arm64-openssl-1.0.x", "linux-arm64-openssl-3.0.x", "linux-arm-openssl-1.1.x", "linux-arm-openssl-1.0.x", "linux-arm-openssl-3.0.x", "linux-musl", "linux-musl-openssl-3.0.x", "linux-musl-arm64-openssl-1.1.x", "linux-musl-arm64-openssl-3.0.x", "linux-nixos", "linux-static-x64", "linux-static-arm64", "windows", "freebsd11", "freebsd12", "freebsd13", "freebsd14", "freebsd15", "openbsd", "netbsd", "arm"];
var Bt = "libquery_engine";
function Ut(e10, r) {
  return e10.includes("windows") ? `query_engine-${e10}.dll.node` : e10.includes("darwin") ? `${Bt}-${e10}.dylib.node` : `${Bt}-${e10}.so.node`;
}
var Ho = A(require$$5), mi = A(require$$6), Kt = A(require$$0);
var Oe = Symbol.for("@ts-pattern/matcher"), Ku = Symbol.for("@ts-pattern/isVariadic"), Qt = "@ts-pattern/anonymous-select-key", ui = (e10) => !!(e10 && typeof e10 == "object"), Gt = (e10) => e10 && !!e10[Oe], Ee = (e10, r, t) => {
  if (Gt(e10)) {
    let n = e10[Oe](), { matched: i, selections: o } = n.match(r);
    return i && o && Object.keys(o).forEach((s) => t(s, o[s])), i;
  }
  if (ui(e10)) {
    if (!ui(r)) return false;
    if (Array.isArray(e10)) {
      if (!Array.isArray(r)) return false;
      let n = [], i = [], o = [];
      for (let s of e10.keys()) {
        let a = e10[s];
        Gt(a) && a[Ku] ? o.push(a) : o.length ? i.push(a) : n.push(a);
      }
      if (o.length) {
        if (o.length > 1) throw new Error("Pattern error: Using `...P.array(...)` several times in a single pattern is not allowed.");
        if (r.length < n.length + i.length) return false;
        let s = r.slice(0, n.length), a = i.length === 0 ? [] : r.slice(-i.length), l = r.slice(n.length, i.length === 0 ? 1 / 0 : -i.length);
        return n.every((u, c) => Ee(u, s[c], t)) && i.every((u, c) => Ee(u, a[c], t)) && (o.length === 0 || Ee(o[0], l, t));
      }
      return e10.length === r.length && e10.every((s, a) => Ee(s, r[a], t));
    }
    return Reflect.ownKeys(e10).every((n) => {
      let i = e10[n];
      return (n in r || Gt(o = i) && o[Oe]().matcherType === "optional") && Ee(i, r[n], t);
      var o;
    });
  }
  return Object.is(r, e10);
}, Ge = (e10) => {
  var r, t, n;
  return ui(e10) ? Gt(e10) ? (r = (t = (n = e10[Oe]()).getSelectionKeys) == null ? void 0 : t.call(n)) != null ? r : [] : Array.isArray(e10) ? zr(e10, Ge) : zr(Object.values(e10), Ge) : [];
}, zr = (e10, r) => e10.reduce((t, n) => t.concat(r(n)), []);
function pe(e10) {
  return Object.assign(e10, { optional: () => Hu(e10), and: (r) => q(e10, r), or: (r) => Yu(e10, r), select: (r) => r === void 0 ? Wo(e10) : Wo(r, e10) });
}
function Hu(e10) {
  return pe({ [Oe]: () => ({ match: (r) => {
    let t = {}, n = (i, o) => {
      t[i] = o;
    };
    return r === void 0 ? (Ge(e10).forEach((i) => n(i, void 0)), { matched: true, selections: t }) : { matched: Ee(e10, r, n), selections: t };
  }, getSelectionKeys: () => Ge(e10), matcherType: "optional" }) });
}
function q(...e10) {
  return pe({ [Oe]: () => ({ match: (r) => {
    let t = {}, n = (i, o) => {
      t[i] = o;
    };
    return { matched: e10.every((i) => Ee(i, r, n)), selections: t };
  }, getSelectionKeys: () => zr(e10, Ge), matcherType: "and" }) });
}
function Yu(...e10) {
  return pe({ [Oe]: () => ({ match: (r) => {
    let t = {}, n = (i, o) => {
      t[i] = o;
    };
    return zr(e10, Ge).forEach((i) => n(i, void 0)), { matched: e10.some((i) => Ee(i, r, n)), selections: t };
  }, getSelectionKeys: () => zr(e10, Ge), matcherType: "or" }) });
}
function C(e10) {
  return { [Oe]: () => ({ match: (r) => ({ matched: !!e10(r) }) }) };
}
function Wo(...e10) {
  let r = typeof e10[0] == "string" ? e10[0] : void 0, t = e10.length === 2 ? e10[1] : typeof e10[0] == "string" ? void 0 : e10[0];
  return pe({ [Oe]: () => ({ match: (n) => {
    let i = { [r != null ? r : Qt]: n };
    return { matched: t === void 0 || Ee(t, n, (o, s) => {
      i[o] = s;
    }), selections: i };
  }, getSelectionKeys: () => [r != null ? r : Qt].concat(t === void 0 ? [] : Ge(t)) }) });
}
function ye(e10) {
  return typeof e10 == "number";
}
function Ve(e10) {
  return typeof e10 == "string";
}
function je(e10) {
  return typeof e10 == "bigint";
}
pe(C(function(e10) {
  return true;
}));
var Be = (e10) => Object.assign(pe(e10), { startsWith: (r) => {
  return Be(q(e10, (t = r, C((n) => Ve(n) && n.startsWith(t)))));
  var t;
}, endsWith: (r) => {
  return Be(q(e10, (t = r, C((n) => Ve(n) && n.endsWith(t)))));
  var t;
}, minLength: (r) => Be(q(e10, ((t) => C((n) => Ve(n) && n.length >= t))(r))), length: (r) => Be(q(e10, ((t) => C((n) => Ve(n) && n.length === t))(r))), maxLength: (r) => Be(q(e10, ((t) => C((n) => Ve(n) && n.length <= t))(r))), includes: (r) => {
  return Be(q(e10, (t = r, C((n) => Ve(n) && n.includes(t)))));
  var t;
}, regex: (r) => {
  return Be(q(e10, (t = r, C((n) => Ve(n) && !!n.match(t)))));
  var t;
} }); Be(C(Ve)); var be = (e10) => Object.assign(pe(e10), { between: (r, t) => be(q(e10, ((n, i) => C((o) => ye(o) && n <= o && i >= o))(r, t))), lt: (r) => be(q(e10, ((t) => C((n) => ye(n) && n < t))(r))), gt: (r) => be(q(e10, ((t) => C((n) => ye(n) && n > t))(r))), lte: (r) => be(q(e10, ((t) => C((n) => ye(n) && n <= t))(r))), gte: (r) => be(q(e10, ((t) => C((n) => ye(n) && n >= t))(r))), int: () => be(q(e10, C((r) => ye(r) && Number.isInteger(r)))), finite: () => be(q(e10, C((r) => ye(r) && Number.isFinite(r)))), positive: () => be(q(e10, C((r) => ye(r) && r > 0))), negative: () => be(q(e10, C((r) => ye(r) && r < 0))) }); be(C(ye)); var Ue = (e10) => Object.assign(pe(e10), { between: (r, t) => Ue(q(e10, ((n, i) => C((o) => je(o) && n <= o && i >= o))(r, t))), lt: (r) => Ue(q(e10, ((t) => C((n) => je(n) && n < t))(r))), gt: (r) => Ue(q(e10, ((t) => C((n) => je(n) && n > t))(r))), lte: (r) => Ue(q(e10, ((t) => C((n) => je(n) && n <= t))(r))), gte: (r) => Ue(q(e10, ((t) => C((n) => je(n) && n >= t))(r))), positive: () => Ue(q(e10, C((r) => je(r) && r > 0))), negative: () => Ue(q(e10, C((r) => je(r) && r < 0))) }); Ue(C(je)); pe(C(function(e10) {
  return typeof e10 == "boolean";
})); pe(C(function(e10) {
  return typeof e10 == "symbol";
})); pe(C(function(e10) {
  return e10 == null;
})); pe(C(function(e10) {
  return e10 != null;
}));
var ci = class extends Error {
  constructor(r) {
    let t;
    try {
      t = JSON.stringify(r);
    } catch {
      t = r;
    }
    super(`Pattern matching error: no pattern matches value ${t}`), this.input = void 0, this.input = r;
  }
}, pi = { matched: false, value: void 0 };
function hr(e10) {
  return new di(e10, pi);
}
var di = class e {
  constructor(r, t) {
    this.input = void 0, this.state = void 0, this.input = r, this.state = t;
  }
  with(...r) {
    if (this.state.matched) return this;
    let t = r[r.length - 1], n = [r[0]], i;
    r.length === 3 && typeof r[1] == "function" ? i = r[1] : r.length > 2 && n.push(...r.slice(1, r.length - 1));
    let o = false, s = {}, a = (u, c) => {
      o = true, s[u] = c;
    }, l = !n.some((u) => Ee(u, this.input, a)) || i && !i(this.input) ? pi : { matched: true, value: t(o ? Qt in s ? s[Qt] : s : this.input, this.input) };
    return new e(this.input, l);
  }
  when(r, t) {
    if (this.state.matched) return this;
    let n = !!r(this.input);
    return new e(this.input, n ? { matched: true, value: t(this.input, this.input) } : pi);
  }
  otherwise(r) {
    return this.state.matched ? this.state.value : r(this.input);
  }
  exhaustive() {
    if (this.state.matched) return this.state.value;
    throw new ci(this.input);
  }
  run() {
    return this.exhaustive();
  }
  returnType() {
    return this;
  }
};
var Yo = require$$7;
var zu = { warn: Ie("prisma:warn") }, Zu = { warn: () => !process.env.PRISMA_DISABLE_WARNINGS };
function Wt(e10, ...r) {
  Zu.warn() && console.warn(`${zu.warn} ${e10}`, ...r);
}
var Xu = (0, Yo.promisify)(Ho.default.exec), ee = gr("prisma:get-platform"), ec = ["1.0.x", "1.1.x", "3.0.x"];
async function zo() {
  let e10 = Kt.default.platform(), r = process.arch;
  if (e10 === "freebsd") {
    let s = await Ht("freebsd-version");
    if (s && s.trim().length > 0) {
      let l = /^(\d+)\.?/.exec(s);
      if (l) return { platform: "freebsd", targetDistro: `freebsd${l[1]}`, arch: r };
    }
  }
  if (e10 !== "linux") return { platform: e10, arch: r };
  let t = await tc(), n = await cc(), i = ic({ arch: r, archFromUname: n, familyDistro: t.familyDistro }), { libssl: o } = await oc(i);
  return { platform: "linux", libssl: o, arch: r, archFromUname: n, ...t };
}
function rc(e10) {
  let r = /^ID="?([^"\n]*)"?$/im, t = /^ID_LIKE="?([^"\n]*)"?$/im, n = r.exec(e10), i = n && n[1] && n[1].toLowerCase() || "", o = t.exec(e10), s = o && o[1] && o[1].toLowerCase() || "", a = hr({ id: i, idLike: s }).with({ id: "alpine" }, ({ id: l }) => ({ targetDistro: "musl", familyDistro: l, originalDistro: l })).with({ id: "raspbian" }, ({ id: l }) => ({ targetDistro: "arm", familyDistro: "debian", originalDistro: l })).with({ id: "nixos" }, ({ id: l }) => ({ targetDistro: "nixos", originalDistro: l, familyDistro: "nixos" })).with({ id: "debian" }, { id: "ubuntu" }, ({ id: l }) => ({ targetDistro: "debian", familyDistro: "debian", originalDistro: l })).with({ id: "rhel" }, { id: "centos" }, { id: "fedora" }, ({ id: l }) => ({ targetDistro: "rhel", familyDistro: "rhel", originalDistro: l })).when(({ idLike: l }) => l.includes("debian") || l.includes("ubuntu"), ({ id: l }) => ({ targetDistro: "debian", familyDistro: "debian", originalDistro: l })).when(({ idLike: l }) => i === "arch" || l.includes("arch"), ({ id: l }) => ({ targetDistro: "debian", familyDistro: "arch", originalDistro: l })).when(({ idLike: l }) => l.includes("centos") || l.includes("fedora") || l.includes("rhel") || l.includes("suse"), ({ id: l }) => ({ targetDistro: "rhel", familyDistro: "rhel", originalDistro: l })).otherwise(({ id: l }) => ({ targetDistro: void 0, familyDistro: void 0, originalDistro: l }));
  return ee(`Found distro info:
${JSON.stringify(a, null, 2)}`), a;
}
async function tc() {
  let e10 = "/etc/os-release";
  try {
    let r = await mi.default.readFile(e10, { encoding: "utf-8" });
    return rc(r);
  } catch {
    return { targetDistro: void 0, familyDistro: void 0, originalDistro: void 0 };
  }
}
function nc(e10) {
  let r = /^OpenSSL\s(\d+\.\d+)\.\d+/.exec(e10);
  if (r) {
    let t = `${r[1]}.x`;
    return Zo(t);
  }
}
function Jo(e10) {
  var _a3;
  let r = /libssl\.so\.(\d)(\.\d)?/.exec(e10);
  if (r) {
    let t = `${r[1]}${(_a3 = r[2]) != null ? _a3 : ".0"}.x`;
    return Zo(t);
  }
}
function Zo(e10) {
  let r = (() => {
    if (es(e10)) return e10;
    let t = e10.split(".");
    return t[1] = "0", t.join(".");
  })();
  if (ec.includes(r)) return r;
}
function ic(e10) {
  return hr(e10).with({ familyDistro: "musl" }, () => (ee('Trying platform-specific paths for "alpine"'), ["/lib", "/usr/lib"])).with({ familyDistro: "debian" }, ({ archFromUname: r }) => (ee('Trying platform-specific paths for "debian" (and "ubuntu")'), [`/usr/lib/${r}-linux-gnu`, `/lib/${r}-linux-gnu`])).with({ familyDistro: "rhel" }, () => (ee('Trying platform-specific paths for "rhel"'), ["/lib64", "/usr/lib64"])).otherwise(({ familyDistro: r, arch: t, archFromUname: n }) => (ee(`Don't know any platform-specific paths for "${r}" on ${t} (${n})`), []));
}
async function oc(e10) {
  let r = 'grep -v "libssl.so.0"', t = await Ko(e10);
  if (t) {
    ee(`Found libssl.so file using platform-specific paths: ${t}`);
    let o = Jo(t);
    if (ee(`The parsed libssl version is: ${o}`), o) return { libssl: o, strategy: "libssl-specific-path" };
  }
  ee('Falling back to "ldconfig" and other generic paths');
  let n = await Ht(`ldconfig -p | sed "s/.*=>s*//" | sed "s|.*/||" | grep libssl | sort | ${r}`);
  if (n || (n = await Ko(["/lib64", "/usr/lib64", "/lib", "/usr/lib"])), n) {
    ee(`Found libssl.so file using "ldconfig" or other generic paths: ${n}`);
    let o = Jo(n);
    if (ee(`The parsed libssl version is: ${o}`), o) return { libssl: o, strategy: "ldconfig" };
  }
  let i = await Ht("openssl version -v");
  if (i) {
    ee(`Found openssl binary with version: ${i}`);
    let o = nc(i);
    if (ee(`The parsed openssl version is: ${o}`), o) return { libssl: o, strategy: "openssl-binary" };
  }
  return ee("Couldn't find any version of libssl or OpenSSL in the system"), {};
}
async function Ko(e10) {
  for (let r of e10) {
    let t = await sc(r);
    if (t) return t;
  }
}
async function sc(e10) {
  try {
    return (await mi.default.readdir(e10)).find((t) => t.startsWith("libssl.so.") && !t.startsWith("libssl.so.0"));
  } catch (r) {
    if (r.code === "ENOENT") return;
    throw r;
  }
}
async function ir() {
  let { binaryTarget: e10 } = await Xo();
  return e10;
}
function ac(e10) {
  return e10.binaryTarget !== void 0;
}
async function fi() {
  let { memoized: e10, ...r } = await Xo();
  return r;
}
var Jt = {};
async function Xo() {
  if (ac(Jt)) return Promise.resolve({ ...Jt, memoized: true });
  let e10 = await zo(), r = lc(e10);
  return Jt = { ...e10, binaryTarget: r }, { ...Jt, memoized: false };
}
function lc(e10) {
  let { platform: r, arch: t, archFromUname: n, libssl: i, targetDistro: o, familyDistro: s, originalDistro: a } = e10;
  r === "linux" && !["x64", "arm64"].includes(t) && Wt(`Prisma only officially supports Linux on amd64 (x86_64) and arm64 (aarch64) system architectures (detected "${t}" instead). If you are using your own custom Prisma engines, you can ignore this warning, as long as you've compiled the engines for your system architecture "${n}".`);
  let l = "1.1.x";
  if (r === "linux" && i === void 0) {
    let c = hr({ familyDistro: s }).with({ familyDistro: "debian" }, () => "Please manually install OpenSSL via `apt-get update -y && apt-get install -y openssl` and try installing Prisma again. If you're running Prisma on Docker, add this command to your Dockerfile, or switch to an image that already has OpenSSL installed.").otherwise(() => "Please manually install OpenSSL and try installing Prisma again.");
    Wt(`Prisma failed to detect the libssl/openssl version to use, and may not work as expected. Defaulting to "openssl-${l}".
${c}`);
  }
  let u = "debian";
  if (r === "linux" && o === void 0 && ee(`Distro is "${a}". Falling back to Prisma engines built for "${u}".`), r === "darwin" && t === "arm64") return "darwin-arm64";
  if (r === "darwin") return "darwin";
  if (r === "win32") return "windows";
  if (r === "freebsd") return o;
  if (r === "openbsd") return "openbsd";
  if (r === "netbsd") return "netbsd";
  if (r === "linux" && o === "nixos") return "linux-nixos";
  if (r === "linux" && t === "arm64") return `${o === "musl" ? "linux-musl-arm64" : "linux-arm64"}-openssl-${i || l}`;
  if (r === "linux" && t === "arm") return `linux-arm-openssl-${i || l}`;
  if (r === "linux" && o === "musl") {
    let c = "linux-musl";
    return !i || es(i) ? c : `${c}-openssl-${i}`;
  }
  return r === "linux" && o && i ? `${o}-openssl-${i}` : (r !== "linux" && Wt(`Prisma detected unknown OS "${r}" and may not work as expected. Defaulting to "linux".`), i ? `${u}-openssl-${i}` : o ? `${o}-openssl-${l}` : `${u}-openssl-${l}`);
}
async function uc(e10) {
  try {
    return await e10();
  } catch {
    return;
  }
}
function Ht(e10) {
  return uc(async () => {
    let r = await Xu(e10);
    return ee(`Command "${e10}" successfully returned "${r.stdout}"`), r.stdout;
  });
}
async function cc() {
  var _a3;
  return typeof Kt.default.machine == "function" ? Kt.default.machine() : (_a3 = await Ht("uname -m")) == null ? void 0 : _a3.trim();
}
function es(e10) {
  return e10.startsWith("1.");
}
var Zt = {};
tr(Zt, { beep: () => Fc, clearScreen: () => kc, clearTerminal: () => _c, cursorBackward: () => yc, cursorDown: () => gc, cursorForward: () => hc, cursorGetPosition: () => wc, cursorHide: () => Pc, cursorLeft: () => ns, cursorMove: () => fc, cursorNextLine: () => xc, cursorPrevLine: () => vc, cursorRestorePosition: () => Ec, cursorSavePosition: () => bc, cursorShow: () => Tc, cursorTo: () => mc, cursorUp: () => ts, enterAlternativeScreen: () => Nc, eraseDown: () => Cc, eraseEndLine: () => Rc, eraseLine: () => is, eraseLines: () => Sc, eraseScreen: () => gi, eraseStartLine: () => Ac, eraseUp: () => Ic, exitAlternativeScreen: () => Lc, iTerm: () => qc, image: () => $c, link: () => Mc, scrollDown: () => Oc, scrollUp: () => Dc });
var zt = A(require$$8, 1);
var Yt = ((_d2 = globalThis.window) == null ? void 0 : _d2.document) !== void 0; ((_f2 = (_e = globalThis.process) == null ? void 0 : _e.versions) == null ? void 0 : _f2.node) !== void 0; ((_h = (_g = globalThis.process) == null ? void 0 : _g.versions) == null ? void 0 : _h.bun) !== void 0; ((_j = (_i2 = globalThis.Deno) == null ? void 0 : _i2.version) == null ? void 0 : _j.deno) !== void 0; ((_l2 = (_k = globalThis.process) == null ? void 0 : _k.versions) == null ? void 0 : _l2.electron) !== void 0; ((_n2 = (_m2 = globalThis.navigator) == null ? void 0 : _m2.userAgent) == null ? void 0 : _n2.includes("jsdom")) === true; typeof WorkerGlobalScope < "u" && globalThis instanceof WorkerGlobalScope; typeof DedicatedWorkerGlobalScope < "u" && globalThis instanceof DedicatedWorkerGlobalScope; typeof SharedWorkerGlobalScope < "u" && globalThis instanceof SharedWorkerGlobalScope; typeof ServiceWorkerGlobalScope < "u" && globalThis instanceof ServiceWorkerGlobalScope; var Zr = (_p2 = (_o2 = globalThis.navigator) == null ? void 0 : _o2.userAgentData) == null ? void 0 : _p2.platform; Zr === "macOS" || ((_q = globalThis.navigator) == null ? void 0 : _q.platform) === "MacIntel" || ((_s2 = (_r2 = globalThis.navigator) == null ? void 0 : _r2.userAgent) == null ? void 0 : _s2.includes(" Mac ")) === true || ((_t2 = globalThis.process) == null ? void 0 : _t2.platform) === "darwin"; Zr === "Windows" || ((_u2 = globalThis.navigator) == null ? void 0 : _u2.platform) === "Win32" || ((_v = globalThis.process) == null ? void 0 : _v.platform) === "win32"; Zr === "Linux" || ((_x = (_w = globalThis.navigator) == null ? void 0 : _w.platform) == null ? void 0 : _x.startsWith("Linux")) === true || ((_z = (_y = globalThis.navigator) == null ? void 0 : _y.userAgent) == null ? void 0 : _z.includes(" Linux ")) === true || ((_A = globalThis.process) == null ? void 0 : _A.platform) === "linux"; Zr === "iOS" || ((_B = globalThis.navigator) == null ? void 0 : _B.platform) === "MacIntel" && ((_C = globalThis.navigator) == null ? void 0 : _C.maxTouchPoints) > 1 || /iPad|iPhone|iPod/.test((_D = globalThis.navigator) == null ? void 0 : _D.platform); Zr === "Android" || ((_E = globalThis.navigator) == null ? void 0 : _E.platform) === "Android" || ((_G = (_F = globalThis.navigator) == null ? void 0 : _F.userAgent) == null ? void 0 : _G.includes(" Android ")) === true || ((_H = globalThis.process) == null ? void 0 : _H.platform) === "android";
var I = "\x1B[", et = "\x1B]", yr = "\x07", Xr = ";", rs = !Yt && zt.default.env.TERM_PROGRAM === "Apple_Terminal", pc = !Yt && zt.default.platform === "win32", dc = Yt ? () => {
  throw new Error("`process.cwd()` only works in Node.js, not the browser.");
} : zt.default.cwd, mc = (e10, r) => {
  if (typeof e10 != "number") throw new TypeError("The `x` argument is required");
  return typeof r != "number" ? I + (e10 + 1) + "G" : I + (r + 1) + Xr + (e10 + 1) + "H";
}, fc = (e10, r) => {
  if (typeof e10 != "number") throw new TypeError("The `x` argument is required");
  let t = "";
  return e10 < 0 ? t += I + -e10 + "D" : e10 > 0 && (t += I + e10 + "C"), r < 0 ? t += I + -r + "A" : r > 0 && (t += I + r + "B"), t;
}, ts = (e10 = 1) => I + e10 + "A", gc = (e10 = 1) => I + e10 + "B", hc = (e10 = 1) => I + e10 + "C", yc = (e10 = 1) => I + e10 + "D", ns = I + "G", bc = rs ? "\x1B7" : I + "s", Ec = rs ? "\x1B8" : I + "u", wc = I + "6n", xc = I + "E", vc = I + "F", Pc = I + "?25l", Tc = I + "?25h", Sc = (e10) => {
  let r = "";
  for (let t = 0; t < e10; t++) r += is + (t < e10 - 1 ? ts() : "");
  return e10 && (r += ns), r;
}, Rc = I + "K", Ac = I + "1K", is = I + "2K", Cc = I + "J", Ic = I + "1J", gi = I + "2J", Dc = I + "S", Oc = I + "T", kc = "\x1Bc", _c = pc ? `${gi}${I}0f` : `${gi}${I}3J${I}H`, Nc = I + "?1049h", Lc = I + "?1049l", Fc = yr, Mc = (e10, r) => [et, "8", Xr, Xr, r, yr, e10, et, "8", Xr, Xr, yr].join(""), $c = (e10, r = {}) => {
  let t = `${et}1337;File=inline=1`;
  return r.width && (t += `;width=${r.width}`), r.height && (t += `;height=${r.height}`), r.preserveAspectRatio === false && (t += ";preserveAspectRatio=0"), t + ":" + Buffer.from(e10).toString("base64") + yr;
}, qc = { setCwd: (e10 = dc()) => `${et}50;CurrentDir=${e10}${yr}`, annotation(e10, r = {}) {
  let t = `${et}1337;`, n = r.x !== void 0, i = r.y !== void 0;
  if ((n || i) && !(n && i && r.length !== void 0)) throw new Error("`x`, `y` and `length` must be defined when `x` or `y` is defined");
  return e10 = e10.replaceAll("|", ""), t += r.isHidden ? "AddHiddenAnnotation=" : "AddAnnotation=", r.length > 0 ? t += (n ? [e10, r.length, r.x, r.y] : [r.length, e10]).join("|") : t += e10, t + yr;
} };
var Xt = A(ps(), 1);
function or(e10, r, { target: t = "stdout", ...n } = {}) {
  return Xt.default[t] ? Zt.link(e10, r) : n.fallback === false ? e10 : typeof n.fallback == "function" ? n.fallback(e10, r) : `${e10} (\u200B${r}\u200B)`;
}
or.isSupported = Xt.default.stdout;
or.stderr = (e10, r, t = {}) => or(e10, r, { target: "stderr", ...t });
or.stderr.isSupported = Xt.default.stderr;
function wi(e10) {
  return or(e10, e10, { fallback: Y });
}
var Gc = ds(), xi = Gc.version;
function Er(e10) {
  let r = Qc();
  return r || ((e10 == null ? void 0 : e10.config.engineType) === "library" ? "library" : (e10 == null ? void 0 : e10.config.engineType) === "binary" ? "binary" : (e10 == null ? void 0 : e10.config.engineType) === "client" ? "client" : Wc(e10));
}
function Qc() {
  let e10 = process.env.PRISMA_CLIENT_ENGINE_TYPE;
  return e10 === "library" ? "library" : e10 === "binary" ? "binary" : e10 === "client" ? "client" : void 0;
}
function Wc(e10) {
  return (e10 == null ? void 0 : e10.previewFeatures.includes("queryCompiler")) ? "client" : "library";
}
function vi(e10) {
  return e10.name === "DriverAdapterError" && typeof e10.cause == "object";
}
function en(e10) {
  return { ok: true, value: e10, map(r) {
    return en(r(e10));
  }, flatMap(r) {
    return r(e10);
  } };
}
function sr(e10) {
  return { ok: false, error: e10, map() {
    return sr(e10);
  }, flatMap() {
    return sr(e10);
  } };
}
var ms = N("driver-adapter-utils"), Pi = class {
  constructor() {
    __publicField(this, "registeredErrors", []);
  }
  consumeError(r) {
    return this.registeredErrors[r];
  }
  registerNewError(r) {
    let t = 0;
    for (; this.registeredErrors[t] !== void 0; ) t++;
    return this.registeredErrors[t] = { error: r }, t;
  }
};
var rn = (e10, r = new Pi()) => {
  let t = { adapterName: e10.adapterName, errorRegistry: r, queryRaw: ke(r, e10.queryRaw.bind(e10)), executeRaw: ke(r, e10.executeRaw.bind(e10)), executeScript: ke(r, e10.executeScript.bind(e10)), dispose: ke(r, e10.dispose.bind(e10)), provider: e10.provider, startTransaction: async (...n) => (await ke(r, e10.startTransaction.bind(e10))(...n)).map((o) => Jc(r, o)) };
  return e10.getConnectionInfo && (t.getConnectionInfo = Kc(r, e10.getConnectionInfo.bind(e10))), t;
}, Jc = (e10, r) => ({ adapterName: r.adapterName, provider: r.provider, options: r.options, queryRaw: ke(e10, r.queryRaw.bind(r)), executeRaw: ke(e10, r.executeRaw.bind(r)), commit: ke(e10, r.commit.bind(r)), rollback: ke(e10, r.rollback.bind(r)) });
function ke(e10, r) {
  return async (...t) => {
    try {
      return en(await r(...t));
    } catch (n) {
      if (ms("[error@wrapAsync]", n), vi(n)) return sr(n.cause);
      let i = e10.registerNewError(n);
      return sr({ kind: "GenericJs", id: i });
    }
  };
}
function Kc(e10, r) {
  return (...t) => {
    try {
      return en(r(...t));
    } catch (n) {
      if (ms("[error@wrapSync]", n), vi(n)) return sr(n.cause);
      let i = e10.registerNewError(n);
      return sr({ kind: "GenericJs", id: i });
    }
  };
}
A(nn());
var M = A(require$$3); A(nn()); N("prisma:engines");
function fs() {
  return M.default.join(__dirname, "../");
}
M.default.join(__dirname, "../query-engine-darwin");
M.default.join(__dirname, "../query-engine-darwin-arm64");
M.default.join(__dirname, "../query-engine-debian-openssl-1.0.x");
M.default.join(__dirname, "../query-engine-debian-openssl-1.1.x");
M.default.join(__dirname, "../query-engine-debian-openssl-3.0.x");
M.default.join(__dirname, "../query-engine-linux-static-x64");
M.default.join(__dirname, "../query-engine-linux-static-arm64");
M.default.join(__dirname, "../query-engine-rhel-openssl-1.0.x");
M.default.join(__dirname, "../query-engine-rhel-openssl-1.1.x");
M.default.join(__dirname, "../query-engine-rhel-openssl-3.0.x");
M.default.join(__dirname, "../libquery_engine-darwin.dylib.node");
M.default.join(__dirname, "../libquery_engine-darwin-arm64.dylib.node");
M.default.join(__dirname, "../libquery_engine-debian-openssl-1.0.x.so.node");
M.default.join(__dirname, "../libquery_engine-debian-openssl-1.1.x.so.node");
M.default.join(__dirname, "../libquery_engine-debian-openssl-3.0.x.so.node");
M.default.join(__dirname, "../libquery_engine-linux-arm64-openssl-1.0.x.so.node");
M.default.join(__dirname, "../libquery_engine-linux-arm64-openssl-1.1.x.so.node");
M.default.join(__dirname, "../libquery_engine-linux-arm64-openssl-3.0.x.so.node");
M.default.join(__dirname, "../libquery_engine-linux-musl.so.node");
M.default.join(__dirname, "../libquery_engine-linux-musl-openssl-3.0.x.so.node");
M.default.join(__dirname, "../libquery_engine-rhel-openssl-1.0.x.so.node");
M.default.join(__dirname, "../libquery_engine-rhel-openssl-1.1.x.so.node");
M.default.join(__dirname, "../libquery_engine-rhel-openssl-3.0.x.so.node");
M.default.join(__dirname, "../query_engine-windows.dll.node");
A(require$$2$1); gr("chmodPlusX");
function Ai(e10) {
  let r = e10.e, t = (a) => `Prisma cannot find the required \`${a}\` system library in your system`, n = r.message.includes("cannot open shared object file"), i = `Please refer to the documentation about Prisma's system requirements: ${wi("https://pris.ly/d/system-requirements")}`, o = `Unable to require(\`${Ce(e10.id)}\`).`, s = hr({ message: r.message, code: r.code }).with({ code: "ENOENT" }, () => "File does not exist.").when(({ message: a }) => n && a.includes("libz"), () => `${t("libz")}. Please install it and try again.`).when(({ message: a }) => n && a.includes("libgcc_s"), () => `${t("libgcc_s")}. Please install it and try again.`).when(({ message: a }) => n && a.includes("libssl"), () => {
    let a = e10.platformInfo.libssl ? `openssl-${e10.platformInfo.libssl}` : "openssl";
    return `${t("libssl")}. Please install ${a} and try again.`;
  }).when(({ message: a }) => a.includes("GLIBC"), () => `Prisma has detected an incompatible version of the \`glibc\` C standard library installed in your system. This probably means your system may be too old to run Prisma. ${i}`).when(({ message: a }) => e10.platformInfo.platform === "linux" && a.includes("symbol not found"), () => `The Prisma engines are not compatible with your system ${e10.platformInfo.originalDistro} on (${e10.platformInfo.archFromUname}) which uses the \`${e10.platformInfo.binaryTarget}\` binaryTarget by default. ${i}`).otherwise(() => `The Prisma engines do not seem to be compatible with your system. ${i}`);
  return `${o}
${s}

Details: ${r.message}`;
}
A(ys(), 1);
var Es = "prisma+postgres", on = `${Es}:`;
function sn(e10) {
  var _a3;
  return (_a3 = e10 == null ? void 0 : e10.toString().startsWith(`${on}//`)) != null ? _a3 : false;
}
function Ii(e10) {
  if (!sn(e10)) return false;
  let { host: r } = new URL(e10);
  return r.includes("localhost") || r.includes("127.0.0.1") || r.includes("[::1]");
}
var xs = A(Di());
function ki(e10) {
  return String(new Oi(e10));
}
var Oi = class {
  constructor(r) {
    this.config = r;
  }
  toString() {
    let { config: r } = this, t = r.provider.fromEnvVar ? `env("${r.provider.fromEnvVar}")` : r.provider.value, n = JSON.parse(JSON.stringify({ provider: t, binaryTargets: Zc(r.binaryTargets) }));
    return `generator ${r.name} {
${(0, xs.default)(Xc(n), 2)}
}`;
  }
};
function Zc(e10) {
  let r;
  if (e10.length > 0) {
    let t = e10.find((n) => n.fromEnvVar !== null);
    t ? r = `env("${t.fromEnvVar}")` : r = e10.map((n) => n.native ? "native" : n.value);
  } else r = void 0;
  return r;
}
function Xc(e10) {
  let r = Object.keys(e10).reduce((t, n) => Math.max(t, n.length), 0);
  return Object.entries(e10).map(([t, n]) => `${t.padEnd(r)} = ${ep(n)}`).join(`
`);
}
function ep(e10) {
  return JSON.parse(JSON.stringify(e10, (r, t) => Array.isArray(t) ? `[${t.map((n) => JSON.stringify(n)).join(", ")}]` : JSON.stringify(t)));
}
var tt = {};
tr(tt, { error: () => np, info: () => tp, log: () => rp, query: () => ip, should: () => vs, tags: () => rt, warn: () => _i });
var rt = { error: ce("prisma:error"), warn: Ie("prisma:warn"), info: De("prisma:info"), query: nr("prisma:query") }, vs = { warn: () => !process.env.PRISMA_DISABLE_WARNINGS };
function rp(...e10) {
  console.log(...e10);
}
function _i(e10, ...r) {
  vs.warn() && console.warn(`${rt.warn} ${e10}`, ...r);
}
function tp(e10, ...r) {
  console.info(`${rt.info} ${e10}`, ...r);
}
function np(e10, ...r) {
  console.error(`${rt.error} ${e10}`, ...r);
}
function ip(e10, ...r) {
  console.log(`${rt.query} ${e10}`, ...r);
}
function an(e10, r) {
  if (!e10) throw new Error(`${r}. This should never happen. If you see this error, please, open an issue at https://pris.ly/prisma-prisma-bug-report`);
}
function ar(e10, r) {
  throw new Error(r);
}
var nt = A(require$$3);
function Li(e10) {
  return nt.default.sep === nt.default.posix.sep ? e10 : e10.split(nt.default.sep).join(nt.default.posix.sep);
}
var qi = A(Os()), ln = A(require$$2$1);
var wr = A(require$$3);
function ks(e10) {
  let r = e10.ignoreProcessEnv ? {} : process.env, t = (n) => {
    var _a3, _b2;
    return (_b2 = (_a3 = n.match(/(.?\${(?:[a-zA-Z0-9_]+)?})/g)) == null ? void 0 : _a3.reduce(function(o, s) {
      let a = /(.?)\${([a-zA-Z0-9_]+)?}/g.exec(s);
      if (!a) return o;
      let l = a[1], u, c;
      if (l === "\\") c = a[0], u = c.replace("\\$", "$");
      else {
        let p = a[2];
        c = a[0].substring(l.length), u = Object.hasOwnProperty.call(r, p) ? r[p] : e10.parsed[p] || "", u = t(u);
      }
      return o.replace(c, u);
    }, n)) != null ? _b2 : n;
  };
  for (let n in e10.parsed) {
    let i = Object.hasOwnProperty.call(r, n) ? r[n] : e10.parsed[n];
    e10.parsed[n] = t(i);
  }
  for (let n in e10.parsed) r[n] = e10.parsed[n];
  return e10;
}
var $i = gr("prisma:tryLoadEnv");
function ot({ rootEnvPath: e10, schemaEnvPath: r }, t = { conflictCheck: "none" }) {
  var _a3, _b2;
  let n = _s(e10);
  t.conflictCheck !== "none" && wp(n, r, t.conflictCheck);
  let i = null;
  return Ns(n == null ? void 0 : n.path, r) || (i = _s(r)), !n && !i && $i("No Environment variables loaded"), (i == null ? void 0 : i.dotenvResult.error) ? console.error(ce(W("Schema Env Error: ")) + i.dotenvResult.error) : { message: [n == null ? void 0 : n.message, i == null ? void 0 : i.message].filter(Boolean).join(`
`), parsed: { ...(_a3 = n == null ? void 0 : n.dotenvResult) == null ? void 0 : _a3.parsed, ...(_b2 = i == null ? void 0 : i.dotenvResult) == null ? void 0 : _b2.parsed } };
}
function wp(e10, r, t) {
  let n = e10 == null ? void 0 : e10.dotenvResult.parsed, i = !Ns(e10 == null ? void 0 : e10.path, r);
  if (n && r && i && ln.default.existsSync(r)) {
    let o = qi.default.parse(ln.default.readFileSync(r)), s = [];
    for (let a in o) n[a] === o[a] && s.push(a);
    if (s.length > 0) {
      let a = wr.default.relative(process.cwd(), e10.path), l = wr.default.relative(process.cwd(), r);
      if (t === "error") {
        let u = `There is a conflict between env var${s.length > 1 ? "s" : ""} in ${Y(a)} and ${Y(l)}
Conflicting env vars:
${s.map((c) => `  ${W(c)}`).join(`
`)}

We suggest to move the contents of ${Y(l)} to ${Y(a)} to consolidate your env vars.
`;
        throw new Error(u);
      } else if (t === "warn") {
        let u = `Conflict for env var${s.length > 1 ? "s" : ""} ${s.map((c) => W(c)).join(", ")} in ${Y(a)} and ${Y(l)}
Env vars from ${Y(l)} overwrite the ones from ${Y(a)}
      `;
        console.warn(`${Ie("warn(prisma)")} ${u}`);
      }
    }
  }
}
function _s(e10) {
  if (xp(e10)) {
    $i(`Environment variables loaded from ${e10}`);
    let r = qi.default.config({ path: e10, debug: process.env.DOTENV_CONFIG_DEBUG ? true : void 0 });
    return { dotenvResult: ks(r), message: Ce(`Environment variables loaded from ${wr.default.relative(process.cwd(), e10)}`), path: e10 };
  } else $i(`Environment variables not found at ${e10}`);
  return null;
}
function Ns(e10, r) {
  return e10 && r && wr.default.resolve(e10) === wr.default.resolve(r);
}
function xp(e10) {
  return !!(e10 && ln.default.existsSync(e10));
}
function Vi(e10, r) {
  return Object.prototype.hasOwnProperty.call(e10, r);
}
function cn(e10, r) {
  let t = {};
  for (let n of Object.keys(e10)) t[n] = r(e10[n], n);
  return t;
}
function ji(e10, r) {
  if (e10.length === 0) return;
  let t = e10[0];
  for (let n = 1; n < e10.length; n++) r(t, e10[n]) < 0 && (t = e10[n]);
  return t;
}
function x(e10, r) {
  Object.defineProperty(e10, "name", { value: r, configurable: true });
}
var Fs = /* @__PURE__ */ new Set(), st = (e10, r, ...t) => {
  Fs.has(e10) || (Fs.add(e10), _i(r, ...t));
};
var P = class e2 extends Error {
  constructor(r, t, n) {
    super(r);
    __publicField(this, "clientVersion");
    __publicField(this, "errorCode");
    __publicField(this, "retryable");
    this.name = "PrismaClientInitializationError", this.clientVersion = t, this.errorCode = n, Error.captureStackTrace(e2);
  }
  get [Symbol.toStringTag]() {
    return "PrismaClientInitializationError";
  }
};
x(P, "PrismaClientInitializationError");
var z = class extends Error {
  constructor(r, { code: t, clientVersion: n, meta: i, batchRequestIdx: o }) {
    super(r);
    __publicField(this, "code");
    __publicField(this, "meta");
    __publicField(this, "clientVersion");
    __publicField(this, "batchRequestIdx");
    this.name = "PrismaClientKnownRequestError", this.code = t, this.clientVersion = n, this.meta = i, Object.defineProperty(this, "batchRequestIdx", { value: o, enumerable: false, writable: true });
  }
  get [Symbol.toStringTag]() {
    return "PrismaClientKnownRequestError";
  }
};
x(z, "PrismaClientKnownRequestError");
var le = class extends Error {
  constructor(r, t) {
    super(r);
    __publicField(this, "clientVersion");
    this.name = "PrismaClientRustPanicError", this.clientVersion = t;
  }
  get [Symbol.toStringTag]() {
    return "PrismaClientRustPanicError";
  }
};
x(le, "PrismaClientRustPanicError");
var V = class extends Error {
  constructor(r, { clientVersion: t, batchRequestIdx: n }) {
    super(r);
    __publicField(this, "clientVersion");
    __publicField(this, "batchRequestIdx");
    this.name = "PrismaClientUnknownRequestError", this.clientVersion = t, Object.defineProperty(this, "batchRequestIdx", { value: n, writable: true, enumerable: false });
  }
  get [Symbol.toStringTag]() {
    return "PrismaClientUnknownRequestError";
  }
};
x(V, "PrismaClientUnknownRequestError");
var Z = class extends Error {
  constructor(r, { clientVersion: t }) {
    super(r);
    __publicField(this, "name", "PrismaClientValidationError");
    __publicField(this, "clientVersion");
    this.clientVersion = t;
  }
  get [Symbol.toStringTag]() {
    return "PrismaClientValidationError";
  }
};
x(Z, "PrismaClientValidationError");
var we = class {
  constructor() {
    __publicField(this, "_map", /* @__PURE__ */ new Map());
  }
  get(r) {
    var _a3;
    return (_a3 = this._map.get(r)) == null ? void 0 : _a3.value;
  }
  set(r, t) {
    this._map.set(r, { value: t });
  }
  getOrCreate(r, t) {
    let n = this._map.get(r);
    if (n) return n.value;
    let i = t();
    return this.set(r, i), i;
  }
};
function We(e10) {
  return e10.substring(0, 1).toLowerCase() + e10.substring(1);
}
function Ms(e10, r) {
  let t = {};
  for (let n of e10) {
    let i = n[r];
    t[i] = n;
  }
  return t;
}
function at(e10) {
  let r;
  return { get() {
    return r || (r = { value: e10() }), r.value;
  } };
}
function $s(e10) {
  return { models: Bi(e10.models), enums: Bi(e10.enums), types: Bi(e10.types) };
}
function Bi(e10) {
  let r = {};
  for (let { name: t, ...n } of e10) r[t] = n;
  return r;
}
function xr(e10) {
  return e10 instanceof Date || Object.prototype.toString.call(e10) === "[object Date]";
}
function dn(e10) {
  return e10.toString() !== "Invalid Date";
}
var vr = 9e15, Ye = 1e9, Ui = "0123456789abcdef", gn = "2.3025850929940456840179914546843642076011014886287729760333279009675726096773524802359972050895982983419677840422862486334095254650828067566662873690987816894829072083255546808437998948262331985283935053089653777326288461633662222876982198867465436674744042432743651550489343149393914796194044002221051017141748003688084012647080685567743216228355220114804663715659121373450747856947683463616792101806445070648000277502684916746550586856935673420670581136429224554405758925724208241314695689016758940256776311356919292033376587141660230105703089634572075440370847469940168269282808481184289314848524948644871927809676271275775397027668605952496716674183485704422507197965004714951050492214776567636938662976979522110718264549734772662425709429322582798502585509785265383207606726317164309505995087807523710333101197857547331541421808427543863591778117054309827482385045648019095610299291824318237525357709750539565187697510374970888692180205189339507238539205144634197265287286965110862571492198849978748873771345686209167058", hn = "3.1415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679821480865132823066470938446095505822317253594081284811174502841027019385211055596446229489549303819644288109756659334461284756482337867831652712019091456485669234603486104543266482133936072602491412737245870066063155881748815209209628292540917153643678925903600113305305488204665213841469519415116094330572703657595919530921861173819326117931051185480744623799627495673518857527248912279381830119491298336733624406566430860213949463952247371907021798609437027705392171762931767523846748184676694051320005681271452635608277857713427577896091736371787214684409012249534301465495853710507922796892589235420199561121290219608640344181598136297747713099605187072113499999983729780499510597317328160963185950244594553469083026425223082533446850352619311881710100031378387528865875332083814206171776691473035982534904287554687311595628638823537875937519577818577805321712268066130019278766111959092164201989380952572010654858632789", Gi = { precision: 20, rounding: 4, modulo: 1, toExpNeg: -7, toExpPos: 21, minE: -vr, maxE: vr, crypto: false }, Bs, Ne, w = true, bn = "[DecimalError] ", He = bn + "Invalid argument: ", Us = bn + "Precision limit exceeded", Gs = bn + "crypto unavailable", Qs = "[object Decimal]", X = Math.floor, U = Math.pow, vp = /^0b([01]+(\.[01]*)?|\.[01]+)(p[+-]?\d+)?$/i, Pp = /^0x([0-9a-f]+(\.[0-9a-f]*)?|\.[0-9a-f]+)(p[+-]?\d+)?$/i, Tp = /^0o([0-7]+(\.[0-7]*)?|\.[0-7]+)(p[+-]?\d+)?$/i, Ws = /^(\d+(\.\d*)?|\.\d+)(e[+-]?\d+)?$/i, fe = 1e7, E = 7, Sp = 9007199254740991, Rp = gn.length - 1, Qi = hn.length - 1, m = { toStringTag: Qs };
m.absoluteValue = m.abs = function() {
  var e10 = new this.constructor(this);
  return e10.s < 0 && (e10.s = 1), y(e10);
};
m.ceil = function() {
  return y(new this.constructor(this), this.e + 1, 2);
};
m.clampedTo = m.clamp = function(e10, r) {
  var t, n = this, i = n.constructor;
  if (e10 = new i(e10), r = new i(r), !e10.s || !r.s) return new i(NaN);
  if (e10.gt(r)) throw Error(He + r);
  return t = n.cmp(e10), t < 0 ? e10 : n.cmp(r) > 0 ? r : new i(n);
};
m.comparedTo = m.cmp = function(e10) {
  var r, t, n, i, o = this, s = o.d, a = (e10 = new o.constructor(e10)).d, l = o.s, u = e10.s;
  if (!s || !a) return !l || !u ? NaN : l !== u ? l : s === a ? 0 : !s ^ l < 0 ? 1 : -1;
  if (!s[0] || !a[0]) return s[0] ? l : a[0] ? -u : 0;
  if (l !== u) return l;
  if (o.e !== e10.e) return o.e > e10.e ^ l < 0 ? 1 : -1;
  for (n = s.length, i = a.length, r = 0, t = n < i ? n : i; r < t; ++r) if (s[r] !== a[r]) return s[r] > a[r] ^ l < 0 ? 1 : -1;
  return n === i ? 0 : n > i ^ l < 0 ? 1 : -1;
};
m.cosine = m.cos = function() {
  var e10, r, t = this, n = t.constructor;
  return t.d ? t.d[0] ? (e10 = n.precision, r = n.rounding, n.precision = e10 + Math.max(t.e, t.sd()) + E, n.rounding = 1, t = Ap(n, zs(n, t)), n.precision = e10, n.rounding = r, y(Ne == 2 || Ne == 3 ? t.neg() : t, e10, r, true)) : new n(1) : new n(NaN);
};
m.cubeRoot = m.cbrt = function() {
  var e10, r, t, n, i, o, s, a, l, u, c = this, p = c.constructor;
  if (!c.isFinite() || c.isZero()) return new p(c);
  for (w = false, o = c.s * U(c.s * c, 1 / 3), !o || Math.abs(o) == 1 / 0 ? (t = J(c.d), e10 = c.e, (o = (e10 - t.length + 1) % 3) && (t += o == 1 || o == -2 ? "0" : "00"), o = U(t, 1 / 3), e10 = X((e10 + 1) / 3) - (e10 % 3 == (e10 < 0 ? -1 : 2)), o == 1 / 0 ? t = "5e" + e10 : (t = o.toExponential(), t = t.slice(0, t.indexOf("e") + 1) + e10), n = new p(t), n.s = c.s) : n = new p(o.toString()), s = (e10 = p.precision) + 3; ; ) if (a = n, l = a.times(a).times(a), u = l.plus(c), n = L(u.plus(c).times(a), u.plus(l), s + 2, 1), J(a.d).slice(0, s) === (t = J(n.d)).slice(0, s)) if (t = t.slice(s - 3, s + 1), t == "9999" || !i && t == "4999") {
    if (!i && (y(a, e10 + 1, 0), a.times(a).times(a).eq(c))) {
      n = a;
      break;
    }
    s += 4, i = 1;
  } else {
    (!+t || !+t.slice(1) && t.charAt(0) == "5") && (y(n, e10 + 1, 1), r = !n.times(n).times(n).eq(c));
    break;
  }
  return w = true, y(n, e10, p.rounding, r);
};
m.decimalPlaces = m.dp = function() {
  var e10, r = this.d, t = NaN;
  if (r) {
    if (e10 = r.length - 1, t = (e10 - X(this.e / E)) * E, e10 = r[e10], e10) for (; e10 % 10 == 0; e10 /= 10) t--;
    t < 0 && (t = 0);
  }
  return t;
};
m.dividedBy = m.div = function(e10) {
  return L(this, new this.constructor(e10));
};
m.dividedToIntegerBy = m.divToInt = function(e10) {
  var r = this, t = r.constructor;
  return y(L(r, new t(e10), 0, 1, 1), t.precision, t.rounding);
};
m.equals = m.eq = function(e10) {
  return this.cmp(e10) === 0;
};
m.floor = function() {
  return y(new this.constructor(this), this.e + 1, 3);
};
m.greaterThan = m.gt = function(e10) {
  return this.cmp(e10) > 0;
};
m.greaterThanOrEqualTo = m.gte = function(e10) {
  var r = this.cmp(e10);
  return r == 1 || r === 0;
};
m.hyperbolicCosine = m.cosh = function() {
  var e10, r, t, n, i, o = this, s = o.constructor, a = new s(1);
  if (!o.isFinite()) return new s(o.s ? 1 / 0 : NaN);
  if (o.isZero()) return a;
  t = s.precision, n = s.rounding, s.precision = t + Math.max(o.e, o.sd()) + 4, s.rounding = 1, i = o.d.length, i < 32 ? (e10 = Math.ceil(i / 3), r = (1 / wn(4, e10)).toString()) : (e10 = 16, r = "2.3283064365386962890625e-10"), o = Pr(s, 1, o.times(r), new s(1), true);
  for (var l, u = e10, c = new s(8); u--; ) l = o.times(o), o = a.minus(l.times(c.minus(l.times(c))));
  return y(o, s.precision = t, s.rounding = n, true);
};
m.hyperbolicSine = m.sinh = function() {
  var e10, r, t, n, i = this, o = i.constructor;
  if (!i.isFinite() || i.isZero()) return new o(i);
  if (r = o.precision, t = o.rounding, o.precision = r + Math.max(i.e, i.sd()) + 4, o.rounding = 1, n = i.d.length, n < 3) i = Pr(o, 2, i, i, true);
  else {
    e10 = 1.4 * Math.sqrt(n), e10 = e10 > 16 ? 16 : e10 | 0, i = i.times(1 / wn(5, e10)), i = Pr(o, 2, i, i, true);
    for (var s, a = new o(5), l = new o(16), u = new o(20); e10--; ) s = i.times(i), i = i.times(a.plus(s.times(l.times(s).plus(u))));
  }
  return o.precision = r, o.rounding = t, y(i, r, t, true);
};
m.hyperbolicTangent = m.tanh = function() {
  var e10, r, t = this, n = t.constructor;
  return t.isFinite() ? t.isZero() ? new n(t) : (e10 = n.precision, r = n.rounding, n.precision = e10 + 7, n.rounding = 1, L(t.sinh(), t.cosh(), n.precision = e10, n.rounding = r)) : new n(t.s);
};
m.inverseCosine = m.acos = function() {
  var e10 = this, r = e10.constructor, t = e10.abs().cmp(1), n = r.precision, i = r.rounding;
  return t !== -1 ? t === 0 ? e10.isNeg() ? xe(r, n, i) : new r(0) : new r(NaN) : e10.isZero() ? xe(r, n + 4, i).times(0.5) : (r.precision = n + 6, r.rounding = 1, e10 = new r(1).minus(e10).div(e10.plus(1)).sqrt().atan(), r.precision = n, r.rounding = i, e10.times(2));
};
m.inverseHyperbolicCosine = m.acosh = function() {
  var e10, r, t = this, n = t.constructor;
  return t.lte(1) ? new n(t.eq(1) ? 0 : NaN) : t.isFinite() ? (e10 = n.precision, r = n.rounding, n.precision = e10 + Math.max(Math.abs(t.e), t.sd()) + 4, n.rounding = 1, w = false, t = t.times(t).minus(1).sqrt().plus(t), w = true, n.precision = e10, n.rounding = r, t.ln()) : new n(t);
};
m.inverseHyperbolicSine = m.asinh = function() {
  var e10, r, t = this, n = t.constructor;
  return !t.isFinite() || t.isZero() ? new n(t) : (e10 = n.precision, r = n.rounding, n.precision = e10 + 2 * Math.max(Math.abs(t.e), t.sd()) + 6, n.rounding = 1, w = false, t = t.times(t).plus(1).sqrt().plus(t), w = true, n.precision = e10, n.rounding = r, t.ln());
};
m.inverseHyperbolicTangent = m.atanh = function() {
  var e10, r, t, n, i = this, o = i.constructor;
  return i.isFinite() ? i.e >= 0 ? new o(i.abs().eq(1) ? i.s / 0 : i.isZero() ? i : NaN) : (e10 = o.precision, r = o.rounding, n = i.sd(), Math.max(n, e10) < 2 * -i.e - 1 ? y(new o(i), e10, r, true) : (o.precision = t = n - i.e, i = L(i.plus(1), new o(1).minus(i), t + e10, 1), o.precision = e10 + 4, o.rounding = 1, i = i.ln(), o.precision = e10, o.rounding = r, i.times(0.5))) : new o(NaN);
};
m.inverseSine = m.asin = function() {
  var e10, r, t, n, i = this, o = i.constructor;
  return i.isZero() ? new o(i) : (r = i.abs().cmp(1), t = o.precision, n = o.rounding, r !== -1 ? r === 0 ? (e10 = xe(o, t + 4, n).times(0.5), e10.s = i.s, e10) : new o(NaN) : (o.precision = t + 6, o.rounding = 1, i = i.div(new o(1).minus(i.times(i)).sqrt().plus(1)).atan(), o.precision = t, o.rounding = n, i.times(2)));
};
m.inverseTangent = m.atan = function() {
  var e10, r, t, n, i, o, s, a, l, u = this, c = u.constructor, p = c.precision, d = c.rounding;
  if (u.isFinite()) {
    if (u.isZero()) return new c(u);
    if (u.abs().eq(1) && p + 4 <= Qi) return s = xe(c, p + 4, d).times(0.25), s.s = u.s, s;
  } else {
    if (!u.s) return new c(NaN);
    if (p + 4 <= Qi) return s = xe(c, p + 4, d).times(0.5), s.s = u.s, s;
  }
  for (c.precision = a = p + 10, c.rounding = 1, t = Math.min(28, a / E + 2 | 0), e10 = t; e10; --e10) u = u.div(u.times(u).plus(1).sqrt().plus(1));
  for (w = false, r = Math.ceil(a / E), n = 1, l = u.times(u), s = new c(u), i = u; e10 !== -1; ) if (i = i.times(l), o = s.minus(i.div(n += 2)), i = i.times(l), s = o.plus(i.div(n += 2)), s.d[r] !== void 0) for (e10 = r; s.d[e10] === o.d[e10] && e10--; ) ;
  return t && (s = s.times(2 << t - 1)), w = true, y(s, c.precision = p, c.rounding = d, true);
};
m.isFinite = function() {
  return !!this.d;
};
m.isInteger = m.isInt = function() {
  return !!this.d && X(this.e / E) > this.d.length - 2;
};
m.isNaN = function() {
  return !this.s;
};
m.isNegative = m.isNeg = function() {
  return this.s < 0;
};
m.isPositive = m.isPos = function() {
  return this.s > 0;
};
m.isZero = function() {
  return !!this.d && this.d[0] === 0;
};
m.lessThan = m.lt = function(e10) {
  return this.cmp(e10) < 0;
};
m.lessThanOrEqualTo = m.lte = function(e10) {
  return this.cmp(e10) < 1;
};
m.logarithm = m.log = function(e10) {
  var r, t, n, i, o, s, a, l, u = this, c = u.constructor, p = c.precision, d = c.rounding, f = 5;
  if (e10 == null) e10 = new c(10), r = true;
  else {
    if (e10 = new c(e10), t = e10.d, e10.s < 0 || !t || !t[0] || e10.eq(1)) return new c(NaN);
    r = e10.eq(10);
  }
  if (t = u.d, u.s < 0 || !t || !t[0] || u.eq(1)) return new c(t && !t[0] ? -1 / 0 : u.s != 1 ? NaN : t ? 0 : 1 / 0);
  if (r) if (t.length > 1) o = true;
  else {
    for (i = t[0]; i % 10 === 0; ) i /= 10;
    o = i !== 1;
  }
  if (w = false, a = p + f, s = Ke(u, a), n = r ? yn(c, a + 10) : Ke(e10, a), l = L(s, n, a, 1), lt(l.d, i = p, d)) do
    if (a += 10, s = Ke(u, a), n = r ? yn(c, a + 10) : Ke(e10, a), l = L(s, n, a, 1), !o) {
      +J(l.d).slice(i + 1, i + 15) + 1 == 1e14 && (l = y(l, p + 1, 0));
      break;
    }
  while (lt(l.d, i += 10, d));
  return w = true, y(l, p, d);
};
m.minus = m.sub = function(e10) {
  var r, t, n, i, o, s, a, l, u, c, p, d, f = this, h = f.constructor;
  if (e10 = new h(e10), !f.d || !e10.d) return !f.s || !e10.s ? e10 = new h(NaN) : f.d ? e10.s = -e10.s : e10 = new h(e10.d || f.s !== e10.s ? f : NaN), e10;
  if (f.s != e10.s) return e10.s = -e10.s, f.plus(e10);
  if (u = f.d, d = e10.d, a = h.precision, l = h.rounding, !u[0] || !d[0]) {
    if (d[0]) e10.s = -e10.s;
    else if (u[0]) e10 = new h(f);
    else return new h(l === 3 ? -0 : 0);
    return w ? y(e10, a, l) : e10;
  }
  if (t = X(e10.e / E), c = X(f.e / E), u = u.slice(), o = c - t, o) {
    for (p = o < 0, p ? (r = u, o = -o, s = d.length) : (r = d, t = c, s = u.length), n = Math.max(Math.ceil(a / E), s) + 2, o > n && (o = n, r.length = 1), r.reverse(), n = o; n--; ) r.push(0);
    r.reverse();
  } else {
    for (n = u.length, s = d.length, p = n < s, p && (s = n), n = 0; n < s; n++) if (u[n] != d[n]) {
      p = u[n] < d[n];
      break;
    }
    o = 0;
  }
  for (p && (r = u, u = d, d = r, e10.s = -e10.s), s = u.length, n = d.length - s; n > 0; --n) u[s++] = 0;
  for (n = d.length; n > o; ) {
    if (u[--n] < d[n]) {
      for (i = n; i && u[--i] === 0; ) u[i] = fe - 1;
      --u[i], u[n] += fe;
    }
    u[n] -= d[n];
  }
  for (; u[--s] === 0; ) u.pop();
  for (; u[0] === 0; u.shift()) --t;
  return u[0] ? (e10.d = u, e10.e = En(u, t), w ? y(e10, a, l) : e10) : new h(l === 3 ? -0 : 0);
};
m.modulo = m.mod = function(e10) {
  var r, t = this, n = t.constructor;
  return e10 = new n(e10), !t.d || !e10.s || e10.d && !e10.d[0] ? new n(NaN) : !e10.d || t.d && !t.d[0] ? y(new n(t), n.precision, n.rounding) : (w = false, n.modulo == 9 ? (r = L(t, e10.abs(), 0, 3, 1), r.s *= e10.s) : r = L(t, e10, 0, n.modulo, 1), r = r.times(e10), w = true, t.minus(r));
};
m.naturalExponential = m.exp = function() {
  return Wi(this);
};
m.naturalLogarithm = m.ln = function() {
  return Ke(this);
};
m.negated = m.neg = function() {
  var e10 = new this.constructor(this);
  return e10.s = -e10.s, y(e10);
};
m.plus = m.add = function(e10) {
  var r, t, n, i, o, s, a, l, u, c, p = this, d = p.constructor;
  if (e10 = new d(e10), !p.d || !e10.d) return !p.s || !e10.s ? e10 = new d(NaN) : p.d || (e10 = new d(e10.d || p.s === e10.s ? p : NaN)), e10;
  if (p.s != e10.s) return e10.s = -e10.s, p.minus(e10);
  if (u = p.d, c = e10.d, a = d.precision, l = d.rounding, !u[0] || !c[0]) return c[0] || (e10 = new d(p)), w ? y(e10, a, l) : e10;
  if (o = X(p.e / E), n = X(e10.e / E), u = u.slice(), i = o - n, i) {
    for (i < 0 ? (t = u, i = -i, s = c.length) : (t = c, n = o, s = u.length), o = Math.ceil(a / E), s = o > s ? o + 1 : s + 1, i > s && (i = s, t.length = 1), t.reverse(); i--; ) t.push(0);
    t.reverse();
  }
  for (s = u.length, i = c.length, s - i < 0 && (i = s, t = c, c = u, u = t), r = 0; i; ) r = (u[--i] = u[i] + c[i] + r) / fe | 0, u[i] %= fe;
  for (r && (u.unshift(r), ++n), s = u.length; u[--s] == 0; ) u.pop();
  return e10.d = u, e10.e = En(u, n), w ? y(e10, a, l) : e10;
};
m.precision = m.sd = function(e10) {
  var r, t = this;
  if (e10 !== void 0 && e10 !== !!e10 && e10 !== 1 && e10 !== 0) throw Error(He + e10);
  return t.d ? (r = Js(t.d), e10 && t.e + 1 > r && (r = t.e + 1)) : r = NaN, r;
};
m.round = function() {
  var e10 = this, r = e10.constructor;
  return y(new r(e10), e10.e + 1, r.rounding);
};
m.sine = m.sin = function() {
  var e10, r, t = this, n = t.constructor;
  return t.isFinite() ? t.isZero() ? new n(t) : (e10 = n.precision, r = n.rounding, n.precision = e10 + Math.max(t.e, t.sd()) + E, n.rounding = 1, t = Ip(n, zs(n, t)), n.precision = e10, n.rounding = r, y(Ne > 2 ? t.neg() : t, e10, r, true)) : new n(NaN);
};
m.squareRoot = m.sqrt = function() {
  var e10, r, t, n, i, o, s = this, a = s.d, l = s.e, u = s.s, c = s.constructor;
  if (u !== 1 || !a || !a[0]) return new c(!u || u < 0 && (!a || a[0]) ? NaN : a ? s : 1 / 0);
  for (w = false, u = Math.sqrt(+s), u == 0 || u == 1 / 0 ? (r = J(a), (r.length + l) % 2 == 0 && (r += "0"), u = Math.sqrt(r), l = X((l + 1) / 2) - (l < 0 || l % 2), u == 1 / 0 ? r = "5e" + l : (r = u.toExponential(), r = r.slice(0, r.indexOf("e") + 1) + l), n = new c(r)) : n = new c(u.toString()), t = (l = c.precision) + 3; ; ) if (o = n, n = o.plus(L(s, o, t + 2, 1)).times(0.5), J(o.d).slice(0, t) === (r = J(n.d)).slice(0, t)) if (r = r.slice(t - 3, t + 1), r == "9999" || !i && r == "4999") {
    if (!i && (y(o, l + 1, 0), o.times(o).eq(s))) {
      n = o;
      break;
    }
    t += 4, i = 1;
  } else {
    (!+r || !+r.slice(1) && r.charAt(0) == "5") && (y(n, l + 1, 1), e10 = !n.times(n).eq(s));
    break;
  }
  return w = true, y(n, l, c.rounding, e10);
};
m.tangent = m.tan = function() {
  var e10, r, t = this, n = t.constructor;
  return t.isFinite() ? t.isZero() ? new n(t) : (e10 = n.precision, r = n.rounding, n.precision = e10 + 10, n.rounding = 1, t = t.sin(), t.s = 1, t = L(t, new n(1).minus(t.times(t)).sqrt(), e10 + 10, 0), n.precision = e10, n.rounding = r, y(Ne == 2 || Ne == 4 ? t.neg() : t, e10, r, true)) : new n(NaN);
};
m.times = m.mul = function(e10) {
  var r, t, n, i, o, s, a, l, u, c = this, p = c.constructor, d = c.d, f = (e10 = new p(e10)).d;
  if (e10.s *= c.s, !d || !d[0] || !f || !f[0]) return new p(!e10.s || d && !d[0] && !f || f && !f[0] && !d ? NaN : !d || !f ? e10.s / 0 : e10.s * 0);
  for (t = X(c.e / E) + X(e10.e / E), l = d.length, u = f.length, l < u && (o = d, d = f, f = o, s = l, l = u, u = s), o = [], s = l + u, n = s; n--; ) o.push(0);
  for (n = u; --n >= 0; ) {
    for (r = 0, i = l + n; i > n; ) a = o[i] + f[n] * d[i - n - 1] + r, o[i--] = a % fe | 0, r = a / fe | 0;
    o[i] = (o[i] + r) % fe | 0;
  }
  for (; !o[--s]; ) o.pop();
  return r ? ++t : o.shift(), e10.d = o, e10.e = En(o, t), w ? y(e10, p.precision, p.rounding) : e10;
};
m.toBinary = function(e10, r) {
  return Ji(this, 2, e10, r);
};
m.toDecimalPlaces = m.toDP = function(e10, r) {
  var t = this, n = t.constructor;
  return t = new n(t), e10 === void 0 ? t : (ie(e10, 0, Ye), r === void 0 ? r = n.rounding : ie(r, 0, 8), y(t, e10 + t.e + 1, r));
};
m.toExponential = function(e10, r) {
  var t, n = this, i = n.constructor;
  return e10 === void 0 ? t = ve(n, true) : (ie(e10, 0, Ye), r === void 0 ? r = i.rounding : ie(r, 0, 8), n = y(new i(n), e10 + 1, r), t = ve(n, true, e10 + 1)), n.isNeg() && !n.isZero() ? "-" + t : t;
};
m.toFixed = function(e10, r) {
  var t, n, i = this, o = i.constructor;
  return e10 === void 0 ? t = ve(i) : (ie(e10, 0, Ye), r === void 0 ? r = o.rounding : ie(r, 0, 8), n = y(new o(i), e10 + i.e + 1, r), t = ve(n, false, e10 + n.e + 1)), i.isNeg() && !i.isZero() ? "-" + t : t;
};
m.toFraction = function(e10) {
  var r, t, n, i, o, s, a, l, u, c, p, d, f = this, h = f.d, g = f.constructor;
  if (!h) return new g(f);
  if (u = t = new g(1), n = l = new g(0), r = new g(n), o = r.e = Js(h) - f.e - 1, s = o % E, r.d[0] = U(10, s < 0 ? E + s : s), e10 == null) e10 = o > 0 ? r : u;
  else {
    if (a = new g(e10), !a.isInt() || a.lt(u)) throw Error(He + a);
    e10 = a.gt(r) ? o > 0 ? r : u : a;
  }
  for (w = false, a = new g(J(h)), c = g.precision, g.precision = o = h.length * E * 2; p = L(a, r, 0, 1, 1), i = t.plus(p.times(n)), i.cmp(e10) != 1; ) t = n, n = i, i = u, u = l.plus(p.times(i)), l = i, i = r, r = a.minus(p.times(i)), a = i;
  return i = L(e10.minus(t), n, 0, 1, 1), l = l.plus(i.times(u)), t = t.plus(i.times(n)), l.s = u.s = f.s, d = L(u, n, o, 1).minus(f).abs().cmp(L(l, t, o, 1).minus(f).abs()) < 1 ? [u, n] : [l, t], g.precision = c, w = true, d;
};
m.toHexadecimal = m.toHex = function(e10, r) {
  return Ji(this, 16, e10, r);
};
m.toNearest = function(e10, r) {
  var t = this, n = t.constructor;
  if (t = new n(t), e10 == null) {
    if (!t.d) return t;
    e10 = new n(1), r = n.rounding;
  } else {
    if (e10 = new n(e10), r === void 0 ? r = n.rounding : ie(r, 0, 8), !t.d) return e10.s ? t : e10;
    if (!e10.d) return e10.s && (e10.s = t.s), e10;
  }
  return e10.d[0] ? (w = false, t = L(t, e10, 0, r, 1).times(e10), w = true, y(t)) : (e10.s = t.s, t = e10), t;
};
m.toNumber = function() {
  return +this;
};
m.toOctal = function(e10, r) {
  return Ji(this, 8, e10, r);
};
m.toPower = m.pow = function(e10) {
  var r, t, n, i, o, s, a = this, l = a.constructor, u = +(e10 = new l(e10));
  if (!a.d || !e10.d || !a.d[0] || !e10.d[0]) return new l(U(+a, u));
  if (a = new l(a), a.eq(1)) return a;
  if (n = l.precision, o = l.rounding, e10.eq(1)) return y(a, n, o);
  if (r = X(e10.e / E), r >= e10.d.length - 1 && (t = u < 0 ? -u : u) <= Sp) return i = Ks(l, a, t, n), e10.s < 0 ? new l(1).div(i) : y(i, n, o);
  if (s = a.s, s < 0) {
    if (r < e10.d.length - 1) return new l(NaN);
    if ((e10.d[r] & 1) == 0 && (s = 1), a.e == 0 && a.d[0] == 1 && a.d.length == 1) return a.s = s, a;
  }
  return t = U(+a, u), r = t == 0 || !isFinite(t) ? X(u * (Math.log("0." + J(a.d)) / Math.LN10 + a.e + 1)) : new l(t + "").e, r > l.maxE + 1 || r < l.minE - 1 ? new l(r > 0 ? s / 0 : 0) : (w = false, l.rounding = a.s = 1, t = Math.min(12, (r + "").length), i = Wi(e10.times(Ke(a, n + t)), n), i.d && (i = y(i, n + 5, 1), lt(i.d, n, o) && (r = n + 10, i = y(Wi(e10.times(Ke(a, r + t)), r), r + 5, 1), +J(i.d).slice(n + 1, n + 15) + 1 == 1e14 && (i = y(i, n + 1, 0)))), i.s = s, w = true, l.rounding = o, y(i, n, o));
};
m.toPrecision = function(e10, r) {
  var t, n = this, i = n.constructor;
  return e10 === void 0 ? t = ve(n, n.e <= i.toExpNeg || n.e >= i.toExpPos) : (ie(e10, 1, Ye), r === void 0 ? r = i.rounding : ie(r, 0, 8), n = y(new i(n), e10, r), t = ve(n, e10 <= n.e || n.e <= i.toExpNeg, e10)), n.isNeg() && !n.isZero() ? "-" + t : t;
};
m.toSignificantDigits = m.toSD = function(e10, r) {
  var t = this, n = t.constructor;
  return e10 === void 0 ? (e10 = n.precision, r = n.rounding) : (ie(e10, 1, Ye), r === void 0 ? r = n.rounding : ie(r, 0, 8)), y(new n(t), e10, r);
};
m.toString = function() {
  var e10 = this, r = e10.constructor, t = ve(e10, e10.e <= r.toExpNeg || e10.e >= r.toExpPos);
  return e10.isNeg() && !e10.isZero() ? "-" + t : t;
};
m.truncated = m.trunc = function() {
  return y(new this.constructor(this), this.e + 1, 1);
};
m.valueOf = m.toJSON = function() {
  var e10 = this, r = e10.constructor, t = ve(e10, e10.e <= r.toExpNeg || e10.e >= r.toExpPos);
  return e10.isNeg() ? "-" + t : t;
};
function J(e10) {
  var r, t, n, i = e10.length - 1, o = "", s = e10[0];
  if (i > 0) {
    for (o += s, r = 1; r < i; r++) n = e10[r] + "", t = E - n.length, t && (o += Je(t)), o += n;
    s = e10[r], n = s + "", t = E - n.length, t && (o += Je(t));
  } else if (s === 0) return "0";
  for (; s % 10 === 0; ) s /= 10;
  return o + s;
}
function ie(e10, r, t) {
  if (e10 !== ~~e10 || e10 < r || e10 > t) throw Error(He + e10);
}
function lt(e10, r, t, n) {
  var i, o, s, a;
  for (o = e10[0]; o >= 10; o /= 10) --r;
  return --r < 0 ? (r += E, i = 0) : (i = Math.ceil((r + 1) / E), r %= E), o = U(10, E - r), a = e10[i] % o | 0, n == null ? r < 3 ? (r == 0 ? a = a / 100 | 0 : r == 1 && (a = a / 10 | 0), s = t < 4 && a == 99999 || t > 3 && a == 49999 || a == 5e4 || a == 0) : s = (t < 4 && a + 1 == o || t > 3 && a + 1 == o / 2) && (e10[i + 1] / o / 100 | 0) == U(10, r - 2) - 1 || (a == o / 2 || a == 0) && (e10[i + 1] / o / 100 | 0) == 0 : r < 4 ? (r == 0 ? a = a / 1e3 | 0 : r == 1 ? a = a / 100 | 0 : r == 2 && (a = a / 10 | 0), s = (n || t < 4) && a == 9999 || !n && t > 3 && a == 4999) : s = ((n || t < 4) && a + 1 == o || !n && t > 3 && a + 1 == o / 2) && (e10[i + 1] / o / 1e3 | 0) == U(10, r - 3) - 1, s;
}
function mn(e10, r, t) {
  for (var n, i = [0], o, s = 0, a = e10.length; s < a; ) {
    for (o = i.length; o--; ) i[o] *= r;
    for (i[0] += Ui.indexOf(e10.charAt(s++)), n = 0; n < i.length; n++) i[n] > t - 1 && (i[n + 1] === void 0 && (i[n + 1] = 0), i[n + 1] += i[n] / t | 0, i[n] %= t);
  }
  return i.reverse();
}
function Ap(e10, r) {
  var t, n, i;
  if (r.isZero()) return r;
  n = r.d.length, n < 32 ? (t = Math.ceil(n / 3), i = (1 / wn(4, t)).toString()) : (t = 16, i = "2.3283064365386962890625e-10"), e10.precision += t, r = Pr(e10, 1, r.times(i), new e10(1));
  for (var o = t; o--; ) {
    var s = r.times(r);
    r = s.times(s).minus(s).times(8).plus(1);
  }
  return e10.precision -= t, r;
}
var L = /* @__PURE__ */ (function() {
  function e10(n, i, o) {
    var s, a = 0, l = n.length;
    for (n = n.slice(); l--; ) s = n[l] * i + a, n[l] = s % o | 0, a = s / o | 0;
    return a && n.unshift(a), n;
  }
  function r(n, i, o, s) {
    var a, l;
    if (o != s) l = o > s ? 1 : -1;
    else for (a = l = 0; a < o; a++) if (n[a] != i[a]) {
      l = n[a] > i[a] ? 1 : -1;
      break;
    }
    return l;
  }
  function t(n, i, o, s) {
    for (var a = 0; o--; ) n[o] -= a, a = n[o] < i[o] ? 1 : 0, n[o] = a * s + n[o] - i[o];
    for (; !n[0] && n.length > 1; ) n.shift();
  }
  return function(n, i, o, s, a, l) {
    var u, c, p, d, f, h, g, D, T, S, b, O, me, ae, Jr, j, te, Ae, K, fr, qt = n.constructor, ti = n.s == i.s ? 1 : -1, H = n.d, _ = i.d;
    if (!H || !H[0] || !_ || !_[0]) return new qt(!n.s || !i.s || (H ? _ && H[0] == _[0] : !_) ? NaN : H && H[0] == 0 || !_ ? ti * 0 : ti / 0);
    for (l ? (f = 1, c = n.e - i.e) : (l = fe, f = E, c = X(n.e / f) - X(i.e / f)), K = _.length, te = H.length, T = new qt(ti), S = T.d = [], p = 0; _[p] == (H[p] || 0); p++) ;
    if (_[p] > (H[p] || 0) && c--, o == null ? (ae = o = qt.precision, s = qt.rounding) : a ? ae = o + (n.e - i.e) + 1 : ae = o, ae < 0) S.push(1), h = true;
    else {
      if (ae = ae / f + 2 | 0, p = 0, K == 1) {
        for (d = 0, _ = _[0], ae++; (p < te || d) && ae--; p++) Jr = d * l + (H[p] || 0), S[p] = Jr / _ | 0, d = Jr % _ | 0;
        h = d || p < te;
      } else {
        for (d = l / (_[0] + 1) | 0, d > 1 && (_ = e10(_, d, l), H = e10(H, d, l), K = _.length, te = H.length), j = K, b = H.slice(0, K), O = b.length; O < K; ) b[O++] = 0;
        fr = _.slice(), fr.unshift(0), Ae = _[0], _[1] >= l / 2 && ++Ae;
        do
          d = 0, u = r(_, b, K, O), u < 0 ? (me = b[0], K != O && (me = me * l + (b[1] || 0)), d = me / Ae | 0, d > 1 ? (d >= l && (d = l - 1), g = e10(_, d, l), D = g.length, O = b.length, u = r(g, b, D, O), u == 1 && (d--, t(g, K < D ? fr : _, D, l))) : (d == 0 && (u = d = 1), g = _.slice()), D = g.length, D < O && g.unshift(0), t(b, g, O, l), u == -1 && (O = b.length, u = r(_, b, K, O), u < 1 && (d++, t(b, K < O ? fr : _, O, l))), O = b.length) : u === 0 && (d++, b = [0]), S[p++] = d, u && b[0] ? b[O++] = H[j] || 0 : (b = [H[j]], O = 1);
        while ((j++ < te || b[0] !== void 0) && ae--);
        h = b[0] !== void 0;
      }
      S[0] || S.shift();
    }
    if (f == 1) T.e = c, Bs = h;
    else {
      for (p = 1, d = S[0]; d >= 10; d /= 10) p++;
      T.e = p + c * f - 1, y(T, a ? o + T.e + 1 : o, s, h);
    }
    return T;
  };
})();
function y(e10, r, t, n) {
  var i, o, s, a, l, u, c, p, d, f = e10.constructor;
  e: if (r != null) {
    if (p = e10.d, !p) return e10;
    for (i = 1, a = p[0]; a >= 10; a /= 10) i++;
    if (o = r - i, o < 0) o += E, s = r, c = p[d = 0], l = c / U(10, i - s - 1) % 10 | 0;
    else if (d = Math.ceil((o + 1) / E), a = p.length, d >= a) if (n) {
      for (; a++ <= d; ) p.push(0);
      c = l = 0, i = 1, o %= E, s = o - E + 1;
    } else break e;
    else {
      for (c = a = p[d], i = 1; a >= 10; a /= 10) i++;
      o %= E, s = o - E + i, l = s < 0 ? 0 : c / U(10, i - s - 1) % 10 | 0;
    }
    if (n = n || r < 0 || p[d + 1] !== void 0 || (s < 0 ? c : c % U(10, i - s - 1)), u = t < 4 ? (l || n) && (t == 0 || t == (e10.s < 0 ? 3 : 2)) : l > 5 || l == 5 && (t == 4 || n || t == 6 && (o > 0 ? s > 0 ? c / U(10, i - s) : 0 : p[d - 1]) % 10 & 1 || t == (e10.s < 0 ? 8 : 7)), r < 1 || !p[0]) return p.length = 0, u ? (r -= e10.e + 1, p[0] = U(10, (E - r % E) % E), e10.e = -r || 0) : p[0] = e10.e = 0, e10;
    if (o == 0 ? (p.length = d, a = 1, d--) : (p.length = d + 1, a = U(10, E - o), p[d] = s > 0 ? (c / U(10, i - s) % U(10, s) | 0) * a : 0), u) for (; ; ) if (d == 0) {
      for (o = 1, s = p[0]; s >= 10; s /= 10) o++;
      for (s = p[0] += a, a = 1; s >= 10; s /= 10) a++;
      o != a && (e10.e++, p[0] == fe && (p[0] = 1));
      break;
    } else {
      if (p[d] += a, p[d] != fe) break;
      p[d--] = 0, a = 1;
    }
    for (o = p.length; p[--o] === 0; ) p.pop();
  }
  return w && (e10.e > f.maxE ? (e10.d = null, e10.e = NaN) : e10.e < f.minE && (e10.e = 0, e10.d = [0])), e10;
}
function ve(e10, r, t) {
  if (!e10.isFinite()) return Ys(e10);
  var n, i = e10.e, o = J(e10.d), s = o.length;
  return r ? (t && (n = t - s) > 0 ? o = o.charAt(0) + "." + o.slice(1) + Je(n) : s > 1 && (o = o.charAt(0) + "." + o.slice(1)), o = o + (e10.e < 0 ? "e" : "e+") + e10.e) : i < 0 ? (o = "0." + Je(-i - 1) + o, t && (n = t - s) > 0 && (o += Je(n))) : i >= s ? (o += Je(i + 1 - s), t && (n = t - i - 1) > 0 && (o = o + "." + Je(n))) : ((n = i + 1) < s && (o = o.slice(0, n) + "." + o.slice(n)), t && (n = t - s) > 0 && (i + 1 === s && (o += "."), o += Je(n))), o;
}
function En(e10, r) {
  var t = e10[0];
  for (r *= E; t >= 10; t /= 10) r++;
  return r;
}
function yn(e10, r, t) {
  if (r > Rp) throw w = true, t && (e10.precision = t), Error(Us);
  return y(new e10(gn), r, 1, true);
}
function xe(e10, r, t) {
  if (r > Qi) throw Error(Us);
  return y(new e10(hn), r, t, true);
}
function Js(e10) {
  var r = e10.length - 1, t = r * E + 1;
  if (r = e10[r], r) {
    for (; r % 10 == 0; r /= 10) t--;
    for (r = e10[0]; r >= 10; r /= 10) t++;
  }
  return t;
}
function Je(e10) {
  for (var r = ""; e10--; ) r += "0";
  return r;
}
function Ks(e10, r, t, n) {
  var i, o = new e10(1), s = Math.ceil(n / E + 4);
  for (w = false; ; ) {
    if (t % 2 && (o = o.times(r), Vs(o.d, s) && (i = true)), t = X(t / 2), t === 0) {
      t = o.d.length - 1, i && o.d[t] === 0 && ++o.d[t];
      break;
    }
    r = r.times(r), Vs(r.d, s);
  }
  return w = true, o;
}
function qs(e10) {
  return e10.d[e10.d.length - 1] & 1;
}
function Hs(e10, r, t) {
  for (var n, i, o = new e10(r[0]), s = 0; ++s < r.length; ) {
    if (i = new e10(r[s]), !i.s) {
      o = i;
      break;
    }
    n = o.cmp(i), (n === t || n === 0 && o.s === t) && (o = i);
  }
  return o;
}
function Wi(e10, r) {
  var t, n, i, o, s, a, l, u = 0, c = 0, p = 0, d = e10.constructor, f = d.rounding, h = d.precision;
  if (!e10.d || !e10.d[0] || e10.e > 17) return new d(e10.d ? e10.d[0] ? e10.s < 0 ? 0 : 1 / 0 : 1 : e10.s ? e10.s < 0 ? 0 : e10 : NaN);
  for (r == null ? (w = false, l = h) : l = r, a = new d(0.03125); e10.e > -2; ) e10 = e10.times(a), p += 5;
  for (n = Math.log(U(2, p)) / Math.LN10 * 2 + 5 | 0, l += n, t = o = s = new d(1), d.precision = l; ; ) {
    if (o = y(o.times(e10), l, 1), t = t.times(++c), a = s.plus(L(o, t, l, 1)), J(a.d).slice(0, l) === J(s.d).slice(0, l)) {
      for (i = p; i--; ) s = y(s.times(s), l, 1);
      if (r == null) if (u < 3 && lt(s.d, l - n, f, u)) d.precision = l += 10, t = o = a = new d(1), c = 0, u++;
      else return y(s, d.precision = h, f, w = true);
      else return d.precision = h, s;
    }
    s = a;
  }
}
function Ke(e10, r) {
  var t, n, i, o, s, a, l, u, c, p, d, f = 1, h = 10, g = e10, D = g.d, T = g.constructor, S = T.rounding, b = T.precision;
  if (g.s < 0 || !D || !D[0] || !g.e && D[0] == 1 && D.length == 1) return new T(D && !D[0] ? -1 / 0 : g.s != 1 ? NaN : D ? 0 : g);
  if (r == null ? (w = false, c = b) : c = r, T.precision = c += h, t = J(D), n = t.charAt(0), Math.abs(o = g.e) < 15e14) {
    for (; n < 7 && n != 1 || n == 1 && t.charAt(1) > 3; ) g = g.times(e10), t = J(g.d), n = t.charAt(0), f++;
    o = g.e, n > 1 ? (g = new T("0." + t), o++) : g = new T(n + "." + t.slice(1));
  } else return u = yn(T, c + 2, b).times(o + ""), g = Ke(new T(n + "." + t.slice(1)), c - h).plus(u), T.precision = b, r == null ? y(g, b, S, w = true) : g;
  for (p = g, l = s = g = L(g.minus(1), g.plus(1), c, 1), d = y(g.times(g), c, 1), i = 3; ; ) {
    if (s = y(s.times(d), c, 1), u = l.plus(L(s, new T(i), c, 1)), J(u.d).slice(0, c) === J(l.d).slice(0, c)) if (l = l.times(2), o !== 0 && (l = l.plus(yn(T, c + 2, b).times(o + ""))), l = L(l, new T(f), c, 1), r == null) if (lt(l.d, c - h, S, a)) T.precision = c += h, u = s = g = L(p.minus(1), p.plus(1), c, 1), d = y(g.times(g), c, 1), i = a = 1;
    else return y(l, T.precision = b, S, w = true);
    else return T.precision = b, l;
    l = u, i += 2;
  }
}
function Ys(e10) {
  return String(e10.s * e10.s / 0);
}
function fn(e10, r) {
  var t, n, i;
  for ((t = r.indexOf(".")) > -1 && (r = r.replace(".", "")), (n = r.search(/e/i)) > 0 ? (t < 0 && (t = n), t += +r.slice(n + 1), r = r.substring(0, n)) : t < 0 && (t = r.length), n = 0; r.charCodeAt(n) === 48; n++) ;
  for (i = r.length; r.charCodeAt(i - 1) === 48; --i) ;
  if (r = r.slice(n, i), r) {
    if (i -= n, e10.e = t = t - n - 1, e10.d = [], n = (t + 1) % E, t < 0 && (n += E), n < i) {
      for (n && e10.d.push(+r.slice(0, n)), i -= E; n < i; ) e10.d.push(+r.slice(n, n += E));
      r = r.slice(n), n = E - r.length;
    } else n -= i;
    for (; n--; ) r += "0";
    e10.d.push(+r), w && (e10.e > e10.constructor.maxE ? (e10.d = null, e10.e = NaN) : e10.e < e10.constructor.minE && (e10.e = 0, e10.d = [0]));
  } else e10.e = 0, e10.d = [0];
  return e10;
}
function Cp(e10, r) {
  var t, n, i, o, s, a, l, u, c;
  if (r.indexOf("_") > -1) {
    if (r = r.replace(/(\d)_(?=\d)/g, "$1"), Ws.test(r)) return fn(e10, r);
  } else if (r === "Infinity" || r === "NaN") return +r || (e10.s = NaN), e10.e = NaN, e10.d = null, e10;
  if (Pp.test(r)) t = 16, r = r.toLowerCase();
  else if (vp.test(r)) t = 2;
  else if (Tp.test(r)) t = 8;
  else throw Error(He + r);
  for (o = r.search(/p/i), o > 0 ? (l = +r.slice(o + 1), r = r.substring(2, o)) : r = r.slice(2), o = r.indexOf("."), s = o >= 0, n = e10.constructor, s && (r = r.replace(".", ""), a = r.length, o = a - o, i = Ks(n, new n(t), o, o * 2)), u = mn(r, t, fe), c = u.length - 1, o = c; u[o] === 0; --o) u.pop();
  return o < 0 ? new n(e10.s * 0) : (e10.e = En(u, c), e10.d = u, w = false, s && (e10 = L(e10, i, a * 4)), l && (e10 = e10.times(Math.abs(l) < 54 ? U(2, l) : Le.pow(2, l))), w = true, e10);
}
function Ip(e10, r) {
  var t, n = r.d.length;
  if (n < 3) return r.isZero() ? r : Pr(e10, 2, r, r);
  t = 1.4 * Math.sqrt(n), t = t > 16 ? 16 : t | 0, r = r.times(1 / wn(5, t)), r = Pr(e10, 2, r, r);
  for (var i, o = new e10(5), s = new e10(16), a = new e10(20); t--; ) i = r.times(r), r = r.times(o.plus(i.times(s.times(i).minus(a))));
  return r;
}
function Pr(e10, r, t, n, i) {
  var o, s, a, l, c = e10.precision, p = Math.ceil(c / E);
  for (w = false, l = t.times(t), a = new e10(n); ; ) {
    if (s = L(a.times(l), new e10(r++ * r++), c, 1), a = i ? n.plus(s) : n.minus(s), n = L(s.times(l), new e10(r++ * r++), c, 1), s = a.plus(n), s.d[p] !== void 0) {
      for (o = p; s.d[o] === a.d[o] && o--; ) ;
      if (o == -1) break;
    }
    o = a, a = n, n = s, s = o;
  }
  return w = true, s.d.length = p + 1, s;
}
function wn(e10, r) {
  for (var t = e10; --r; ) t *= e10;
  return t;
}
function zs(e10, r) {
  var t, n = r.s < 0, i = xe(e10, e10.precision, 1), o = i.times(0.5);
  if (r = r.abs(), r.lte(o)) return Ne = n ? 4 : 1, r;
  if (t = r.divToInt(i), t.isZero()) Ne = n ? 3 : 2;
  else {
    if (r = r.minus(t.times(i)), r.lte(o)) return Ne = qs(t) ? n ? 2 : 3 : n ? 4 : 1, r;
    Ne = qs(t) ? n ? 1 : 4 : n ? 3 : 2;
  }
  return r.minus(i).abs();
}
function Ji(e10, r, t, n) {
  var i, o, s, a, l, u, c, p, d, f = e10.constructor, h = t !== void 0;
  if (h ? (ie(t, 1, Ye), n === void 0 ? n = f.rounding : ie(n, 0, 8)) : (t = f.precision, n = f.rounding), !e10.isFinite()) c = Ys(e10);
  else {
    for (c = ve(e10), s = c.indexOf("."), h ? (i = 2, r == 16 ? t = t * 4 - 3 : r == 8 && (t = t * 3 - 2)) : i = r, s >= 0 && (c = c.replace(".", ""), d = new f(1), d.e = c.length - s, d.d = mn(ve(d), 10, i), d.e = d.d.length), p = mn(c, 10, i), o = l = p.length; p[--l] == 0; ) p.pop();
    if (!p[0]) c = h ? "0p+0" : "0";
    else {
      if (s < 0 ? o-- : (e10 = new f(e10), e10.d = p, e10.e = o, e10 = L(e10, d, t, n, 0, i), p = e10.d, o = e10.e, u = Bs), s = p[t], a = i / 2, u = u || p[t + 1] !== void 0, u = n < 4 ? (s !== void 0 || u) && (n === 0 || n === (e10.s < 0 ? 3 : 2)) : s > a || s === a && (n === 4 || u || n === 6 && p[t - 1] & 1 || n === (e10.s < 0 ? 8 : 7)), p.length = t, u) for (; ++p[--t] > i - 1; ) p[t] = 0, t || (++o, p.unshift(1));
      for (l = p.length; !p[l - 1]; --l) ;
      for (s = 0, c = ""; s < l; s++) c += Ui.charAt(p[s]);
      if (h) {
        if (l > 1) if (r == 16 || r == 8) {
          for (s = r == 16 ? 4 : 3, --l; l % s; l++) c += "0";
          for (p = mn(c, i, r), l = p.length; !p[l - 1]; --l) ;
          for (s = 1, c = "1."; s < l; s++) c += Ui.charAt(p[s]);
        } else c = c.charAt(0) + "." + c.slice(1);
        c = c + (o < 0 ? "p" : "p+") + o;
      } else if (o < 0) {
        for (; ++o; ) c = "0" + c;
        c = "0." + c;
      } else if (++o > l) for (o -= l; o--; ) c += "0";
      else o < l && (c = c.slice(0, o) + "." + c.slice(o));
    }
    c = (r == 16 ? "0x" : r == 2 ? "0b" : r == 8 ? "0o" : "") + c;
  }
  return e10.s < 0 ? "-" + c : c;
}
function Vs(e10, r) {
  if (e10.length > r) return e10.length = r, true;
}
function Dp(e10) {
  return new this(e10).abs();
}
function Op(e10) {
  return new this(e10).acos();
}
function kp(e10) {
  return new this(e10).acosh();
}
function _p(e10, r) {
  return new this(e10).plus(r);
}
function Np(e10) {
  return new this(e10).asin();
}
function Lp(e10) {
  return new this(e10).asinh();
}
function Fp(e10) {
  return new this(e10).atan();
}
function Mp(e10) {
  return new this(e10).atanh();
}
function $p(e10, r) {
  e10 = new this(e10), r = new this(r);
  var t, n = this.precision, i = this.rounding, o = n + 4;
  return !e10.s || !r.s ? t = new this(NaN) : !e10.d && !r.d ? (t = xe(this, o, 1).times(r.s > 0 ? 0.25 : 0.75), t.s = e10.s) : !r.d || e10.isZero() ? (t = r.s < 0 ? xe(this, n, i) : new this(0), t.s = e10.s) : !e10.d || r.isZero() ? (t = xe(this, o, 1).times(0.5), t.s = e10.s) : r.s < 0 ? (this.precision = o, this.rounding = 1, t = this.atan(L(e10, r, o, 1)), r = xe(this, o, 1), this.precision = n, this.rounding = i, t = e10.s < 0 ? t.minus(r) : t.plus(r)) : t = this.atan(L(e10, r, o, 1)), t;
}
function qp(e10) {
  return new this(e10).cbrt();
}
function Vp(e10) {
  return y(e10 = new this(e10), e10.e + 1, 2);
}
function jp(e10, r, t) {
  return new this(e10).clamp(r, t);
}
function Bp(e10) {
  if (!e10 || typeof e10 != "object") throw Error(bn + "Object expected");
  var r, t, n, i = e10.defaults === true, o = ["precision", 1, Ye, "rounding", 0, 8, "toExpNeg", -vr, 0, "toExpPos", 0, vr, "maxE", 0, vr, "minE", -vr, 0, "modulo", 0, 9];
  for (r = 0; r < o.length; r += 3) if (t = o[r], i && (this[t] = Gi[t]), (n = e10[t]) !== void 0) if (X(n) === n && n >= o[r + 1] && n <= o[r + 2]) this[t] = n;
  else throw Error(He + t + ": " + n);
  if (t = "crypto", i && (this[t] = Gi[t]), (n = e10[t]) !== void 0) if (n === true || n === false || n === 0 || n === 1) if (n) if (typeof crypto < "u" && crypto && (crypto.getRandomValues || crypto.randomBytes)) this[t] = true;
  else throw Error(Gs);
  else this[t] = false;
  else throw Error(He + t + ": " + n);
  return this;
}
function Up(e10) {
  return new this(e10).cos();
}
function Gp(e10) {
  return new this(e10).cosh();
}
function Zs(e10) {
  var r, t, n;
  function i(o) {
    var s, a, l, u = this;
    if (!(u instanceof i)) return new i(o);
    if (u.constructor = i, js(o)) {
      u.s = o.s, w ? !o.d || o.e > i.maxE ? (u.e = NaN, u.d = null) : o.e < i.minE ? (u.e = 0, u.d = [0]) : (u.e = o.e, u.d = o.d.slice()) : (u.e = o.e, u.d = o.d ? o.d.slice() : o.d);
      return;
    }
    if (l = typeof o, l === "number") {
      if (o === 0) {
        u.s = 1 / o < 0 ? -1 : 1, u.e = 0, u.d = [0];
        return;
      }
      if (o < 0 ? (o = -o, u.s = -1) : u.s = 1, o === ~~o && o < 1e7) {
        for (s = 0, a = o; a >= 10; a /= 10) s++;
        w ? s > i.maxE ? (u.e = NaN, u.d = null) : s < i.minE ? (u.e = 0, u.d = [0]) : (u.e = s, u.d = [o]) : (u.e = s, u.d = [o]);
        return;
      }
      if (o * 0 !== 0) {
        o || (u.s = NaN), u.e = NaN, u.d = null;
        return;
      }
      return fn(u, o.toString());
    }
    if (l === "string") return (a = o.charCodeAt(0)) === 45 ? (o = o.slice(1), u.s = -1) : (a === 43 && (o = o.slice(1)), u.s = 1), Ws.test(o) ? fn(u, o) : Cp(u, o);
    if (l === "bigint") return o < 0 ? (o = -o, u.s = -1) : u.s = 1, fn(u, o.toString());
    throw Error(He + o);
  }
  if (i.prototype = m, i.ROUND_UP = 0, i.ROUND_DOWN = 1, i.ROUND_CEIL = 2, i.ROUND_FLOOR = 3, i.ROUND_HALF_UP = 4, i.ROUND_HALF_DOWN = 5, i.ROUND_HALF_EVEN = 6, i.ROUND_HALF_CEIL = 7, i.ROUND_HALF_FLOOR = 8, i.EUCLID = 9, i.config = i.set = Bp, i.clone = Zs, i.isDecimal = js, i.abs = Dp, i.acos = Op, i.acosh = kp, i.add = _p, i.asin = Np, i.asinh = Lp, i.atan = Fp, i.atanh = Mp, i.atan2 = $p, i.cbrt = qp, i.ceil = Vp, i.clamp = jp, i.cos = Up, i.cosh = Gp, i.div = Qp, i.exp = Wp, i.floor = Jp, i.hypot = Kp, i.ln = Hp, i.log = Yp, i.log10 = Zp, i.log2 = zp, i.max = Xp, i.min = ed, i.mod = rd, i.mul = td, i.pow = nd, i.random = id, i.round = od, i.sign = sd, i.sin = ad, i.sinh = ld, i.sqrt = ud, i.sub = cd, i.sum = pd, i.tan = dd, i.tanh = md, i.trunc = fd, e10 === void 0 && (e10 = {}), e10 && e10.defaults !== true) for (n = ["precision", "rounding", "toExpNeg", "toExpPos", "maxE", "minE", "modulo", "crypto"], r = 0; r < n.length; ) e10.hasOwnProperty(t = n[r++]) || (e10[t] = this[t]);
  return i.config(e10), i;
}
function Qp(e10, r) {
  return new this(e10).div(r);
}
function Wp(e10) {
  return new this(e10).exp();
}
function Jp(e10) {
  return y(e10 = new this(e10), e10.e + 1, 3);
}
function Kp() {
  var e10, r, t = new this(0);
  for (w = false, e10 = 0; e10 < arguments.length; ) if (r = new this(arguments[e10++]), r.d) t.d && (t = t.plus(r.times(r)));
  else {
    if (r.s) return w = true, new this(1 / 0);
    t = r;
  }
  return w = true, t.sqrt();
}
function js(e10) {
  return e10 instanceof Le || e10 && e10.toStringTag === Qs || false;
}
function Hp(e10) {
  return new this(e10).ln();
}
function Yp(e10, r) {
  return new this(e10).log(r);
}
function zp(e10) {
  return new this(e10).log(2);
}
function Zp(e10) {
  return new this(e10).log(10);
}
function Xp() {
  return Hs(this, arguments, -1);
}
function ed() {
  return Hs(this, arguments, 1);
}
function rd(e10, r) {
  return new this(e10).mod(r);
}
function td(e10, r) {
  return new this(e10).mul(r);
}
function nd(e10, r) {
  return new this(e10).pow(r);
}
function id(e10) {
  var r, t, n, i, o = 0, s = new this(1), a = [];
  if (e10 === void 0 ? e10 = this.precision : ie(e10, 1, Ye), n = Math.ceil(e10 / E), this.crypto) if (crypto.getRandomValues) for (r = crypto.getRandomValues(new Uint32Array(n)); o < n; ) i = r[o], i >= 429e7 ? r[o] = crypto.getRandomValues(new Uint32Array(1))[0] : a[o++] = i % 1e7;
  else if (crypto.randomBytes) {
    for (r = crypto.randomBytes(n *= 4); o < n; ) i = r[o] + (r[o + 1] << 8) + (r[o + 2] << 16) + ((r[o + 3] & 127) << 24), i >= 214e7 ? crypto.randomBytes(4).copy(r, o) : (a.push(i % 1e7), o += 4);
    o = n / 4;
  } else throw Error(Gs);
  else for (; o < n; ) a[o++] = Math.random() * 1e7 | 0;
  for (n = a[--o], e10 %= E, n && e10 && (i = U(10, E - e10), a[o] = (n / i | 0) * i); a[o] === 0; o--) a.pop();
  if (o < 0) t = 0, a = [0];
  else {
    for (t = -1; a[0] === 0; t -= E) a.shift();
    for (n = 1, i = a[0]; i >= 10; i /= 10) n++;
    n < E && (t -= E - n);
  }
  return s.e = t, s.d = a, s;
}
function od(e10) {
  return y(e10 = new this(e10), e10.e + 1, this.rounding);
}
function sd(e10) {
  return e10 = new this(e10), e10.d ? e10.d[0] ? e10.s : 0 * e10.s : e10.s || NaN;
}
function ad(e10) {
  return new this(e10).sin();
}
function ld(e10) {
  return new this(e10).sinh();
}
function ud(e10) {
  return new this(e10).sqrt();
}
function cd(e10, r) {
  return new this(e10).sub(r);
}
function pd() {
  var e10 = 0, r = arguments, t = new this(r[e10]);
  for (w = false; t.s && ++e10 < r.length; ) t = t.plus(r[e10]);
  return w = true, y(t, this.precision, this.rounding);
}
function dd(e10) {
  return new this(e10).tan();
}
function md(e10) {
  return new this(e10).tanh();
}
function fd(e10) {
  return y(e10 = new this(e10), e10.e + 1, 1);
}
m[Symbol.for("nodejs.util.inspect.custom")] = m.toString;
m[Symbol.toStringTag] = "Decimal";
var Le = m.constructor = Zs(Gi);
gn = new Le(gn);
hn = new Le(hn);
var Fe = Le;
function Tr(e10) {
  return Le.isDecimal(e10) ? true : e10 !== null && typeof e10 == "object" && typeof e10.s == "number" && typeof e10.e == "number" && typeof e10.toFixed == "function" && Array.isArray(e10.d);
}
var ut = {};
tr(ut, { ModelAction: () => Sr, datamodelEnumToSchemaEnum: () => gd });
function gd(e10) {
  return { name: e10.name, values: e10.values.map((r) => r.name) };
}
var Sr = ((b) => (b.findUnique = "findUnique", b.findUniqueOrThrow = "findUniqueOrThrow", b.findFirst = "findFirst", b.findFirstOrThrow = "findFirstOrThrow", b.findMany = "findMany", b.create = "create", b.createMany = "createMany", b.createManyAndReturn = "createManyAndReturn", b.update = "update", b.updateMany = "updateMany", b.updateManyAndReturn = "updateManyAndReturn", b.upsert = "upsert", b.delete = "delete", b.deleteMany = "deleteMany", b.groupBy = "groupBy", b.count = "count", b.aggregate = "aggregate", b.findRaw = "findRaw", b.aggregateRaw = "aggregateRaw", b))(Sr || {});
A(Di());
A(require$$2$1);
var Xs = { keyword: De, entity: De, value: (e10) => W(nr(e10)), punctuation: nr, directive: De, function: De, variable: (e10) => W(nr(e10)), string: (e10) => W(qe(e10)), boolean: Ie, number: De, comment: Kr };
var hd = (e10) => e10, xn = {}, yd = 0, v = { manual: xn.Prism && xn.Prism.manual, disableWorkerMessageHandler: xn.Prism && xn.Prism.disableWorkerMessageHandler, util: { encode: function(e10) {
  if (e10 instanceof ge) {
    let r = e10;
    return new ge(r.type, v.util.encode(r.content), r.alias);
  } else return Array.isArray(e10) ? e10.map(v.util.encode) : e10.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/\u00a0/g, " ");
}, type: function(e10) {
  return Object.prototype.toString.call(e10).slice(8, -1);
}, objId: function(e10) {
  return e10.__id || Object.defineProperty(e10, "__id", { value: ++yd }), e10.__id;
}, clone: function e3(r, t) {
  let n, i, o = v.util.type(r);
  switch (t = t || {}, o) {
    case "Object":
      if (i = v.util.objId(r), t[i]) return t[i];
      n = {}, t[i] = n;
      for (let s in r) r.hasOwnProperty(s) && (n[s] = e3(r[s], t));
      return n;
    case "Array":
      return i = v.util.objId(r), t[i] ? t[i] : (n = [], t[i] = n, r.forEach(function(s, a) {
        n[a] = e3(s, t);
      }), n);
    default:
      return r;
  }
} }, languages: { extend: function(e10, r) {
  let t = v.util.clone(v.languages[e10]);
  for (let n in r) t[n] = r[n];
  return t;
}, insertBefore: function(e10, r, t, n) {
  n = n || v.languages;
  let i = n[e10], o = {};
  for (let a in i) if (i.hasOwnProperty(a)) {
    if (a == r) for (let l in t) t.hasOwnProperty(l) && (o[l] = t[l]);
    t.hasOwnProperty(a) || (o[a] = i[a]);
  }
  let s = n[e10];
  return n[e10] = o, v.languages.DFS(v.languages, function(a, l) {
    l === s && a != e10 && (this[a] = o);
  }), o;
}, DFS: function e4(r, t, n, i) {
  i = i || {};
  let o = v.util.objId;
  for (let s in r) if (r.hasOwnProperty(s)) {
    t.call(r, s, r[s], n || s);
    let a = r[s], l = v.util.type(a);
    l === "Object" && !i[o(a)] ? (i[o(a)] = true, e4(a, t, null, i)) : l === "Array" && !i[o(a)] && (i[o(a)] = true, e4(a, t, s, i));
  }
} }};
v.languages.clike = { comment: [{ pattern: /(^|[^\\])\/\*[\s\S]*?(?:\*\/|$)/, lookbehind: true }, { pattern: /(^|[^\\:])\/\/.*/, lookbehind: true, greedy: true }], string: { pattern: /(["'])(?:\\(?:\r\n|[\s\S])|(?!\1)[^\\\r\n])*\1/, greedy: true }, "class-name": { pattern: /((?:\b(?:class|interface|extends|implements|trait|instanceof|new)\s+)|(?:catch\s+\())[\w.\\]+/i, lookbehind: true, inside: { punctuation: /[.\\]/ } }, keyword: /\b(?:if|else|while|do|for|return|in|instanceof|function|new|try|throw|catch|finally|null|break|continue)\b/, boolean: /\b(?:true|false)\b/, function: /\w+(?=\()/, number: /\b0x[\da-f]+\b|(?:\b\d+\.?\d*|\B\.\d+)(?:e[+-]?\d+)?/i, operator: /--?|\+\+?|!=?=?|<=?|>=?|==?=?|&&?|\|\|?|\?|\*|\/|~|\^|%/, punctuation: /[{}[\];(),.:]/ };
v.languages.javascript = v.languages.extend("clike", { "class-name": [v.languages.clike["class-name"], { pattern: /(^|[^$\w\xA0-\uFFFF])[_$A-Z\xA0-\uFFFF][$\w\xA0-\uFFFF]*(?=\.(?:prototype|constructor))/, lookbehind: true }], keyword: [{ pattern: /((?:^|})\s*)(?:catch|finally)\b/, lookbehind: true }, { pattern: /(^|[^.])\b(?:as|async(?=\s*(?:function\b|\(|[$\w\xA0-\uFFFF]|$))|await|break|case|class|const|continue|debugger|default|delete|do|else|enum|export|extends|for|from|function|get|if|implements|import|in|instanceof|interface|let|new|null|of|package|private|protected|public|return|set|static|super|switch|this|throw|try|typeof|undefined|var|void|while|with|yield)\b/, lookbehind: true }], number: /\b(?:(?:0[xX](?:[\dA-Fa-f](?:_[\dA-Fa-f])?)+|0[bB](?:[01](?:_[01])?)+|0[oO](?:[0-7](?:_[0-7])?)+)n?|(?:\d(?:_\d)?)+n|NaN|Infinity)\b|(?:\b(?:\d(?:_\d)?)+\.?(?:\d(?:_\d)?)*|\B\.(?:\d(?:_\d)?)+)(?:[Ee][+-]?(?:\d(?:_\d)?)+)?/, function: /[_$a-zA-Z\xA0-\uFFFF][$\w\xA0-\uFFFF]*(?=\s*(?:\.\s*(?:apply|bind|call)\s*)?\()/, operator: /-[-=]?|\+[+=]?|!=?=?|<<?=?|>>?>?=?|=(?:==?|>)?|&[&=]?|\|[|=]?|\*\*?=?|\/=?|~|\^=?|%=?|\?|\.{3}/ });
v.languages.javascript["class-name"][0].pattern = /(\b(?:class|interface|extends|implements|instanceof|new)\s+)[\w.\\]+/;
v.languages.insertBefore("javascript", "keyword", { regex: { pattern: /((?:^|[^$\w\xA0-\uFFFF."'\])\s])\s*)\/(\[(?:[^\]\\\r\n]|\\.)*]|\\.|[^/\\\[\r\n])+\/[gimyus]{0,6}(?=\s*($|[\r\n,.;})\]]))/, lookbehind: true, greedy: true }, "function-variable": { pattern: /[_$a-zA-Z\xA0-\uFFFF][$\w\xA0-\uFFFF]*(?=\s*[=:]\s*(?:async\s*)?(?:\bfunction\b|(?:\((?:[^()]|\([^()]*\))*\)|[_$a-zA-Z\xA0-\uFFFF][$\w\xA0-\uFFFF]*)\s*=>))/, alias: "function" }, parameter: [{ pattern: /(function(?:\s+[_$A-Za-z\xA0-\uFFFF][$\w\xA0-\uFFFF]*)?\s*\(\s*)(?!\s)(?:[^()]|\([^()]*\))+?(?=\s*\))/, lookbehind: true, inside: v.languages.javascript }, { pattern: /[_$a-z\xA0-\uFFFF][$\w\xA0-\uFFFF]*(?=\s*=>)/i, inside: v.languages.javascript }, { pattern: /(\(\s*)(?!\s)(?:[^()]|\([^()]*\))+?(?=\s*\)\s*=>)/, lookbehind: true, inside: v.languages.javascript }, { pattern: /((?:\b|\s|^)(?!(?:as|async|await|break|case|catch|class|const|continue|debugger|default|delete|do|else|enum|export|extends|finally|for|from|function|get|if|implements|import|in|instanceof|interface|let|new|null|of|package|private|protected|public|return|set|static|super|switch|this|throw|try|typeof|undefined|var|void|while|with|yield)(?![$\w\xA0-\uFFFF]))(?:[_$A-Za-z\xA0-\uFFFF][$\w\xA0-\uFFFF]*\s*)\(\s*)(?!\s)(?:[^()]|\([^()]*\))+?(?=\s*\)\s*\{)/, lookbehind: true, inside: v.languages.javascript }], constant: /\b[A-Z](?:[A-Z_]|\dx?)*\b/ });
v.languages.markup && v.languages.markup.tag.addInlined("script", "javascript");
v.languages.js = v.languages.javascript;
v.languages.typescript = v.languages.extend("javascript", { keyword: /\b(?:abstract|as|async|await|break|case|catch|class|const|constructor|continue|debugger|declare|default|delete|do|else|enum|export|extends|finally|for|from|function|get|if|implements|import|in|instanceof|interface|is|keyof|let|module|namespace|new|null|of|package|private|protected|public|readonly|return|require|set|static|super|switch|this|throw|try|type|typeof|var|void|while|with|yield)\b/, builtin: /\b(?:string|Function|any|number|boolean|Array|symbol|console|Promise|unknown|never)\b/ });
v.languages.ts = v.languages.typescript;
function ge(e10, r, t, n, i) {
  this.type = e10, this.content = r, this.alias = t, this.length = (n || "").length | 0, this.greedy = !!i;
}
ge.stringify = function(e10, r) {
  return typeof e10 == "string" ? e10 : Array.isArray(e10) ? e10.map(function(t) {
    return ge.stringify(t, r);
  }).join("") : bd(e10.type)(e10.content);
};
function bd(e10) {
  return Xs[e10] || hd;
}
var wd = { red: ce, gray: Kr, dim: Ce, bold: W, underline: Y, highlightSource: (e10) => e10.highlight() }, xd = { red: (e10) => e10, gray: (e10) => e10, dim: (e10) => e10, bold: (e10) => e10, underline: (e10) => e10, highlightSource: (e10) => e10 };
function vd({ message: e10, originalMethod: r, isPanic: t, callArguments: n }) {
  return { functionName: `prisma.${r}()`, message: e10, isPanic: t != null ? t : false, callArguments: n };
}
function Pd({ callsite: e10, message: r, originalMethod: t, isPanic: n, callArguments: i }, o) {
  let s = vd({ message: r, originalMethod: t, isPanic: n, callArguments: i });
  return s;
}
function Rd({ functionName: e10, location: r, message: t, isPanic: n, contextLines: i, callArguments: o }, s) {
  let a = [""], l = r ? " in" : ":";
  if (n ? (a.push(s.red(`Oops, an unknown error occurred! This is ${s.bold("on us")}, you did nothing wrong.`)), a.push(s.red(`It occurred in the ${s.bold(`\`${e10}\``)} invocation${l}`))) : a.push(s.red(`Invalid ${s.bold(`\`${e10}\``)} invocation${l}`)), r && a.push(s.underline(Ad(r))), i) {
    a.push("");
    let u = [i.toString()];
    o && (u.push(o), u.push(s.dim(")"))), a.push(u.join("")), o && a.push("");
  } else a.push(""), o && a.push(o), a.push("");
  return a.push(t), a.join(`
`);
}
function Ad(e10) {
  let r = [e10.fileName];
  return e10.lineNumber && r.push(String(e10.lineNumber)), e10.columnNumber && r.push(String(e10.columnNumber)), r.join(":");
}
function Pn(e10) {
  let r = e10.showColors ? wd : xd, t;
  return t = Pd(e10), Rd(t, r);
}
var da = A(Ki());
function aa(e10, r, t) {
  let n = la(e10), i = Cd(n), o = Dd(i);
  o ? Tn(o, r, t) : r.addErrorMessage(() => "Unknown error");
}
function la(e10) {
  return e10.errors.flatMap((r) => r.kind === "Union" ? la(r) : [r]);
}
function Cd(e10) {
  let r = /* @__PURE__ */ new Map(), t = [];
  for (let n of e10) {
    if (n.kind !== "InvalidArgumentType") {
      t.push(n);
      continue;
    }
    let i = `${n.selectionPath.join(".")}:${n.argumentPath.join(".")}`, o = r.get(i);
    o ? r.set(i, { ...n, argument: { ...n.argument, typeNames: Id(o.argument.typeNames, n.argument.typeNames) } }) : r.set(i, n);
  }
  return t.push(...r.values()), t;
}
function Id(e10, r) {
  return [...new Set(e10.concat(r))];
}
function Dd(e10) {
  return ji(e10, (r, t) => {
    let n = oa(r), i = oa(t);
    return n !== i ? n - i : sa(r) - sa(t);
  });
}
function oa(e10) {
  let r = 0;
  return Array.isArray(e10.selectionPath) && (r += e10.selectionPath.length), Array.isArray(e10.argumentPath) && (r += e10.argumentPath.length), r;
}
function sa(e10) {
  switch (e10.kind) {
    case "InvalidArgumentValue":
    case "ValueTooLarge":
      return 20;
    case "InvalidArgumentType":
      return 10;
    case "RequiredArgumentMissing":
      return -10;
    default:
      return 0;
  }
}
var ue = class {
  constructor(r, t) {
    __publicField(this, "isRequired", false);
    this.name = r;
    this.value = t;
  }
  makeRequired() {
    return this.isRequired = true, this;
  }
  write(r) {
    let { colors: { green: t } } = r.context;
    r.addMarginSymbol(t(this.isRequired ? "+" : "?")), r.write(t(this.name)), this.isRequired || r.write(t("?")), r.write(t(": ")), typeof this.value == "string" ? r.write(t(this.value)) : r.write(this.value);
  }
};
ca();
var Rr = class {
  constructor(r = 0, t) {
    __publicField(this, "lines", []);
    __publicField(this, "currentLine", "");
    __publicField(this, "currentIndent", 0);
    __publicField(this, "marginSymbol");
    __publicField(this, "afterNextNewLineCallback");
    this.context = t;
    this.currentIndent = r;
  }
  write(r) {
    return typeof r == "string" ? this.currentLine += r : r.write(this), this;
  }
  writeJoined(r, t, n = (i, o) => o.write(i)) {
    let i = t.length - 1;
    for (let o = 0; o < t.length; o++) n(t[o], this), o !== i && this.write(r);
    return this;
  }
  writeLine(r) {
    return this.write(r).newLine();
  }
  newLine() {
    this.lines.push(this.indentedCurrentLine()), this.currentLine = "", this.marginSymbol = void 0;
    let r = this.afterNextNewLineCallback;
    return this.afterNextNewLineCallback = void 0, r == null ? void 0 : r(), this;
  }
  withIndent(r) {
    return this.indent(), r(this), this.unindent(), this;
  }
  afterNextNewline(r) {
    return this.afterNextNewLineCallback = r, this;
  }
  indent() {
    return this.currentIndent++, this;
  }
  unindent() {
    return this.currentIndent > 0 && this.currentIndent--, this;
  }
  addMarginSymbol(r) {
    return this.marginSymbol = r, this;
  }
  toString() {
    return this.lines.concat(this.indentedCurrentLine()).join(`
`);
  }
  getCurrentLineLength() {
    return this.currentLine.length;
  }
  indentedCurrentLine() {
    let r = this.currentLine.padStart(this.currentLine.length + 2 * this.currentIndent);
    return this.marginSymbol ? this.marginSymbol + r.slice(1) : r;
  }
};
ua();
var Sn = class {
  constructor(r) {
    this.value = r;
  }
  write(r) {
    r.write(this.value);
  }
  markAsError() {
    this.value.markAsError();
  }
};
var Rn = (e10) => e10, An = { bold: Rn, red: Rn, green: Rn, dim: Rn, enabled: false }, pa = { bold: W, red: ce, green: qe, dim: Ce, enabled: true }, Ar = { write(e10) {
  e10.writeLine(",");
} };
var Pe = class {
  constructor(r) {
    __publicField(this, "isUnderlined", false);
    __publicField(this, "color", (r) => r);
    this.contents = r;
  }
  underline() {
    return this.isUnderlined = true, this;
  }
  setColor(r) {
    return this.color = r, this;
  }
  write(r) {
    let t = r.getCurrentLineLength();
    r.write(this.color(this.contents)), this.isUnderlined && r.afterNextNewline(() => {
      r.write(" ".repeat(t)).writeLine(this.color("~".repeat(this.contents.length)));
    });
  }
};
var ze = class {
  constructor() {
    __publicField(this, "hasError", false);
  }
  markAsError() {
    return this.hasError = true, this;
  }
};
var Cr = class extends ze {
  constructor() {
    super(...arguments);
    __publicField(this, "items", []);
  }
  addItem(r) {
    return this.items.push(new Sn(r)), this;
  }
  getField(r) {
    return this.items[r];
  }
  getPrintWidth() {
    return this.items.length === 0 ? 2 : Math.max(...this.items.map((t) => t.value.getPrintWidth())) + 2;
  }
  write(r) {
    if (this.items.length === 0) {
      this.writeEmpty(r);
      return;
    }
    this.writeWithItems(r);
  }
  writeEmpty(r) {
    let t = new Pe("[]");
    this.hasError && t.setColor(r.context.colors.red).underline(), r.write(t);
  }
  writeWithItems(r) {
    let { colors: t } = r.context;
    r.writeLine("[").withIndent(() => r.writeJoined(Ar, this.items).newLine()).write("]"), this.hasError && r.afterNextNewline(() => {
      r.writeLine(t.red("~".repeat(this.getPrintWidth())));
    });
  }
  asObject() {
  }
};
var Ir = class e6 extends ze {
  constructor() {
    super(...arguments);
    __publicField(this, "fields", {});
    __publicField(this, "suggestions", []);
  }
  addField(r) {
    this.fields[r.name] = r;
  }
  addSuggestion(r) {
    this.suggestions.push(r);
  }
  getField(r) {
    return this.fields[r];
  }
  getDeepField(r) {
    let [t, ...n] = r, i = this.getField(t);
    if (!i) return;
    let o = i;
    for (let s of n) {
      let a;
      if (o.value instanceof e6 ? a = o.value.getField(s) : o.value instanceof Cr && (a = o.value.getField(Number(s))), !a) return;
      o = a;
    }
    return o;
  }
  getDeepFieldValue(r) {
    var _a3;
    return r.length === 0 ? this : (_a3 = this.getDeepField(r)) == null ? void 0 : _a3.value;
  }
  hasField(r) {
    return !!this.getField(r);
  }
  removeAllFields() {
    this.fields = {};
  }
  removeField(r) {
    delete this.fields[r];
  }
  getFields() {
    return this.fields;
  }
  isEmpty() {
    return Object.keys(this.fields).length === 0;
  }
  getFieldValue(r) {
    var _a3;
    return (_a3 = this.getField(r)) == null ? void 0 : _a3.value;
  }
  getDeepSubSelectionValue(r) {
    let t = this;
    for (let n of r) {
      if (!(t instanceof e6)) return;
      let i = t.getSubSelectionValue(n);
      if (!i) return;
      t = i;
    }
    return t;
  }
  getDeepSelectionParent(r) {
    let t = this.getSelectionParent();
    if (!t) return;
    let n = t;
    for (let i of r) {
      let o = n.value.getFieldValue(i);
      if (!o || !(o instanceof e6)) return;
      let s = o.getSelectionParent();
      if (!s) return;
      n = s;
    }
    return n;
  }
  getSelectionParent() {
    var _a3, _b2;
    let r = (_a3 = this.getField("select")) == null ? void 0 : _a3.value.asObject();
    if (r) return { kind: "select", value: r };
    let t = (_b2 = this.getField("include")) == null ? void 0 : _b2.value.asObject();
    if (t) return { kind: "include", value: t };
  }
  getSubSelectionValue(r) {
    var _a3;
    return (_a3 = this.getSelectionParent()) == null ? void 0 : _a3.value.fields[r].value;
  }
  getPrintWidth() {
    let r = Object.values(this.fields);
    return r.length == 0 ? 2 : Math.max(...r.map((n) => n.getPrintWidth())) + 2;
  }
  write(r) {
    let t = Object.values(this.fields);
    if (t.length === 0 && this.suggestions.length === 0) {
      this.writeEmpty(r);
      return;
    }
    this.writeWithContents(r, t);
  }
  asObject() {
    return this;
  }
  writeEmpty(r) {
    let t = new Pe("{}");
    this.hasError && t.setColor(r.context.colors.red).underline(), r.write(t);
  }
  writeWithContents(r, t) {
    r.writeLine("{").withIndent(() => {
      r.writeJoined(Ar, [...t, ...this.suggestions]).newLine();
    }), r.write("}"), this.hasError && r.afterNextNewline(() => {
      r.writeLine(r.context.colors.red("~".repeat(this.getPrintWidth())));
    });
  }
};
var Q = class extends ze {
  constructor(t) {
    super();
    this.text = t;
  }
  getPrintWidth() {
    return this.text.length;
  }
  write(t) {
    let n = new Pe(this.text);
    this.hasError && n.underline().setColor(t.context.colors.red), t.write(n);
  }
  asObject() {
  }
};
var ct = class {
  constructor() {
    __publicField(this, "fields", []);
  }
  addField(r, t) {
    return this.fields.push({ write(n) {
      let { green: i, dim: o } = n.context.colors;
      n.write(i(o(`${r}: ${t}`))).addMarginSymbol(i(o("+")));
    } }), this;
  }
  write(r) {
    let { colors: { green: t } } = r.context;
    r.writeLine(t("{")).withIndent(() => {
      r.writeJoined(Ar, this.fields).newLine();
    }).write(t("}")).addMarginSymbol(t("+"));
  }
};
function Tn(e10, r, t) {
  switch (e10.kind) {
    case "MutuallyExclusiveFields":
      Od(e10, r);
      break;
    case "IncludeOnScalar":
      kd(e10, r);
      break;
    case "EmptySelection":
      _d(e10, r, t);
      break;
    case "UnknownSelectionField":
      Md(e10, r);
      break;
    case "InvalidSelectionValue":
      $d(e10, r);
      break;
    case "UnknownArgument":
      qd(e10, r);
      break;
    case "UnknownInputField":
      Vd(e10, r);
      break;
    case "RequiredArgumentMissing":
      jd(e10, r);
      break;
    case "InvalidArgumentType":
      Bd(e10, r);
      break;
    case "InvalidArgumentValue":
      Ud(e10, r);
      break;
    case "ValueTooLarge":
      Gd(e10, r);
      break;
    case "SomeFieldsMissing":
      Qd(e10, r);
      break;
    case "TooManyFieldsGiven":
      Wd(e10, r);
      break;
    case "Union":
      aa(e10, r, t);
      break;
    default:
      throw new Error("not implemented: " + e10.kind);
  }
}
function Od(e10, r) {
  var _a3, _b2, _c3;
  let t = (_a3 = r.arguments.getDeepSubSelectionValue(e10.selectionPath)) == null ? void 0 : _a3.asObject();
  t && ((_b2 = t.getField(e10.firstField)) == null ? void 0 : _b2.markAsError(), (_c3 = t.getField(e10.secondField)) == null ? void 0 : _c3.markAsError()), r.addErrorMessage((n) => `Please ${n.bold("either")} use ${n.green(`\`${e10.firstField}\``)} or ${n.green(`\`${e10.secondField}\``)}, but ${n.red("not both")} at the same time.`);
}
function kd(e10, r) {
  var _a3, _b2;
  let [t, n] = Dr(e10.selectionPath), i = e10.outputType, o = (_a3 = r.arguments.getDeepSelectionParent(t)) == null ? void 0 : _a3.value;
  if (o && ((_b2 = o.getField(n)) == null ? void 0 : _b2.markAsError(), i)) for (let s of i.fields) s.isRelation && o.addSuggestion(new ue(s.name, "true"));
  r.addErrorMessage((s) => {
    let a = `Invalid scalar field ${s.red(`\`${n}\``)} for ${s.bold("include")} statement`;
    return i ? a += ` on model ${s.bold(i.name)}. ${pt(s)}` : a += ".", a += `
Note that ${s.bold("include")} statements only accept relation fields.`, a;
  });
}
function _d(e10, r, t) {
  var _a3, _b2;
  let n = (_a3 = r.arguments.getDeepSubSelectionValue(e10.selectionPath)) == null ? void 0 : _a3.asObject();
  if (n) {
    let i = (_b2 = n.getField("omit")) == null ? void 0 : _b2.value.asObject();
    if (i) {
      Nd(e10, r, i);
      return;
    }
    if (n.hasField("select")) {
      Ld(e10, r);
      return;
    }
  }
  if (t == null ? void 0 : t[We(e10.outputType.name)]) {
    Fd(e10, r);
    return;
  }
  r.addErrorMessage(() => `Unknown field at "${e10.selectionPath.join(".")} selection"`);
}
function Nd(e10, r, t) {
  t.removeAllFields();
  for (let n of e10.outputType.fields) t.addSuggestion(new ue(n.name, "false"));
  r.addErrorMessage((n) => `The ${n.red("omit")} statement includes every field of the model ${n.bold(e10.outputType.name)}. At least one field must be included in the result`);
}
function Ld(e10, r) {
  var _a3, _b2;
  let t = e10.outputType, n = (_a3 = r.arguments.getDeepSelectionParent(e10.selectionPath)) == null ? void 0 : _a3.value, i = (_b2 = n == null ? void 0 : n.isEmpty()) != null ? _b2 : false;
  n && (n.removeAllFields(), ga(n, t)), r.addErrorMessage((o) => i ? `The ${o.red("`select`")} statement for type ${o.bold(t.name)} must not be empty. ${pt(o)}` : `The ${o.red("`select`")} statement for type ${o.bold(t.name)} needs ${o.bold("at least one truthy value")}.`);
}
function Fd(e10, r) {
  var _a3, _b2, _c3;
  let t = new ct();
  for (let i of e10.outputType.fields) i.isRelation || t.addField(i.name, "false");
  let n = new ue("omit", t).makeRequired();
  if (e10.selectionPath.length === 0) r.arguments.addSuggestion(n);
  else {
    let [i, o] = Dr(e10.selectionPath), a = (_b2 = (_a3 = r.arguments.getDeepSelectionParent(i)) == null ? void 0 : _a3.value.asObject()) == null ? void 0 : _b2.getField(o);
    if (a) {
      let l = (_c3 = a == null ? void 0 : a.value.asObject()) != null ? _c3 : new Ir();
      l.addSuggestion(n), a.value = l;
    }
  }
  r.addErrorMessage((i) => `The global ${i.red("omit")} configuration excludes every field of the model ${i.bold(e10.outputType.name)}. At least one field must be included in the result`);
}
function Md(e10, r) {
  let t = ha(e10.selectionPath, r);
  if (t.parentKind !== "unknown") {
    t.field.markAsError();
    let n = t.parent;
    switch (t.parentKind) {
      case "select":
        ga(n, e10.outputType);
        break;
      case "include":
        Jd(n, e10.outputType);
        break;
      case "omit":
        Kd(n, e10.outputType);
        break;
    }
  }
  r.addErrorMessage((n) => {
    let i = [`Unknown field ${n.red(`\`${t.fieldName}\``)}`];
    return t.parentKind !== "unknown" && i.push(`for ${n.bold(t.parentKind)} statement`), i.push(`on model ${n.bold(`\`${e10.outputType.name}\``)}.`), i.push(pt(n)), i.join(" ");
  });
}
function $d(e10, r) {
  let t = ha(e10.selectionPath, r);
  t.parentKind !== "unknown" && t.field.value.markAsError(), r.addErrorMessage((n) => `Invalid value for selection field \`${n.red(t.fieldName)}\`: ${e10.underlyingError}`);
}
function qd(e10, r) {
  var _a3, _b2;
  let t = e10.argumentPath[0], n = (_a3 = r.arguments.getDeepSubSelectionValue(e10.selectionPath)) == null ? void 0 : _a3.asObject();
  n && ((_b2 = n.getField(t)) == null ? void 0 : _b2.markAsError(), Hd(n, e10.arguments)), r.addErrorMessage((i) => ma(i, t, e10.arguments.map((o) => o.name)));
}
function Vd(e10, r) {
  var _a3, _b2, _c3;
  let [t, n] = Dr(e10.argumentPath), i = (_a3 = r.arguments.getDeepSubSelectionValue(e10.selectionPath)) == null ? void 0 : _a3.asObject();
  if (i) {
    (_b2 = i.getDeepField(e10.argumentPath)) == null ? void 0 : _b2.markAsError();
    let o = (_c3 = i.getDeepFieldValue(t)) == null ? void 0 : _c3.asObject();
    o && ya(o, e10.inputType);
  }
  r.addErrorMessage((o) => ma(o, n, e10.inputType.fields.map((s) => s.name)));
}
function ma(e10, r, t) {
  let n = [`Unknown argument \`${e10.red(r)}\`.`], i = zd(r, t);
  return i && n.push(`Did you mean \`${e10.green(i)}\`?`), t.length > 0 && n.push(pt(e10)), n.join(" ");
}
function jd(e10, r) {
  var _a3, _b2, _c3;
  let t;
  r.addErrorMessage((l) => (t == null ? void 0 : t.value) instanceof Q && t.value.text === "null" ? `Argument \`${l.green(o)}\` must not be ${l.red("null")}.` : `Argument \`${l.green(o)}\` is missing.`);
  let n = (_a3 = r.arguments.getDeepSubSelectionValue(e10.selectionPath)) == null ? void 0 : _a3.asObject();
  if (!n) return;
  let [i, o] = Dr(e10.argumentPath), s = new ct(), a = (_b2 = n.getDeepFieldValue(i)) == null ? void 0 : _b2.asObject();
  if (a) {
    if (t = a.getField(o), t && a.removeField(o), e10.inputTypes.length === 1 && e10.inputTypes[0].kind === "object") {
      for (let l of e10.inputTypes[0].fields) s.addField(l.name, l.typeNames.join(" | "));
      a.addSuggestion(new ue(o, s).makeRequired());
    } else {
      let l = e10.inputTypes.map(fa).join(" | ");
      a.addSuggestion(new ue(o, l).makeRequired());
    }
    if (e10.dependentArgumentPath) {
      (_c3 = n.getDeepField(e10.dependentArgumentPath)) == null ? void 0 : _c3.markAsError();
      let [, l] = Dr(e10.dependentArgumentPath);
      r.addErrorMessage((u) => `Argument \`${u.green(o)}\` is required because argument \`${u.green(l)}\` was provided.`);
    }
  }
}
function fa(e10) {
  return e10.kind === "list" ? `${fa(e10.elementType)}[]` : e10.name;
}
function Bd(e10, r) {
  var _a3, _b2;
  let t = e10.argument.name, n = (_a3 = r.arguments.getDeepSubSelectionValue(e10.selectionPath)) == null ? void 0 : _a3.asObject();
  n && ((_b2 = n.getDeepFieldValue(e10.argumentPath)) == null ? void 0 : _b2.markAsError()), r.addErrorMessage((i) => {
    let o = Cn("or", e10.argument.typeNames.map((s) => i.green(s)));
    return `Argument \`${i.bold(t)}\`: Invalid value provided. Expected ${o}, provided ${i.red(e10.inferredType)}.`;
  });
}
function Ud(e10, r) {
  var _a3, _b2;
  let t = e10.argument.name, n = (_a3 = r.arguments.getDeepSubSelectionValue(e10.selectionPath)) == null ? void 0 : _a3.asObject();
  n && ((_b2 = n.getDeepFieldValue(e10.argumentPath)) == null ? void 0 : _b2.markAsError()), r.addErrorMessage((i) => {
    let o = [`Invalid value for argument \`${i.bold(t)}\``];
    if (e10.underlyingError && o.push(`: ${e10.underlyingError}`), o.push("."), e10.argument.typeNames.length > 0) {
      let s = Cn("or", e10.argument.typeNames.map((a) => i.green(a)));
      o.push(` Expected ${s}.`);
    }
    return o.join("");
  });
}
function Gd(e10, r) {
  var _a3, _b2;
  let t = e10.argument.name, n = (_a3 = r.arguments.getDeepSubSelectionValue(e10.selectionPath)) == null ? void 0 : _a3.asObject(), i;
  if (n) {
    let s = (_b2 = n.getDeepField(e10.argumentPath)) == null ? void 0 : _b2.value;
    s == null ? void 0 : s.markAsError(), s instanceof Q && (i = s.text);
  }
  r.addErrorMessage((o) => {
    let s = ["Unable to fit value"];
    return i && s.push(o.red(i)), s.push(`into a 64-bit signed integer for field \`${o.bold(t)}\``), s.join(" ");
  });
}
function Qd(e10, r) {
  var _a3, _b2;
  let t = e10.argumentPath[e10.argumentPath.length - 1], n = (_a3 = r.arguments.getDeepSubSelectionValue(e10.selectionPath)) == null ? void 0 : _a3.asObject();
  if (n) {
    let i = (_b2 = n.getDeepFieldValue(e10.argumentPath)) == null ? void 0 : _b2.asObject();
    i && ya(i, e10.inputType);
  }
  r.addErrorMessage((i) => {
    let o = [`Argument \`${i.bold(t)}\` of type ${i.bold(e10.inputType.name)} needs`];
    return e10.constraints.minFieldCount === 1 ? e10.constraints.requiredFields ? o.push(`${i.green("at least one of")} ${Cn("or", e10.constraints.requiredFields.map((s) => `\`${i.bold(s)}\``))} arguments.`) : o.push(`${i.green("at least one")} argument.`) : o.push(`${i.green(`at least ${e10.constraints.minFieldCount}`)} arguments.`), o.push(pt(i)), o.join(" ");
  });
}
function Wd(e10, r) {
  var _a3, _b2;
  let t = e10.argumentPath[e10.argumentPath.length - 1], n = (_a3 = r.arguments.getDeepSubSelectionValue(e10.selectionPath)) == null ? void 0 : _a3.asObject(), i = [];
  if (n) {
    let o = (_b2 = n.getDeepFieldValue(e10.argumentPath)) == null ? void 0 : _b2.asObject();
    o && (o.markAsError(), i = Object.keys(o.getFields()));
  }
  r.addErrorMessage((o) => {
    let s = [`Argument \`${o.bold(t)}\` of type ${o.bold(e10.inputType.name)} needs`];
    return e10.constraints.minFieldCount === 1 && e10.constraints.maxFieldCount == 1 ? s.push(`${o.green("exactly one")} argument,`) : e10.constraints.maxFieldCount == 1 ? s.push(`${o.green("at most one")} argument,`) : s.push(`${o.green(`at most ${e10.constraints.maxFieldCount}`)} arguments,`), s.push(`but you provided ${Cn("and", i.map((a) => o.red(a)))}. Please choose`), e10.constraints.maxFieldCount === 1 ? s.push("one.") : s.push(`${e10.constraints.maxFieldCount}.`), s.join(" ");
  });
}
function ga(e10, r) {
  for (let t of r.fields) e10.hasField(t.name) || e10.addSuggestion(new ue(t.name, "true"));
}
function Jd(e10, r) {
  for (let t of r.fields) t.isRelation && !e10.hasField(t.name) && e10.addSuggestion(new ue(t.name, "true"));
}
function Kd(e10, r) {
  for (let t of r.fields) !e10.hasField(t.name) && !t.isRelation && e10.addSuggestion(new ue(t.name, "true"));
}
function Hd(e10, r) {
  for (let t of r) e10.hasField(t.name) || e10.addSuggestion(new ue(t.name, t.typeNames.join(" | ")));
}
function ha(e10, r) {
  var _a3, _b2, _c3, _d3;
  let [t, n] = Dr(e10), i = (_a3 = r.arguments.getDeepSubSelectionValue(t)) == null ? void 0 : _a3.asObject();
  if (!i) return { parentKind: "unknown", fieldName: n };
  let o = (_b2 = i.getFieldValue("select")) == null ? void 0 : _b2.asObject(), s = (_c3 = i.getFieldValue("include")) == null ? void 0 : _c3.asObject(), a = (_d3 = i.getFieldValue("omit")) == null ? void 0 : _d3.asObject(), l = o == null ? void 0 : o.getField(n);
  return o && l ? { parentKind: "select", parent: o, field: l, fieldName: n } : (l = s == null ? void 0 : s.getField(n), s && l ? { parentKind: "include", field: l, parent: s, fieldName: n } : (l = a == null ? void 0 : a.getField(n), a && l ? { parentKind: "omit", field: l, parent: a, fieldName: n } : { parentKind: "unknown", fieldName: n }));
}
function ya(e10, r) {
  if (r.kind === "object") for (let t of r.fields) e10.hasField(t.name) || e10.addSuggestion(new ue(t.name, t.typeNames.join(" | ")));
}
function Dr(e10) {
  let r = [...e10], t = r.pop();
  if (!t) throw new Error("unexpected empty path");
  return [r, t];
}
function pt({ green: e10, enabled: r }) {
  return "Available options are " + (r ? `listed in ${e10("green")}` : "marked with ?") + ".";
}
function Cn(e10, r) {
  if (r.length === 1) return r[0];
  let t = [...r], n = t.pop();
  return `${t.join(", ")} ${e10} ${n}`;
}
var Yd = 3;
function zd(e10, r) {
  let t = 1 / 0, n;
  for (let i of r) {
    let o = (0, da.default)(e10, i);
    o > Yd || o < t && (t = o, n = i);
  }
  return n;
}
var dt = class {
  constructor(r, t, n, i, o) {
    __publicField(this, "modelName");
    __publicField(this, "name");
    __publicField(this, "typeName");
    __publicField(this, "isList");
    __publicField(this, "isEnum");
    this.modelName = r, this.name = t, this.typeName = n, this.isList = i, this.isEnum = o;
  }
  _toGraphQLInputType() {
    let r = this.isList ? "List" : "", t = this.isEnum ? "Enum" : "";
    return `${r}${t}${this.typeName}FieldRefInput<${this.modelName}>`;
  }
};
function Or(e10) {
  return e10 instanceof dt;
}
var In = Symbol(), Yi = /* @__PURE__ */ new WeakMap(), Me = class {
  constructor(r) {
    r === In ? Yi.set(this, `Prisma.${this._getName()}`) : Yi.set(this, `new Prisma.${this._getNamespace()}.${this._getName()}()`);
  }
  _getName() {
    return this.constructor.name;
  }
  toString() {
    return Yi.get(this);
  }
}, mt = class extends Me {
  _getNamespace() {
    return "NullTypes";
  }
}, ft = (_I = class extends mt {
  constructor() {
    super(...arguments);
    __privateAdd(this, _e2);
  }
}, _e2 = new WeakMap(), _I);
zi(ft, "DbNull");
var gt = (_J = class extends mt {
  constructor() {
    super(...arguments);
    __privateAdd(this, _e3);
  }
}, _e3 = new WeakMap(), _J);
zi(gt, "JsonNull");
var ht = (_K = class extends mt {
  constructor() {
    super(...arguments);
    __privateAdd(this, _e4);
  }
}, _e4 = new WeakMap(), _K);
zi(ht, "AnyNull");
var Dn = { classes: { DbNull: ft, JsonNull: gt, AnyNull: ht }, instances: { DbNull: new ft(In), JsonNull: new gt(In), AnyNull: new ht(In) } };
function zi(e10, r) {
  Object.defineProperty(e10, "name", { value: r, configurable: true });
}
var ba = ": ", On = class {
  constructor(r, t) {
    __publicField(this, "hasError", false);
    this.name = r;
    this.value = t;
  }
  markAsError() {
    this.hasError = true;
  }
  getPrintWidth() {
    return this.name.length + this.value.getPrintWidth() + ba.length;
  }
  write(r) {
    let t = new Pe(this.name);
    this.hasError && t.underline().setColor(r.context.colors.red), r.write(t).write(ba).write(this.value);
  }
};
var Zi = class {
  constructor(r) {
    __publicField(this, "arguments");
    __publicField(this, "errorMessages", []);
    this.arguments = r;
  }
  write(r) {
    r.write(this.arguments);
  }
  addErrorMessage(r) {
    this.errorMessages.push(r);
  }
  renderAllMessages(r) {
    return this.errorMessages.map((t) => t(r)).join(`
`);
  }
};
function kr(e10) {
  return new Zi(Ea(e10));
}
function Ea(e10) {
  let r = new Ir();
  for (let [t, n] of Object.entries(e10)) {
    let i = new On(t, wa(n));
    r.addField(i);
  }
  return r;
}
function wa(e10) {
  if (typeof e10 == "string") return new Q(JSON.stringify(e10));
  if (typeof e10 == "number" || typeof e10 == "boolean") return new Q(String(e10));
  if (typeof e10 == "bigint") return new Q(`${e10}n`);
  if (e10 === null) return new Q("null");
  if (e10 === void 0) return new Q("undefined");
  if (Tr(e10)) return new Q(`new Prisma.Decimal("${e10.toFixed()}")`);
  if (e10 instanceof Uint8Array) return Buffer.isBuffer(e10) ? new Q(`Buffer.alloc(${e10.byteLength})`) : new Q(`new Uint8Array(${e10.byteLength})`);
  if (e10 instanceof Date) {
    let r = dn(e10) ? e10.toISOString() : "Invalid Date";
    return new Q(`new Date("${r}")`);
  }
  return e10 instanceof Me ? new Q(`Prisma.${e10._getName()}`) : Or(e10) ? new Q(`prisma.${We(e10.modelName)}.$fields.${e10.name}`) : Array.isArray(e10) ? Zd(e10) : typeof e10 == "object" ? Ea(e10) : new Q(Object.prototype.toString.call(e10));
}
function Zd(e10) {
  let r = new Cr();
  for (let t of e10) r.addItem(wa(t));
  return r;
}
function kn(e10, r) {
  let t = r === "pretty" ? pa : An, n = e10.renderAllMessages(t), i = new Rr(0, { colors: t }).write(e10).toString();
  return { message: n, args: i };
}
function _n({ args: e10, errors: r, errorFormat: t, callsite: n, originalMethod: i, clientVersion: o, globalOmit: s }) {
  let a = kr(e10);
  for (let p of r) Tn(p, a, s);
  let { message: l, args: u } = kn(a, t), c = Pn({ message: l, callsite: n, originalMethod: i, showColors: t === "pretty", callArguments: u });
  throw new Z(c, { clientVersion: o });
}
function Te(e10) {
  return e10.replace(/^./, (r) => r.toLowerCase());
}
function va(e10, r, t) {
  let n = Te(t);
  return !r.result || !(r.result.$allModels || r.result[n]) ? e10 : Xd({ ...e10, ...xa(r.name, e10, r.result.$allModels), ...xa(r.name, e10, r.result[n]) });
}
function Xd(e10) {
  let r = new we(), t = (n, i) => r.getOrCreate(n, () => i.has(n) ? [n] : (i.add(n), e10[n] ? e10[n].needs.flatMap((o) => t(o, i)) : [n]));
  return cn(e10, (n) => ({ ...n, needs: t(n.name, /* @__PURE__ */ new Set()) }));
}
function xa(e10, r, t) {
  return t ? cn(t, ({ needs: n, compute: i }, o) => ({ name: o, needs: n ? Object.keys(n).filter((s) => n[s]) : [], compute: em(r, o, i) })) : {};
}
function em(e10, r, t) {
  var _a3;
  let n = (_a3 = e10 == null ? void 0 : e10[r]) == null ? void 0 : _a3.compute;
  return n ? (i) => t({ ...i, [r]: n(i) }) : t;
}
function Pa(e10, r) {
  if (!r) return e10;
  let t = { ...e10 };
  for (let n of Object.values(r)) if (e10[n.name]) for (let i of n.needs) t[i] = true;
  return t;
}
function Ta(e10, r) {
  if (!r) return e10;
  let t = { ...e10 };
  for (let n of Object.values(r)) if (!e10[n.name]) for (let i of n.needs) delete t[i];
  return t;
}
var Nn = class {
  constructor(r, t) {
    __publicField(this, "computedFieldsCache", new we());
    __publicField(this, "modelExtensionsCache", new we());
    __publicField(this, "queryCallbacksCache", new we());
    __publicField(this, "clientExtensions", at(() => {
      var _a3, _b2;
      return this.extension.client ? { ...(_a3 = this.previous) == null ? void 0 : _a3.getAllClientExtensions(), ...this.extension.client } : (_b2 = this.previous) == null ? void 0 : _b2.getAllClientExtensions();
    }));
    __publicField(this, "batchCallbacks", at(() => {
      var _a3, _b2, _c3;
      let r = (_b2 = (_a3 = this.previous) == null ? void 0 : _a3.getAllBatchQueryCallbacks()) != null ? _b2 : [], t = (_c3 = this.extension.query) == null ? void 0 : _c3.$__internalBatch;
      return t ? r.concat(t) : r;
    }));
    this.extension = r;
    this.previous = t;
  }
  getAllComputedFields(r) {
    return this.computedFieldsCache.getOrCreate(r, () => {
      var _a3;
      return va((_a3 = this.previous) == null ? void 0 : _a3.getAllComputedFields(r), this.extension, r);
    });
  }
  getAllClientExtensions() {
    return this.clientExtensions.get();
  }
  getAllModelExtensions(r) {
    return this.modelExtensionsCache.getOrCreate(r, () => {
      var _a3, _b2;
      let t = Te(r);
      return !this.extension.model || !(this.extension.model[t] || this.extension.model.$allModels) ? (_a3 = this.previous) == null ? void 0 : _a3.getAllModelExtensions(r) : { ...(_b2 = this.previous) == null ? void 0 : _b2.getAllModelExtensions(r), ...this.extension.model.$allModels, ...this.extension.model[t] };
    });
  }
  getAllQueryCallbacks(r, t) {
    return this.queryCallbacksCache.getOrCreate(`${r}:${t}`, () => {
      var _a3, _b2;
      let n = (_b2 = (_a3 = this.previous) == null ? void 0 : _a3.getAllQueryCallbacks(r, t)) != null ? _b2 : [], i = [], o = this.extension.query;
      return !o || !(o[r] || o.$allModels || o[t] || o.$allOperations) ? n : (o[r] !== void 0 && (o[r][t] !== void 0 && i.push(o[r][t]), o[r].$allOperations !== void 0 && i.push(o[r].$allOperations)), r !== "$none" && o.$allModels !== void 0 && (o.$allModels[t] !== void 0 && i.push(o.$allModels[t]), o.$allModels.$allOperations !== void 0 && i.push(o.$allModels.$allOperations)), o[t] !== void 0 && i.push(o[t]), o.$allOperations !== void 0 && i.push(o.$allOperations), n.concat(i));
    });
  }
  getAllBatchQueryCallbacks() {
    return this.batchCallbacks.get();
  }
}, _r = class e7 {
  constructor(r) {
    this.head = r;
  }
  static empty() {
    return new e7();
  }
  static single(r) {
    return new e7(new Nn(r));
  }
  isEmpty() {
    return this.head === void 0;
  }
  append(r) {
    return new e7(new Nn(r, this.head));
  }
  getAllComputedFields(r) {
    var _a3;
    return (_a3 = this.head) == null ? void 0 : _a3.getAllComputedFields(r);
  }
  getAllClientExtensions() {
    var _a3;
    return (_a3 = this.head) == null ? void 0 : _a3.getAllClientExtensions();
  }
  getAllModelExtensions(r) {
    var _a3;
    return (_a3 = this.head) == null ? void 0 : _a3.getAllModelExtensions(r);
  }
  getAllQueryCallbacks(r, t) {
    var _a3, _b2;
    return (_b2 = (_a3 = this.head) == null ? void 0 : _a3.getAllQueryCallbacks(r, t)) != null ? _b2 : [];
  }
  getAllBatchQueryCallbacks() {
    var _a3, _b2;
    return (_b2 = (_a3 = this.head) == null ? void 0 : _a3.getAllBatchQueryCallbacks()) != null ? _b2 : [];
  }
};
var Ln = class {
  constructor(r) {
    this.name = r;
  }
};
function Sa(e10) {
  return e10 instanceof Ln;
}
function Ra(e10) {
  return new Ln(e10);
}
var Aa = Symbol(), yt = class {
  constructor(r) {
    if (r !== Aa) throw new Error("Skip instance can not be constructed directly");
  }
  ifUndefined(r) {
    return r === void 0 ? Fn : r;
  }
}, Fn = new yt(Aa);
function Se(e10) {
  return e10 instanceof yt;
}
var rm = { findUnique: "findUnique", findUniqueOrThrow: "findUniqueOrThrow", findFirst: "findFirst", findFirstOrThrow: "findFirstOrThrow", findMany: "findMany", count: "aggregate", create: "createOne", createMany: "createMany", createManyAndReturn: "createManyAndReturn", update: "updateOne", updateMany: "updateMany", updateManyAndReturn: "updateManyAndReturn", upsert: "upsertOne", delete: "deleteOne", deleteMany: "deleteMany", executeRaw: "executeRaw", queryRaw: "queryRaw", aggregate: "aggregate", groupBy: "groupBy", runCommandRaw: "runCommandRaw", findRaw: "findRaw", aggregateRaw: "aggregateRaw" }, Ca = "explicitly `undefined` values are not allowed";
function Mn({ modelName: e10, action: r, args: t, runtimeDataModel: n, extensions: i = _r.empty(), callsite: o, clientMethod: s, errorFormat: a, clientVersion: l, previewFeatures: u, globalOmit: c }) {
  let p = new Xi({ runtimeDataModel: n, modelName: e10, action: r, rootArgs: t, callsite: o, extensions: i, selectionPath: [], argumentPath: [], originalMethod: s, errorFormat: a, clientVersion: l, previewFeatures: u, globalOmit: c });
  return { modelName: e10, action: rm[r], query: bt(t, p) };
}
function bt({ select: e10, include: r, ...t } = {}, n) {
  let i = t.omit;
  return delete t.omit, { arguments: Da(t, n), selection: tm(e10, r, i, n) };
}
function tm(e10, r, t, n) {
  return e10 ? (r ? n.throwValidationError({ kind: "MutuallyExclusiveFields", firstField: "include", secondField: "select", selectionPath: n.getSelectionPath() }) : t && n.throwValidationError({ kind: "MutuallyExclusiveFields", firstField: "omit", secondField: "select", selectionPath: n.getSelectionPath() }), sm(e10, n)) : nm(n, r, t);
}
function nm(e10, r, t) {
  let n = {};
  return e10.modelOrType && !e10.isRawAction() && (n.$composites = true, n.$scalars = true), r && im(n, r, e10), om(n, t, e10), n;
}
function im(e10, r, t) {
  for (let [n, i] of Object.entries(r)) {
    if (Se(i)) continue;
    let o = t.nestSelection(n);
    if (eo(i, o), i === false || i === void 0) {
      e10[n] = false;
      continue;
    }
    let s = t.findField(n);
    if (s && s.kind !== "object" && t.throwValidationError({ kind: "IncludeOnScalar", selectionPath: t.getSelectionPath().concat(n), outputType: t.getOutputTypeDescription() }), s) {
      e10[n] = bt(i === true ? {} : i, o);
      continue;
    }
    if (i === true) {
      e10[n] = true;
      continue;
    }
    e10[n] = bt(i, o);
  }
}
function om(e10, r, t) {
  let n = t.getComputedFields(), i = { ...t.getGlobalOmit(), ...r }, o = Ta(i, n);
  for (let [s, a] of Object.entries(o)) {
    if (Se(a)) continue;
    eo(a, t.nestSelection(s));
    let l = t.findField(s);
    (n == null ? void 0 : n[s]) && !l || (e10[s] = !a);
  }
}
function sm(e10, r) {
  let t = {}, n = r.getComputedFields(), i = Pa(e10, n);
  for (let [o, s] of Object.entries(i)) {
    if (Se(s)) continue;
    let a = r.nestSelection(o);
    eo(s, a);
    let l = r.findField(o);
    if (!((n == null ? void 0 : n[o]) && !l)) {
      if (s === false || s === void 0 || Se(s)) {
        t[o] = false;
        continue;
      }
      if (s === true) {
        (l == null ? void 0 : l.kind) === "object" ? t[o] = bt({}, a) : t[o] = true;
        continue;
      }
      t[o] = bt(s, a);
    }
  }
  return t;
}
function Ia(e10, r) {
  if (e10 === null) return null;
  if (typeof e10 == "string" || typeof e10 == "number" || typeof e10 == "boolean") return e10;
  if (typeof e10 == "bigint") return { $type: "BigInt", value: String(e10) };
  if (xr(e10)) {
    if (dn(e10)) return { $type: "DateTime", value: e10.toISOString() };
    r.throwValidationError({ kind: "InvalidArgumentValue", selectionPath: r.getSelectionPath(), argumentPath: r.getArgumentPath(), argument: { name: r.getArgumentName(), typeNames: ["Date"] }, underlyingError: "Provided Date object is invalid" });
  }
  if (Sa(e10)) return { $type: "Param", value: e10.name };
  if (Or(e10)) return { $type: "FieldRef", value: { _ref: e10.name, _container: e10.modelName } };
  if (Array.isArray(e10)) return am(e10, r);
  if (ArrayBuffer.isView(e10)) {
    let { buffer: t, byteOffset: n, byteLength: i } = e10;
    return { $type: "Bytes", value: Buffer.from(t, n, i).toString("base64") };
  }
  if (lm(e10)) return e10.values;
  if (Tr(e10)) return { $type: "Decimal", value: e10.toFixed() };
  if (e10 instanceof Me) {
    if (e10 !== Dn.instances[e10._getName()]) throw new Error("Invalid ObjectEnumValue");
    return { $type: "Enum", value: e10._getName() };
  }
  if (um(e10)) return e10.toJSON();
  if (typeof e10 == "object") return Da(e10, r);
  r.throwValidationError({ kind: "InvalidArgumentValue", selectionPath: r.getSelectionPath(), argumentPath: r.getArgumentPath(), argument: { name: r.getArgumentName(), typeNames: [] }, underlyingError: `We could not serialize ${Object.prototype.toString.call(e10)} value. Serialize the object to JSON or implement a ".toJSON()" method on it` });
}
function Da(e10, r) {
  if (e10.$type) return { $type: "Raw", value: e10 };
  let t = {};
  for (let n in e10) {
    let i = e10[n], o = r.nestArgument(n);
    Se(i) || (i !== void 0 ? t[n] = Ia(i, o) : r.isPreviewFeatureOn("strictUndefinedChecks") && r.throwValidationError({ kind: "InvalidArgumentValue", argumentPath: o.getArgumentPath(), selectionPath: r.getSelectionPath(), argument: { name: r.getArgumentName(), typeNames: [] }, underlyingError: Ca }));
  }
  return t;
}
function am(e10, r) {
  let t = [];
  for (let n = 0; n < e10.length; n++) {
    let i = r.nestArgument(String(n)), o = e10[n];
    if (o === void 0 || Se(o)) {
      let s = o === void 0 ? "undefined" : "Prisma.skip";
      r.throwValidationError({ kind: "InvalidArgumentValue", selectionPath: i.getSelectionPath(), argumentPath: i.getArgumentPath(), argument: { name: `${r.getArgumentName()}[${n}]`, typeNames: [] }, underlyingError: `Can not use \`${s}\` value within array. Use \`null\` or filter out \`${s}\` values` });
    }
    t.push(Ia(o, i));
  }
  return t;
}
function lm(e10) {
  return typeof e10 == "object" && e10 !== null && e10.__prismaRawParameters__ === true;
}
function um(e10) {
  return typeof e10 == "object" && e10 !== null && typeof e10.toJSON == "function";
}
function eo(e10, r) {
  e10 === void 0 && r.isPreviewFeatureOn("strictUndefinedChecks") && r.throwValidationError({ kind: "InvalidSelectionValue", selectionPath: r.getSelectionPath(), underlyingError: Ca });
}
var Xi = class e8 {
  constructor(r) {
    __publicField(this, "modelOrType");
    var _a3;
    this.params = r;
    this.params.modelName && (this.modelOrType = (_a3 = this.params.runtimeDataModel.models[this.params.modelName]) != null ? _a3 : this.params.runtimeDataModel.types[this.params.modelName]);
  }
  throwValidationError(r) {
    var _a3;
    _n({ errors: [r], originalMethod: this.params.originalMethod, args: (_a3 = this.params.rootArgs) != null ? _a3 : {}, callsite: this.params.callsite, errorFormat: this.params.errorFormat, clientVersion: this.params.clientVersion, globalOmit: this.params.globalOmit });
  }
  getSelectionPath() {
    return this.params.selectionPath;
  }
  getArgumentPath() {
    return this.params.argumentPath;
  }
  getArgumentName() {
    return this.params.argumentPath[this.params.argumentPath.length - 1];
  }
  getOutputTypeDescription() {
    if (!(!this.params.modelName || !this.modelOrType)) return { name: this.params.modelName, fields: this.modelOrType.fields.map((r) => ({ name: r.name, typeName: "boolean", isRelation: r.kind === "object" })) };
  }
  isRawAction() {
    return ["executeRaw", "queryRaw", "runCommandRaw", "findRaw", "aggregateRaw"].includes(this.params.action);
  }
  isPreviewFeatureOn(r) {
    return this.params.previewFeatures.includes(r);
  }
  getComputedFields() {
    if (this.params.modelName) return this.params.extensions.getAllComputedFields(this.params.modelName);
  }
  findField(r) {
    var _a3;
    return (_a3 = this.modelOrType) == null ? void 0 : _a3.fields.find((t) => t.name === r);
  }
  nestSelection(r) {
    let t = this.findField(r), n = (t == null ? void 0 : t.kind) === "object" ? t.type : void 0;
    return new e8({ ...this.params, modelName: n, selectionPath: this.params.selectionPath.concat(r) });
  }
  getGlobalOmit() {
    var _a3, _b2;
    return this.params.modelName && this.shouldApplyGlobalOmit() ? (_b2 = (_a3 = this.params.globalOmit) == null ? void 0 : _a3[We(this.params.modelName)]) != null ? _b2 : {} : {};
  }
  shouldApplyGlobalOmit() {
    switch (this.params.action) {
      case "findFirst":
      case "findFirstOrThrow":
      case "findUniqueOrThrow":
      case "findMany":
      case "upsert":
      case "findUnique":
      case "createManyAndReturn":
      case "create":
      case "update":
      case "updateManyAndReturn":
      case "delete":
        return true;
      case "executeRaw":
      case "aggregateRaw":
      case "runCommandRaw":
      case "findRaw":
      case "createMany":
      case "deleteMany":
      case "groupBy":
      case "updateMany":
      case "count":
      case "aggregate":
      case "queryRaw":
        return false;
      default:
        ar(this.params.action, "Unknown action");
    }
  }
  nestArgument(r) {
    return new e8({ ...this.params, argumentPath: this.params.argumentPath.concat(r) });
  }
};
function Oa(e10) {
  if (!e10._hasPreviewFlag("metrics")) throw new Z("`metrics` preview feature must be enabled in order to access metrics API", { clientVersion: e10._clientVersion });
}
var Nr = class {
  constructor(r) {
    __publicField(this, "_client");
    this._client = r;
  }
  prometheus(r) {
    return Oa(this._client), this._client._engine.metrics({ format: "prometheus", ...r });
  }
  json(r) {
    return Oa(this._client), this._client._engine.metrics({ format: "json", ...r });
  }
};
function ka(e10, r) {
  let t = at(() => cm(r));
  Object.defineProperty(e10, "dmmf", { get: () => t.get() });
}
function cm(e10) {
  return { datamodel: { models: ro(e10.models), enums: ro(e10.enums), types: ro(e10.types) } };
}
function ro(e10) {
  return Object.entries(e10).map(([r, t]) => ({ name: r, ...t }));
}
var to = /* @__PURE__ */ new WeakMap(), $n = "$$PrismaTypedSql", Et = class {
  constructor(r, t) {
    to.set(this, { sql: r, values: t }), Object.defineProperty(this, $n, { value: $n });
  }
  get sql() {
    return to.get(this).sql;
  }
  get values() {
    return to.get(this).values;
  }
};
function _a(e10) {
  return (...r) => new Et(e10, r);
}
function qn(e10) {
  return e10 != null && e10[$n] === $n;
}
var fu = A(Ti());
var gu = require$$9, hu = require$$10, yu = A(require$$2$1), ri = A(require$$3);
var oe = class e9 {
  constructor(r, t) {
    if (r.length - 1 !== t.length) throw r.length === 0 ? new TypeError("Expected at least 1 string") : new TypeError(`Expected ${r.length} strings to have ${r.length - 1} values`);
    let n = t.reduce((s, a) => s + (a instanceof e9 ? a.values.length : 1), 0);
    this.values = new Array(n), this.strings = new Array(n + 1), this.strings[0] = r[0];
    let i = 0, o = 0;
    for (; i < t.length; ) {
      let s = t[i++], a = r[i];
      if (s instanceof e9) {
        this.strings[o] += s.strings[0];
        let l = 0;
        for (; l < s.values.length; ) this.values[o++] = s.values[l++], this.strings[o] = s.strings[l];
        this.strings[o] += a;
      } else this.values[o++] = s, this.strings[o] = a;
    }
  }
  get sql() {
    let r = this.strings.length, t = 1, n = this.strings[0];
    for (; t < r; ) n += `?${this.strings[t++]}`;
    return n;
  }
  get statement() {
    let r = this.strings.length, t = 1, n = this.strings[0];
    for (; t < r; ) n += `:${t}${this.strings[t++]}`;
    return n;
  }
  get text() {
    let r = this.strings.length, t = 1, n = this.strings[0];
    for (; t < r; ) n += `$${t}${this.strings[t++]}`;
    return n;
  }
  inspect() {
    return { sql: this.sql, statement: this.statement, text: this.text, values: this.values };
  }
};
function Na(e10, r = ",", t = "", n = "") {
  if (e10.length === 0) throw new TypeError("Expected `join([])` to be called with an array of multiple elements, but got an empty array");
  return new oe([t, ...Array(e10.length - 1).fill(r), n], e10);
}
function no(e10) {
  return new oe([e10], []);
}
var La = no("");
function io(e10, ...r) {
  return new oe(e10, r);
}
function wt(e10) {
  return { getKeys() {
    return Object.keys(e10);
  }, getPropertyValue(r) {
    return e10[r];
  } };
}
function re(e10, r) {
  return { getKeys() {
    return [e10];
  }, getPropertyValue() {
    return r();
  } };
}
function lr(e10) {
  let r = new we();
  return { getKeys() {
    return e10.getKeys();
  }, getPropertyValue(t) {
    return r.getOrCreate(t, () => e10.getPropertyValue(t));
  }, getPropertyDescriptor(t) {
    var _a3;
    return (_a3 = e10.getPropertyDescriptor) == null ? void 0 : _a3.call(e10, t);
  } };
}
var Vn = { enumerable: true, configurable: true, writable: true };
function jn(e10) {
  let r = new Set(e10);
  return { getPrototypeOf: () => Object.prototype, getOwnPropertyDescriptor: () => Vn, has: (t, n) => r.has(n), set: (t, n, i) => r.add(n) && Reflect.set(t, n, i), ownKeys: () => [...r] };
}
var Fa = Symbol.for("nodejs.util.inspect.custom");
function he(e10, r) {
  let t = pm(r), n = /* @__PURE__ */ new Set(), i = new Proxy(e10, { get(o, s) {
    if (n.has(s)) return o[s];
    let a = t.get(s);
    return a ? a.getPropertyValue(s) : o[s];
  }, has(o, s) {
    var _a3, _b2;
    if (n.has(s)) return true;
    let a = t.get(s);
    return a ? (_b2 = (_a3 = a.has) == null ? void 0 : _a3.call(a, s)) != null ? _b2 : true : Reflect.has(o, s);
  }, ownKeys(o) {
    let s = Ma(Reflect.ownKeys(o), t), a = Ma(Array.from(t.keys()), t);
    return [.../* @__PURE__ */ new Set([...s, ...a, ...n])];
  }, set(o, s, a) {
    var _a3, _b2, _c3;
    return ((_c3 = (_b2 = (_a3 = t.get(s)) == null ? void 0 : _a3.getPropertyDescriptor) == null ? void 0 : _b2.call(_a3, s)) == null ? void 0 : _c3.writable) === false ? false : (n.add(s), Reflect.set(o, s, a));
  }, getOwnPropertyDescriptor(o, s) {
    let a = Reflect.getOwnPropertyDescriptor(o, s);
    if (a && !a.configurable) return a;
    let l = t.get(s);
    return l ? l.getPropertyDescriptor ? { ...Vn, ...l == null ? void 0 : l.getPropertyDescriptor(s) } : Vn : a;
  }, defineProperty(o, s, a) {
    return n.add(s), Reflect.defineProperty(o, s, a);
  }, getPrototypeOf: () => Object.prototype });
  return i[Fa] = function() {
    let o = { ...this };
    return delete o[Fa], o;
  }, i;
}
function pm(e10) {
  let r = /* @__PURE__ */ new Map();
  for (let t of e10) {
    let n = t.getKeys();
    for (let i of n) r.set(i, t);
  }
  return r;
}
function Ma(e10, r) {
  return e10.filter((t) => {
    var _a3, _b2, _c3;
    return (_c3 = (_b2 = (_a3 = r.get(t)) == null ? void 0 : _a3.has) == null ? void 0 : _b2.call(_a3, t)) != null ? _c3 : true;
  });
}
function Lr(e10) {
  return { getKeys() {
    return e10;
  }, has() {
    return false;
  }, getPropertyValue() {
  } };
}
function Fr(e10, r) {
  return { batch: e10, transaction: (r == null ? void 0 : r.kind) === "batch" ? { isolationLevel: r.options.isolationLevel } : void 0 };
}
function $a(e10) {
  if (e10 === void 0) return "";
  let r = kr(e10);
  return new Rr(0, { colors: An }).write(r).toString();
}
var dm = "P2037";
function Mr({ error: e10, user_facing_error: r }, t, n) {
  return r.error_code ? new z(mm(r, n), { code: r.error_code, clientVersion: t, meta: r.meta, batchRequestIdx: r.batch_request_idx }) : new V(e10, { clientVersion: t, batchRequestIdx: r.batch_request_idx });
}
function mm(e10, r) {
  let t = e10.message;
  return (r === "postgresql" || r === "postgres" || r === "mysql") && e10.error_code === dm && (t += `
Prisma Accelerate has built-in connection pooling to prevent such errors: https://pris.ly/client/error-accelerate`), t;
}
var xt = "<unknown>";
function qa(e10) {
  var r = e10.split(`
`);
  return r.reduce(function(t, n) {
    var i = hm(n) || bm(n) || xm(n) || Sm(n) || Pm(n);
    return i && t.push(i), t;
  }, []);
}
var fm = /^\s*at (.*?) ?\(((?:file|https?|blob|chrome-extension|native|eval|webpack|rsc|<anonymous>|\/|[a-z]:\\|\\\\).*?)(?::(\d+))?(?::(\d+))?\)?\s*$/i, gm = /\((\S*)(?::(\d+))(?::(\d+))\)/;
function hm(e10) {
  var r = fm.exec(e10);
  if (!r) return null;
  var t = r[2] && r[2].indexOf("native") === 0, n = r[2] && r[2].indexOf("eval") === 0, i = gm.exec(r[2]);
  return n && i != null && (r[2] = i[1], r[3] = i[2], r[4] = i[3]), { file: t ? null : r[2], methodName: r[1] || xt, arguments: t ? [r[2]] : [], lineNumber: r[3] ? +r[3] : null, column: r[4] ? +r[4] : null };
}
var ym = /^\s*at (?:((?:\[object object\])?.+) )?\(?((?:file|ms-appx|https?|webpack|rsc|blob):.*?):(\d+)(?::(\d+))?\)?\s*$/i;
function bm(e10) {
  var r = ym.exec(e10);
  return r ? { file: r[2], methodName: r[1] || xt, arguments: [], lineNumber: +r[3], column: r[4] ? +r[4] : null } : null;
}
var Em = /^\s*(.*?)(?:\((.*?)\))?(?:^|@)((?:file|https?|blob|chrome|webpack|rsc|resource|\[native).*?|[^@]*bundle)(?::(\d+))?(?::(\d+))?\s*$/i, wm = /(\S+) line (\d+)(?: > eval line \d+)* > eval/i;
function xm(e10) {
  var r = Em.exec(e10);
  if (!r) return null;
  var t = r[3] && r[3].indexOf(" > eval") > -1, n = wm.exec(r[3]);
  return t && n != null && (r[3] = n[1], r[4] = n[2], r[5] = null), { file: r[3], methodName: r[1] || xt, arguments: r[2] ? r[2].split(",") : [], lineNumber: r[4] ? +r[4] : null, column: r[5] ? +r[5] : null };
}
var vm = /^\s*(?:([^@]*)(?:\((.*?)\))?@)?(\S.*?):(\d+)(?::(\d+))?\s*$/i;
function Pm(e10) {
  var r = vm.exec(e10);
  return r ? { file: r[3], methodName: r[1] || xt, arguments: [], lineNumber: +r[4], column: r[5] ? +r[5] : null } : null;
}
var Tm = /^\s*at (?:((?:\[object object\])?[^\\/]+(?: \[as \S+\])?) )?\(?(.*?):(\d+)(?::(\d+))?\)?\s*$/i;
function Sm(e10) {
  var r = Tm.exec(e10);
  return r ? { file: r[2], methodName: r[1] || xt, arguments: [], lineNumber: +r[3], column: r[4] ? +r[4] : null } : null;
}
var oo = class {
  getLocation() {
    return null;
  }
}, so = class {
  constructor() {
    __publicField(this, "_error");
    this._error = new Error();
  }
  getLocation() {
    let r = this._error.stack;
    if (!r) return null;
    let n = qa(r).find((i) => {
      if (!i.file) return false;
      let o = Li(i.file);
      return o !== "<anonymous>" && !o.includes("@prisma") && !o.includes("/packages/client/src/runtime/") && !o.endsWith("/runtime/binary.js") && !o.endsWith("/runtime/library.js") && !o.endsWith("/runtime/edge.js") && !o.endsWith("/runtime/edge-esm.js") && !o.startsWith("internal/") && !i.methodName.includes("new ") && !i.methodName.includes("getCallSite") && !i.methodName.includes("Proxy.") && i.methodName.split(".").length < 4;
    });
    return !n || !n.file ? null : { fileName: n.file, lineNumber: n.lineNumber, columnNumber: n.column };
  }
};
function Ze(e10) {
  return e10 === "minimal" ? typeof $EnabledCallSite == "function" && e10 !== "minimal" ? new $EnabledCallSite() : new oo() : new so();
}
var Va = { _avg: true, _count: true, _sum: true, _min: true, _max: true };
function $r(e10 = {}) {
  let r = Am(e10);
  return Object.entries(r).reduce((n, [i, o]) => (Va[i] !== void 0 ? n.select[i] = { select: o } : n[i] = o, n), { select: {} });
}
function Am(e10 = {}) {
  return typeof e10._count == "boolean" ? { ...e10, _count: { _all: e10._count } } : e10;
}
function Bn(e10 = {}) {
  return (r) => (typeof e10._count == "boolean" && (r._count = r._count._all), r);
}
function ja(e10, r) {
  let t = Bn(e10);
  return r({ action: "aggregate", unpacker: t, argsMapper: $r })(e10);
}
function Cm(e10 = {}) {
  let { select: r, ...t } = e10;
  return typeof r == "object" ? $r({ ...t, _count: r }) : $r({ ...t, _count: { _all: true } });
}
function Im(e10 = {}) {
  return typeof e10.select == "object" ? (r) => Bn(e10)(r)._count : (r) => Bn(e10)(r)._count._all;
}
function Ba(e10, r) {
  return r({ action: "count", unpacker: Im(e10), argsMapper: Cm })(e10);
}
function Dm(e10 = {}) {
  let r = $r(e10);
  if (Array.isArray(r.by)) for (let t of r.by) typeof t == "string" && (r.select[t] = true);
  else typeof r.by == "string" && (r.select[r.by] = true);
  return r;
}
function Om(e10 = {}) {
  return (r) => (typeof (e10 == null ? void 0 : e10._count) == "boolean" && r.forEach((t) => {
    t._count = t._count._all;
  }), r);
}
function Ua(e10, r) {
  return r({ action: "groupBy", unpacker: Om(e10), argsMapper: Dm })(e10);
}
function Ga(e10, r, t) {
  if (r === "aggregate") return (n) => ja(n, t);
  if (r === "count") return (n) => Ba(n, t);
  if (r === "groupBy") return (n) => Ua(n, t);
}
function Qa(e10, r) {
  let t = r.fields.filter((i) => !i.relationName), n = Ms(t, "name");
  return new Proxy({}, { get(i, o) {
    if (o in i || typeof o == "symbol") return i[o];
    let s = n[o];
    if (s) return new dt(e10, o, s.type, s.isList, s.kind === "enum");
  }, ...jn(Object.keys(n)) });
}
var Wa = (e10) => Array.isArray(e10) ? e10 : e10.split("."), ao = (e10, r) => Wa(r).reduce((t, n) => t && t[n], e10), Ja = (e10, r, t) => Wa(r).reduceRight((n, i, o, s) => Object.assign({}, ao(e10, s.slice(0, o)), { [i]: n }), t);
function km(e10, r) {
  return e10 === void 0 || r === void 0 ? [] : [...r, "select", e10];
}
function _m(e10, r, t) {
  return r === void 0 ? e10 != null ? e10 : {} : Ja(r, t, e10 || true);
}
function lo(e10, r, t, n, i, o) {
  let a = e10._runtimeDataModel.models[r].fields.reduce((l, u) => ({ ...l, [u.name]: u }), {});
  return (l) => {
    let u = Ze(e10._errorFormat), c = km(n, i), p = _m(l, o, c), d = t({ dataPath: c, callsite: u })(p), f = Nm(e10, r);
    return new Proxy(d, { get(h, g) {
      if (!f.includes(g)) return h[g];
      let T = [a[g].type, t, g], S = [c, p];
      return lo(e10, ...T, ...S);
    }, ...jn([...f, ...Object.getOwnPropertyNames(d)]) });
  };
}
function Nm(e10, r) {
  return e10._runtimeDataModel.models[r].fields.filter((t) => t.kind === "object").map((t) => t.name);
}
var Lm = ["findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "create", "update", "upsert", "delete"], Fm = ["aggregate", "count", "groupBy"];
function uo(e10, r) {
  var _a3;
  let t = (_a3 = e10._extensions.getAllModelExtensions(r)) != null ? _a3 : {}, n = [Mm(e10, r), qm(e10, r), wt(t), re("name", () => r), re("$name", () => r), re("$parent", () => e10._appliedParent)];
  return he({}, n);
}
function Mm(e10, r) {
  let t = Te(r), n = Object.keys(Sr).concat("count");
  return { getKeys() {
    return n;
  }, getPropertyValue(i) {
    let o = i, s = (a) => (l) => {
      let u = Ze(e10._errorFormat);
      return e10._createPrismaPromise((c) => {
        let p = { args: l, dataPath: [], action: o, model: r, clientMethod: `${t}.${i}`, jsModelName: t, transaction: c, callsite: u };
        return e10._request({ ...p, ...a });
      }, { action: o, args: l, model: r });
    };
    return Lm.includes(o) ? lo(e10, r, s) : $m(i) ? Ga(e10, i, s) : s({});
  } };
}
function $m(e10) {
  return Fm.includes(e10);
}
function qm(e10, r) {
  return lr(re("fields", () => {
    let t = e10._runtimeDataModel.models[r];
    return Qa(r, t);
  }));
}
function Ka(e10) {
  return e10.replace(/^./, (r) => r.toUpperCase());
}
var co = Symbol();
function vt(e10) {
  let r = [Vm(e10), jm(e10), re(co, () => e10), re("$parent", () => e10._appliedParent)], t = e10._extensions.getAllClientExtensions();
  return t && r.push(wt(t)), he(e10, r);
}
function Vm(e10) {
  let r = Object.getPrototypeOf(e10._originalClient), t = [...new Set(Object.getOwnPropertyNames(r))];
  return { getKeys() {
    return t;
  }, getPropertyValue(n) {
    return e10[n];
  } };
}
function jm(e10) {
  let r = Object.keys(e10._runtimeDataModel.models), t = r.map(Te), n = [...new Set(r.concat(t))];
  return lr({ getKeys() {
    return n;
  }, getPropertyValue(i) {
    let o = Ka(i);
    if (e10._runtimeDataModel.models[o] !== void 0) return uo(e10, o);
    if (e10._runtimeDataModel.models[i] !== void 0) return uo(e10, i);
  }, getPropertyDescriptor(i) {
    if (!t.includes(i)) return { enumerable: false };
  } });
}
function Ha(e10) {
  return e10[co] ? e10[co] : e10;
}
function Ya(e10) {
  var _a3;
  if (typeof e10 == "function") return e10(this);
  if ((_a3 = e10.client) == null ? void 0 : _a3.__AccelerateEngine) {
    let t = e10.client.__AccelerateEngine;
    this._originalClient._engine = new t(this._originalClient._accelerateEngineConfig);
  }
  let r = Object.create(this._originalClient, { _extensions: { value: this._extensions.append(e10) }, _appliedParent: { value: this, configurable: true }, $on: { value: void 0 } });
  return vt(r);
}
function za({ result: e10, modelName: r, select: t, omit: n, extensions: i }) {
  let o = i.getAllComputedFields(r);
  if (!o) return e10;
  let s = [], a = [];
  for (let l of Object.values(o)) {
    if (n) {
      if (n[l.name]) continue;
      let u = l.needs.filter((c) => n[c]);
      u.length > 0 && a.push(Lr(u));
    } else if (t) {
      if (!t[l.name]) continue;
      let u = l.needs.filter((c) => !t[c]);
      u.length > 0 && a.push(Lr(u));
    }
    Bm(e10, l.needs) && s.push(Um(l, he(e10, s)));
  }
  return s.length > 0 || a.length > 0 ? he(e10, [...s, ...a]) : e10;
}
function Bm(e10, r) {
  return r.every((t) => Vi(e10, t));
}
function Um(e10, r) {
  return lr(re(e10.name, () => e10.compute(r)));
}
function Un({ visitor: e10, result: r, args: t, runtimeDataModel: n, modelName: i }) {
  var _a3;
  if (Array.isArray(r)) {
    for (let s = 0; s < r.length; s++) r[s] = Un({ result: r[s], args: t, modelName: i, runtimeDataModel: n, visitor: e10 });
    return r;
  }
  let o = (_a3 = e10(r, i, t)) != null ? _a3 : r;
  return t.include && Za({ includeOrSelect: t.include, result: o, parentModelName: i, runtimeDataModel: n, visitor: e10 }), t.select && Za({ includeOrSelect: t.select, result: o, parentModelName: i, runtimeDataModel: n, visitor: e10 }), o;
}
function Za({ includeOrSelect: e10, result: r, parentModelName: t, runtimeDataModel: n, visitor: i }) {
  for (let [o, s] of Object.entries(e10)) {
    if (!s || r[o] == null || Se(s)) continue;
    let l = n.models[t].fields.find((c) => c.name === o);
    if (!l || l.kind !== "object" || !l.relationName) continue;
    let u = typeof s == "object" ? s : {};
    r[o] = Un({ visitor: i, result: r[o], args: u, modelName: l.type, runtimeDataModel: n });
  }
}
function Xa({ result: e10, modelName: r, args: t, extensions: n, runtimeDataModel: i, globalOmit: o }) {
  return n.isEmpty() || e10 == null || typeof e10 != "object" || !i.models[r] ? e10 : Un({ result: e10, args: t != null ? t : {}, modelName: r, runtimeDataModel: i, visitor: (a, l, u) => {
    let c = Te(l);
    return za({ result: a, modelName: c, select: u.select, omit: u.select ? void 0 : { ...o == null ? void 0 : o[c], ...u.omit }, extensions: n });
  } });
}
var Gm = ["$connect", "$disconnect", "$on", "$transaction", "$extends"], el = Gm;
function rl(e10) {
  if (e10 instanceof oe) return Qm(e10);
  if (qn(e10)) return Wm(e10);
  if (Array.isArray(e10)) {
    let t = [e10[0]];
    for (let n = 1; n < e10.length; n++) t[n] = Pt(e10[n]);
    return t;
  }
  let r = {};
  for (let t in e10) r[t] = Pt(e10[t]);
  return r;
}
function Qm(e10) {
  return new oe(e10.strings, e10.values);
}
function Wm(e10) {
  return new Et(e10.sql, e10.values);
}
function Pt(e10) {
  if (typeof e10 != "object" || e10 == null || e10 instanceof Me || Or(e10)) return e10;
  if (Tr(e10)) return new Fe(e10.toFixed());
  if (xr(e10)) return /* @__PURE__ */ new Date(+e10);
  if (ArrayBuffer.isView(e10)) return e10.slice(0);
  if (Array.isArray(e10)) {
    let r = e10.length, t;
    for (t = Array(r); r--; ) t[r] = Pt(e10[r]);
    return t;
  }
  if (typeof e10 == "object") {
    let r = {};
    for (let t in e10) t === "__proto__" ? Object.defineProperty(r, t, { value: Pt(e10[t]), configurable: true, enumerable: true, writable: true }) : r[t] = Pt(e10[t]);
    return r;
  }
  ar(e10, "Unknown value");
}
function nl(e10, r, t, n = 0) {
  return e10._createPrismaPromise((i) => {
    var _a3, _b2;
    let o = r.customDataProxyFetch;
    return "transaction" in r && i !== void 0 && (((_a3 = r.transaction) == null ? void 0 : _a3.kind) === "batch" && r.transaction.lock.then(), r.transaction = i), n === t.length ? e10._executeRequest(r) : t[n]({ model: r.model, operation: r.model ? r.action : r.clientMethod, args: rl((_b2 = r.args) != null ? _b2 : {}), __internalParams: r, query: (s, a = r) => {
      let l = a.customDataProxyFetch;
      return a.customDataProxyFetch = al(o, l), a.args = s, nl(e10, a, t, n + 1);
    } });
  });
}
function il(e10, r) {
  let { jsModelName: t, action: n, clientMethod: i } = r, o = t ? n : i;
  if (e10._extensions.isEmpty()) return e10._executeRequest(r);
  let s = e10._extensions.getAllQueryCallbacks(t != null ? t : "$none", o);
  return nl(e10, r, s);
}
function ol(e10) {
  return (r) => {
    let t = { requests: r }, n = r[0].extensions.getAllBatchQueryCallbacks();
    return n.length ? sl(t, n, 0, e10) : e10(t);
  };
}
function sl(e10, r, t, n) {
  if (t === r.length) return n(e10);
  let i = e10.customDataProxyFetch, o = e10.requests[0].transaction;
  return r[t]({ args: { queries: e10.requests.map((s) => ({ model: s.modelName, operation: s.action, args: s.args })), transaction: o ? { isolationLevel: o.kind === "batch" ? o.isolationLevel : void 0 } : void 0 }, __internalParams: e10, query(s, a = e10) {
    let l = a.customDataProxyFetch;
    return a.customDataProxyFetch = al(i, l), sl(a, r, t + 1, n);
  } });
}
var tl = (e10) => e10;
function al(e10 = tl, r = tl) {
  return (t) => e10(r(t));
}
var ll = N("prisma:client"), ul = { Vercel: "vercel", "Netlify CI": "netlify" };
function cl({ postinstall: e10, ciName: r, clientVersion: t }) {
  if (ll("checkPlatformCaching:postinstall", e10), ll("checkPlatformCaching:ciName", r), e10 === true && r && r in ul) {
    let n = `Prisma has detected that this project was built on ${r}, which caches dependencies. This leads to an outdated Prisma Client because Prisma's auto-generation isn't triggered. To fix this, make sure to run the \`prisma generate\` command during the build process.

Learn how: https://pris.ly/d/${ul[r]}-build`;
    throw console.error(n), new P(n, t);
  }
}
function pl(e10, r) {
  return e10 ? e10.datasources ? e10.datasources : e10.datasourceUrl ? { [r[0]]: { url: e10.datasourceUrl } } : {} : {};
}
var Jm = () => {
  var _a3, _b2;
  return ((_b2 = (_a3 = globalThis.process) == null ? void 0 : _a3.release) == null ? void 0 : _b2.name) === "node";
}, Km = () => {
  var _a3, _b2;
  return !!globalThis.Bun || !!((_b2 = (_a3 = globalThis.process) == null ? void 0 : _a3.versions) == null ? void 0 : _b2.bun);
}, Hm = () => !!globalThis.Deno, Ym = () => typeof globalThis.Netlify == "object", zm = () => typeof globalThis.EdgeRuntime == "object", Zm = () => {
  var _a3;
  return ((_a3 = globalThis.navigator) == null ? void 0 : _a3.userAgent) === "Cloudflare-Workers";
};
function Xm() {
  var _a3;
  return (_a3 = [[Ym, "netlify"], [zm, "edge-light"], [Zm, "workerd"], [Hm, "deno"], [Km, "bun"], [Jm, "node"]].flatMap((t) => t[0]() ? [t[1]] : []).at(0)) != null ? _a3 : "";
}
var ef = { node: "Node.js", workerd: "Cloudflare Workers", deno: "Deno and Deno Deploy", netlify: "Netlify Edge Functions", "edge-light": "Edge Runtime (Vercel Edge Functions, Vercel Edge Middleware, Next.js (Pages Router) Edge API Routes, Next.js (App Router) Edge Route Handlers or Next.js Middleware)" };
function Gn() {
  let e10 = Xm();
  return { id: e10, prettyName: ef[e10] || e10, isEdge: ["workerd", "deno", "netlify", "edge-light"].includes(e10) };
}
var hl = A(require$$2$1), Tt = A(require$$3);
function Qn(e10) {
  let { runtimeBinaryTarget: r } = e10;
  return `Add "${r}" to \`binaryTargets\` in the "schema.prisma" file and run \`prisma generate\` after saving it:

${rf(e10)}`;
}
function rf(e10) {
  let { generator: r, generatorBinaryTargets: t, runtimeBinaryTarget: n } = e10, i = { fromEnvVar: null, value: n }, o = [...t, i];
  return ki({ ...r, binaryTargets: o });
}
function Xe(e10) {
  let { runtimeBinaryTarget: r } = e10;
  return `Prisma Client could not locate the Query Engine for runtime "${r}".`;
}
function er(e10) {
  let { searchedLocations: r } = e10;
  return `The following locations have been searched:
${[...new Set(r)].map((i) => `  ${i}`).join(`
`)}`;
}
function dl(e10) {
  let { runtimeBinaryTarget: r } = e10;
  return `${Xe(e10)}

This happened because \`binaryTargets\` have been pinned, but the actual deployment also required "${r}".
${Qn(e10)}

${er(e10)}`;
}
function Wn(e10) {
  return `We would appreciate if you could take the time to share some information with us.
Please help us by answering a few questions: https://pris.ly/${e10}`;
}
function Jn(e10) {
  let { errorStack: r } = e10;
  return (r == null ? void 0 : r.match(/\/\.next|\/next@|\/next\//)) ? `

We detected that you are using Next.js, learn how to fix this: https://pris.ly/d/engine-not-found-nextjs.` : "";
}
function ml(e10) {
  let { queryEngineName: r } = e10;
  return `${Xe(e10)}${Jn(e10)}

This is likely caused by a bundler that has not copied "${r}" next to the resulting bundle.
Ensure that "${r}" has been copied next to the bundle or in "${e10.expectedLocation}".

${Wn("engine-not-found-bundler-investigation")}

${er(e10)}`;
}
function fl(e10) {
  var _a3;
  let { runtimeBinaryTarget: r, generatorBinaryTargets: t } = e10, n = t.find((i) => i.native);
  return `${Xe(e10)}

This happened because Prisma Client was generated for "${(_a3 = n == null ? void 0 : n.value) != null ? _a3 : "unknown"}", but the actual deployment required "${r}".
${Qn(e10)}

${er(e10)}`;
}
function gl(e10) {
  let { queryEngineName: r } = e10;
  return `${Xe(e10)}${Jn(e10)}

This is likely caused by tooling that has not copied "${r}" to the deployment folder.
Ensure that you ran \`prisma generate\` and that "${r}" has been copied to "${e10.expectedLocation}".

${Wn("engine-not-found-tooling-investigation")}

${er(e10)}`;
}
var tf = N("prisma:client:engines:resolveEnginePath"), nf = () => new RegExp("runtime[\\\\/]library\\.m?js$");
async function yl(e10, r) {
  var _a3, _b2, _c3;
  let t = (_a3 = { binary: process.env.PRISMA_QUERY_ENGINE_BINARY, library: process.env.PRISMA_QUERY_ENGINE_LIBRARY }[e10]) != null ? _a3 : r.prismaPath;
  if (t !== void 0) return t;
  let { enginePath: n, searchedLocations: i } = await of(e10, r);
  if (tf("enginePath", n), n !== void 0) return r.prismaPath = n;
  let o = await ir(), s = (_c3 = (_b2 = r.generator) == null ? void 0 : _b2.binaryTargets) != null ? _c3 : [], a = s.some((d) => d.native), l = !s.some((d) => d.value === o), u = __filename.match(nf()) === null, c = { searchedLocations: i, generatorBinaryTargets: s, generator: r.generator, runtimeBinaryTarget: o, queryEngineName: bl(e10, o), expectedLocation: Tt.default.relative(process.cwd(), r.dirname), errorStack: new Error().stack }, p;
  throw a && l ? p = fl(c) : l ? p = dl(c) : u ? p = ml(c) : p = gl(c), new P(p, r.clientVersion);
}
async function of(e10, r) {
  var _a3, _b2, _c3;
  let t = await ir(), n = [], i = [r.dirname, Tt.default.resolve(__dirname, ".."), (_c3 = (_b2 = (_a3 = r.generator) == null ? void 0 : _a3.output) == null ? void 0 : _b2.value) != null ? _c3 : __dirname, Tt.default.resolve(__dirname, "../../../.prisma/client"), "/tmp/prisma-engines", r.cwd];
  __filename.includes("resolveEnginePath") && i.push(fs());
  for (let o of i) {
    let s = bl(e10, t), a = Tt.default.join(o, s);
    if (n.push(o), hl.default.existsSync(a)) return { enginePath: a, searchedLocations: n };
  }
  return { enginePath: void 0, searchedLocations: n };
}
function bl(e10, r) {
  return Ut(r) ;
}
var po = A(Ni());
function El(e10) {
  return e10 ? e10.replace(/".*"/g, '"X"').replace(/[\s:\[]([+-]?([0-9]*[.])?[0-9]+)/g, (r) => `${r[0]}5`) : "";
}
function wl(e10) {
  return e10.split(`
`).map((r) => r.replace(/^\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d\.\d+([+-][0-2]\d:[0-5]\d|Z)\s*/, "").replace(/\+\d+\s*ms$/, "")).join(`
`);
}
var xl = A(Ls());
function vl({ title: e10, user: r = "prisma", repo: t = "prisma", template: n = "bug_report.yml", body: i }) {
  return (0, xl.default)({ user: r, repo: t, template: n, title: e10, body: i });
}
function Pl({ version: e10, binaryTarget: r, title: t, description: n, engineVersion: i, database: o, query: s }) {
  var _a3, _b2;
  let a = Uo(6e3 - ((_a3 = s == null ? void 0 : s.length) != null ? _a3 : 0)), l = wl((0, po.default)(a)), u = n ? `# Description
\`\`\`
${n}
\`\`\`` : "", c = (0, po.default)(`Hi Prisma Team! My Prisma Client just crashed. This is the report:
## Versions

| Name            | Version            |
|-----------------|--------------------|
| Node            | ${(_b2 = process.version) == null ? void 0 : _b2.padEnd(19)}| 
| OS              | ${r == null ? void 0 : r.padEnd(19)}|
| Prisma Client   | ${e10 == null ? void 0 : e10.padEnd(19)}|
| Query Engine    | ${i == null ? void 0 : i.padEnd(19)}|
| Database        | ${o == null ? void 0 : o.padEnd(19)}|

${u}

## Logs
\`\`\`
${l}
\`\`\`

## Client Snippet
\`\`\`ts
// PLEASE FILL YOUR CODE SNIPPET HERE
\`\`\`

## Schema
\`\`\`prisma
// PLEASE ADD YOUR SCHEMA HERE IF POSSIBLE
\`\`\`

## Prisma Engine Query
\`\`\`
${s ? El(s) : ""}
\`\`\`
`), p = vl({ title: t, body: c });
  return `${t}

This is a non-recoverable error which probably happens when the Prisma Query Engine has a panic.

${Y(p)}

If you want the Prisma team to look into it, please open the link above \u{1F64F}
To increase the chance of success, please post your schema and a snippet of
how you used Prisma Client in the issue. 
`;
}
function Tl(e10, r) {
  throw new Error(r);
}
function sf(e10) {
  return e10 !== null && typeof e10 == "object" && typeof e10.$type == "string";
}
function af(e10, r) {
  let t = {};
  for (let n of Object.keys(e10)) t[n] = r(e10[n], n);
  return t;
}
function qr(e10) {
  return e10 === null ? e10 : Array.isArray(e10) ? e10.map(qr) : typeof e10 == "object" ? sf(e10) ? lf(e10) : e10.constructor !== null && e10.constructor.name !== "Object" ? e10 : af(e10, qr) : e10;
}
function lf({ $type: e10, value: r }) {
  switch (e10) {
    case "BigInt":
      return BigInt(r);
    case "Bytes": {
      let { buffer: t, byteOffset: n, byteLength: i } = Buffer.from(r, "base64");
      return new Uint8Array(t, n, i);
    }
    case "DateTime":
      return new Date(r);
    case "Decimal":
      return new Le(r);
    case "Json":
      return JSON.parse(r);
    default:
      Tl(r, "Unknown tagged value");
  }
}
var Sl = "6.15.0";
function Vr({ inlineDatasources: e10, overrideDatasources: r, env: t, clientVersion: n }) {
  var _a3, _b2;
  let i, o = Object.keys(e10)[0], s = (_a3 = e10[o]) == null ? void 0 : _a3.url, a = (_b2 = r[o]) == null ? void 0 : _b2.url;
  if (o === void 0 ? i = void 0 : a ? i = a : (s == null ? void 0 : s.value) ? i = s.value : (s == null ? void 0 : s.fromEnvVar) && (i = t[s.fromEnvVar]), (s == null ? void 0 : s.fromEnvVar) !== void 0 && i === void 0) throw new P(`error: Environment variable not found: ${s.fromEnvVar}.`, n);
  if (i === void 0) throw new P("error: Missing URL environment variable, value, or override.", n);
  return i;
}
var Kn = class extends Error {
  constructor(r, t) {
    super(r);
    __publicField(this, "clientVersion");
    __publicField(this, "cause");
    this.clientVersion = t.clientVersion, this.cause = t.cause;
  }
  get [Symbol.toStringTag]() {
    return this.name;
  }
};
var se = class extends Kn {
  constructor(r, t) {
    var _a3;
    super(r, t);
    __publicField(this, "isRetryable");
    this.isRetryable = (_a3 = t.isRetryable) != null ? _a3 : true;
  }
};
function R(e10, r) {
  return { ...e10, isRetryable: r };
}
var ur = class extends se {
  constructor(r, t) {
    super(r, R(t, false));
    __publicField(this, "name", "InvalidDatasourceError");
    __publicField(this, "code", "P6001");
  }
};
x(ur, "InvalidDatasourceError");
function Rl(e10) {
  let r = { clientVersion: e10.clientVersion }, t = Object.keys(e10.inlineDatasources)[0], n = Vr({ inlineDatasources: e10.inlineDatasources, overrideDatasources: e10.overrideDatasources, clientVersion: e10.clientVersion, env: { ...e10.env, ...typeof process < "u" ? process.env : {} } }), i;
  try {
    i = new URL(n);
  } catch {
    throw new ur(`Error validating datasource \`${t}\`: the URL must start with the protocol \`prisma://\``, r);
  }
  let { protocol: o, searchParams: s } = i;
  if (o !== "prisma:" && o !== on) throw new ur(`Error validating datasource \`${t}\`: the URL must start with the protocol \`prisma://\` or \`prisma+postgres://\``, r);
  let a = s.get("api_key");
  if (a === null || a.length < 1) throw new ur(`Error validating datasource \`${t}\`: the URL must contain a valid API key`, r);
  let l = Ii(i) ? "http:" : "https:", u = new URL(i.href.replace(o, l));
  return { apiKey: a, url: u };
}
var Al = A(nn()), Hn = (_L = class {
  constructor({ apiKey: r, tracingHelper: t, logLevel: n, logQueries: i, engineHash: o }) {
    __privateAdd(this, _Hn_instances);
    __publicField(this, "apiKey");
    __publicField(this, "tracingHelper");
    __publicField(this, "logLevel");
    __publicField(this, "logQueries");
    __publicField(this, "engineHash");
    this.apiKey = r, this.tracingHelper = t, this.logLevel = n, this.logQueries = i, this.engineHash = o;
  }
  build({ traceparent: r, transactionId: t } = {}) {
    let n = { Accept: "application/json", Authorization: `Bearer ${this.apiKey}`, "Content-Type": "application/json", "Prisma-Engine-Hash": this.engineHash, "Prisma-Engine-Version": Al.enginesVersion };
    this.tracingHelper.isEnabled() && (n.traceparent = r != null ? r : this.tracingHelper.getTraceParent()), t && (n["X-Transaction-Id"] = t);
    let i = __privateMethod(this, _Hn_instances, e_fn).call(this);
    return i.length > 0 && (n["X-Capture-Telemetry"] = i.join(", ")), n;
  }
}, _Hn_instances = new WeakSet(), e_fn = function() {
  let r = [];
  return this.tracingHelper.isEnabled() && r.push("tracing"), this.logLevel && r.push(this.logLevel), this.logQueries && r.push("query"), r;
}, _L);
function cf(e10) {
  return e10[0] * 1e3 + e10[1] / 1e6;
}
function mo(e10) {
  return new Date(cf(e10));
}
var jr = class extends se {
  constructor(r) {
    super("This request must be retried", R(r, true));
    __publicField(this, "name", "ForcedRetryError");
    __publicField(this, "code", "P5001");
  }
};
x(jr, "ForcedRetryError");
var cr = class extends se {
  constructor(r, t) {
    super(r, R(t, false));
    __publicField(this, "name", "NotImplementedYetError");
    __publicField(this, "code", "P5004");
  }
};
x(cr, "NotImplementedYetError");
var $ = class extends se {
  constructor(r, t) {
    super(r, t);
    __publicField(this, "response");
    this.response = t.response;
    let n = this.response.headers.get("prisma-request-id");
    if (n) {
      let i = `(The request id was: ${n})`;
      this.message = this.message + " " + i;
    }
  }
};
var pr = class extends $ {
  constructor(r) {
    super("Schema needs to be uploaded", R(r, true));
    __publicField(this, "name", "SchemaMissingError");
    __publicField(this, "code", "P5005");
  }
};
x(pr, "SchemaMissingError");
var fo = "This request could not be understood by the server", St = class extends $ {
  constructor(r, t, n) {
    super(t || fo, R(r, false));
    __publicField(this, "name", "BadRequestError");
    __publicField(this, "code", "P5000");
    n && (this.code = n);
  }
};
x(St, "BadRequestError");
var Rt = class extends $ {
  constructor(r, t) {
    super("Engine not started: healthcheck timeout", R(r, true));
    __publicField(this, "name", "HealthcheckTimeoutError");
    __publicField(this, "code", "P5013");
    __publicField(this, "logs");
    this.logs = t;
  }
};
x(Rt, "HealthcheckTimeoutError");
var At = class extends $ {
  constructor(r, t, n) {
    super(t, R(r, true));
    __publicField(this, "name", "EngineStartupError");
    __publicField(this, "code", "P5014");
    __publicField(this, "logs");
    this.logs = n;
  }
};
x(At, "EngineStartupError");
var Ct = class extends $ {
  constructor(r) {
    super("Engine version is not supported", R(r, false));
    __publicField(this, "name", "EngineVersionNotSupportedError");
    __publicField(this, "code", "P5012");
  }
};
x(Ct, "EngineVersionNotSupportedError");
var go = "Request timed out", It = class extends $ {
  constructor(r, t = go) {
    super(t, R(r, false));
    __publicField(this, "name", "GatewayTimeoutError");
    __publicField(this, "code", "P5009");
  }
};
x(It, "GatewayTimeoutError");
var pf = "Interactive transaction error", Dt = class extends $ {
  constructor(r, t = pf) {
    super(t, R(r, false));
    __publicField(this, "name", "InteractiveTransactionError");
    __publicField(this, "code", "P5015");
  }
};
x(Dt, "InteractiveTransactionError");
var df = "Request parameters are invalid", Ot = class extends $ {
  constructor(r, t = df) {
    super(t, R(r, false));
    __publicField(this, "name", "InvalidRequestError");
    __publicField(this, "code", "P5011");
  }
};
x(Ot, "InvalidRequestError");
var ho = "Requested resource does not exist", kt = class extends $ {
  constructor(r, t = ho) {
    super(t, R(r, false));
    __publicField(this, "name", "NotFoundError");
    __publicField(this, "code", "P5003");
  }
};
x(kt, "NotFoundError");
var yo = "Unknown server error", Br = class extends $ {
  constructor(r, t, n) {
    super(t || yo, R(r, true));
    __publicField(this, "name", "ServerError");
    __publicField(this, "code", "P5006");
    __publicField(this, "logs");
    this.logs = n;
  }
};
x(Br, "ServerError");
var bo = "Unauthorized, check your connection string", _t = class extends $ {
  constructor(r, t = bo) {
    super(t, R(r, false));
    __publicField(this, "name", "UnauthorizedError");
    __publicField(this, "code", "P5007");
  }
};
x(_t, "UnauthorizedError");
var Eo = "Usage exceeded, retry again later", Nt = class extends $ {
  constructor(r, t = Eo) {
    super(t, R(r, true));
    __publicField(this, "name", "UsageExceededError");
    __publicField(this, "code", "P5008");
  }
};
x(Nt, "UsageExceededError");
async function mf(e10) {
  let r;
  try {
    r = await e10.text();
  } catch {
    return { type: "EmptyError" };
  }
  try {
    let t = JSON.parse(r);
    if (typeof t == "string") switch (t) {
      case "InternalDataProxyError":
        return { type: "DataProxyError", body: t };
      default:
        return { type: "UnknownTextError", body: t };
    }
    if (typeof t == "object" && t !== null) {
      if ("is_panic" in t && "message" in t && "error_code" in t) return { type: "QueryEngineError", body: t };
      if ("EngineNotStarted" in t || "InteractiveTransactionMisrouted" in t || "InvalidRequestError" in t) {
        let n = Object.values(t)[0].reason;
        return typeof n == "string" && !["SchemaMissing", "EngineVersionNotSupported"].includes(n) ? { type: "UnknownJsonError", body: t } : { type: "DataProxyError", body: t };
      }
    }
    return { type: "UnknownJsonError", body: t };
  } catch {
    return r === "" ? { type: "EmptyError" } : { type: "UnknownTextError", body: r };
  }
}
async function Lt(e10, r) {
  if (e10.ok) return;
  let t = { clientVersion: r, response: e10 }, n = await mf(e10);
  if (n.type === "QueryEngineError") throw new z(n.body.message, { code: n.body.error_code, clientVersion: r });
  if (n.type === "DataProxyError") {
    if (n.body === "InternalDataProxyError") throw new Br(t, "Internal Data Proxy error");
    if ("EngineNotStarted" in n.body) {
      if (n.body.EngineNotStarted.reason === "SchemaMissing") return new pr(t);
      if (n.body.EngineNotStarted.reason === "EngineVersionNotSupported") throw new Ct(t);
      if ("EngineStartupError" in n.body.EngineNotStarted.reason) {
        let { msg: i, logs: o } = n.body.EngineNotStarted.reason.EngineStartupError;
        throw new At(t, i, o);
      }
      if ("KnownEngineStartupError" in n.body.EngineNotStarted.reason) {
        let { msg: i, error_code: o } = n.body.EngineNotStarted.reason.KnownEngineStartupError;
        throw new P(i, r, o);
      }
      if ("HealthcheckTimeout" in n.body.EngineNotStarted.reason) {
        let { logs: i } = n.body.EngineNotStarted.reason.HealthcheckTimeout;
        throw new Rt(t, i);
      }
    }
    if ("InteractiveTransactionMisrouted" in n.body) {
      let i = { IDParseError: "Could not parse interactive transaction ID", NoQueryEngineFoundError: "Could not find Query Engine for the specified host and transaction ID", TransactionStartError: "Could not start interactive transaction" };
      throw new Dt(t, i[n.body.InteractiveTransactionMisrouted.reason]);
    }
    if ("InvalidRequestError" in n.body) throw new Ot(t, n.body.InvalidRequestError.reason);
  }
  if (e10.status === 401 || e10.status === 403) throw new _t(t, Ur(bo, n));
  if (e10.status === 404) return new kt(t, Ur(ho, n));
  if (e10.status === 429) throw new Nt(t, Ur(Eo, n));
  if (e10.status === 504) throw new It(t, Ur(go, n));
  if (e10.status >= 500) throw new Br(t, Ur(yo, n));
  if (e10.status >= 400) throw new St(t, Ur(fo, n));
}
function Ur(e10, r) {
  return r.type === "EmptyError" ? e10 : `${e10}: ${JSON.stringify(r)}`;
}
function Cl(e10) {
  let r = Math.pow(2, e10) * 50, t = Math.ceil(Math.random() * r) - Math.ceil(r / 2), n = r + t;
  return new Promise((i) => setTimeout(() => i(n), n));
}
var $e = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function Il(e10) {
  let r = new TextEncoder().encode(e10), t = "", n = r.byteLength, i = n % 3, o = n - i, s, a, l, u, c;
  for (let p = 0; p < o; p = p + 3) c = r[p] << 16 | r[p + 1] << 8 | r[p + 2], s = (c & 16515072) >> 18, a = (c & 258048) >> 12, l = (c & 4032) >> 6, u = c & 63, t += $e[s] + $e[a] + $e[l] + $e[u];
  return i == 1 ? (c = r[o], s = (c & 252) >> 2, a = (c & 3) << 4, t += $e[s] + $e[a] + "==") : i == 2 && (c = r[o] << 8 | r[o + 1], s = (c & 64512) >> 10, a = (c & 1008) >> 4, l = (c & 15) << 2, t += $e[s] + $e[a] + $e[l] + "="), t;
}
function Dl(e10) {
  var _a3;
  if (!!((_a3 = e10.generator) == null ? void 0 : _a3.previewFeatures.some((t) => t.toLowerCase().includes("metrics")))) throw new P("The `metrics` preview feature is not yet available with Accelerate.\nPlease remove `metrics` from the `previewFeatures` in your schema.\n\nMore information about Accelerate: https://pris.ly/d/accelerate", e10.clientVersion);
}
var Ol = { "@prisma/engines-version": "6.15.0-5.85179d7826409ee107a6ba334b5e305ae3fba9fb"};
var Ft = class extends se {
  constructor(r, t) {
    super(`Cannot fetch data from service:
${r}`, R(t, true));
    __publicField(this, "name", "RequestError");
    __publicField(this, "code", "P5010");
  }
};
x(Ft, "RequestError");
async function dr(e10, r, t = (n) => n) {
  var _a3;
  let { clientVersion: n, ...i } = r, o = t(fetch);
  try {
    return await o(e10, i);
  } catch (s) {
    let a = (_a3 = s.message) != null ? _a3 : "Unknown error";
    throw new Ft(a, { clientVersion: n, cause: s });
  }
}
var gf = /^[1-9][0-9]*\.[0-9]+\.[0-9]+$/, kl = N("prisma:client:dataproxyEngine");
async function hf(e10, r) {
  var _a3, _b2, _c3;
  let t = Ol["@prisma/engines-version"], n = (_a3 = r.clientVersion) != null ? _a3 : "unknown";
  if (process.env.PRISMA_CLIENT_DATA_PROXY_CLIENT_VERSION || globalThis.PRISMA_CLIENT_DATA_PROXY_CLIENT_VERSION) return process.env.PRISMA_CLIENT_DATA_PROXY_CLIENT_VERSION || globalThis.PRISMA_CLIENT_DATA_PROXY_CLIENT_VERSION;
  if (e10.includes("accelerate") && n !== "0.0.0" && n !== "in-memory") return n;
  let [i, o] = (_b2 = n == null ? void 0 : n.split("-")) != null ? _b2 : [];
  if (o === void 0 && gf.test(i)) return i;
  if (o !== void 0 || n === "0.0.0" || n === "in-memory") {
    let [s] = (_c3 = t.split("-")) != null ? _c3 : [], [a, l, u] = s.split("."), c = yf(`<=${a}.${l}.${u}`), p = await dr(c, { clientVersion: n });
    if (!p.ok) throw new Error(`Failed to fetch stable Prisma version, unpkg.com status ${p.status} ${p.statusText}, response body: ${await p.text() || "<empty body>"}`);
    let d = await p.text();
    kl("length of body fetched from unpkg.com", d.length);
    let f;
    try {
      f = JSON.parse(d);
    } catch (h) {
      throw console.error("JSON.parse error: body fetched from unpkg.com: ", d), h;
    }
    return f.version;
  }
  throw new cr("Only `major.minor.patch` versions are supported by Accelerate.", { clientVersion: n });
}
async function _l(e10, r) {
  let t = await hf(e10, r);
  return kl("version", t), t;
}
function yf(e10) {
  return encodeURI(`https://unpkg.com/prisma@${e10}/package.json`);
}
var Nl = 3, Mt = N("prisma:client:dataproxyEngine"), $t = class {
  constructor(r) {
    __publicField(this, "name", "DataProxyEngine");
    __publicField(this, "inlineSchema");
    __publicField(this, "inlineSchemaHash");
    __publicField(this, "inlineDatasources");
    __publicField(this, "config");
    __publicField(this, "logEmitter");
    __publicField(this, "env");
    __publicField(this, "clientVersion");
    __publicField(this, "engineHash");
    __publicField(this, "tracingHelper");
    __publicField(this, "remoteClientVersion");
    __publicField(this, "host");
    __publicField(this, "headerBuilder");
    __publicField(this, "startPromise");
    __publicField(this, "protocol");
    Dl(r), this.config = r, this.env = r.env, this.inlineSchema = Il(r.inlineSchema), this.inlineDatasources = r.inlineDatasources, this.inlineSchemaHash = r.inlineSchemaHash, this.clientVersion = r.clientVersion, this.engineHash = r.engineVersion, this.logEmitter = r.logEmitter, this.tracingHelper = r.tracingHelper;
  }
  apiKey() {
    return this.headerBuilder.apiKey;
  }
  version() {
    return this.engineHash;
  }
  async start() {
    this.startPromise !== void 0 && await this.startPromise, this.startPromise = (async () => {
      var _a3;
      let { apiKey: r, url: t } = this.getURLAndAPIKey();
      this.host = t.host, this.protocol = t.protocol, this.headerBuilder = new Hn({ apiKey: r, tracingHelper: this.tracingHelper, logLevel: (_a3 = this.config.logLevel) != null ? _a3 : "error", logQueries: this.config.logQueries, engineHash: this.engineHash }), this.remoteClientVersion = await _l(this.host, this.config), Mt("host", this.host), Mt("protocol", this.protocol);
    })(), await this.startPromise;
  }
  async stop() {
  }
  propagateResponseExtensions(r) {
    var _a3, _b2;
    ((_a3 = r == null ? void 0 : r.logs) == null ? void 0 : _a3.length) && r.logs.forEach((t) => {
      var _a4, _b3, _c3, _d3;
      switch (t.level) {
        case "debug":
        case "trace":
          Mt(t);
          break;
        case "error":
        case "warn":
        case "info": {
          this.logEmitter.emit(t.level, { timestamp: mo(t.timestamp), message: (_a4 = t.attributes.message) != null ? _a4 : "", target: t.target });
          break;
        }
        case "query": {
          this.logEmitter.emit("query", { query: (_b3 = t.attributes.query) != null ? _b3 : "", timestamp: mo(t.timestamp), duration: (_c3 = t.attributes.duration_ms) != null ? _c3 : 0, params: (_d3 = t.attributes.params) != null ? _d3 : "", target: t.target });
          break;
        }
        default:
          t.level;
      }
    }), ((_b2 = r == null ? void 0 : r.traces) == null ? void 0 : _b2.length) && this.tracingHelper.dispatchEngineSpans(r.traces);
  }
  onBeforeExit() {
    throw new Error('"beforeExit" hook is not applicable to the remote query engine');
  }
  async url(r) {
    return await this.start(), `${this.protocol}//${this.host}/${this.remoteClientVersion}/${this.inlineSchemaHash}/${r}`;
  }
  async uploadSchema() {
    let r = { name: "schemaUpload", internal: true };
    return this.tracingHelper.runInChildSpan(r, async () => {
      let t = await dr(await this.url("schema"), { method: "PUT", headers: this.headerBuilder.build(), body: this.inlineSchema, clientVersion: this.clientVersion });
      t.ok || Mt("schema response status", t.status);
      let n = await Lt(t, this.clientVersion);
      if (n) throw this.logEmitter.emit("warn", { message: `Error while uploading schema: ${n.message}`, timestamp: /* @__PURE__ */ new Date(), target: "" }), n;
      this.logEmitter.emit("info", { message: `Schema (re)uploaded (hash: ${this.inlineSchemaHash})`, timestamp: /* @__PURE__ */ new Date(), target: "" });
    });
  }
  request(r, { traceparent: t, interactiveTransaction: n, customDataProxyFetch: i }) {
    return this.requestInternal({ body: r, traceparent: t, interactiveTransaction: n, customDataProxyFetch: i });
  }
  async requestBatch(r, { traceparent: t, transaction: n, customDataProxyFetch: i }) {
    let o = (n == null ? void 0 : n.kind) === "itx" ? n.options : void 0, s = Fr(r, n);
    return (await this.requestInternal({ body: s, customDataProxyFetch: i, interactiveTransaction: o, traceparent: t })).map((l) => (l.extensions && this.propagateResponseExtensions(l.extensions), "errors" in l ? this.convertProtocolErrorsToClientError(l.errors) : l));
  }
  requestInternal({ body: r, traceparent: t, customDataProxyFetch: n, interactiveTransaction: i }) {
    return this.withRetry({ actionGerund: "querying", callback: async ({ logHttpCall: o }) => {
      let s = i ? `${i.payload.endpoint}/graphql` : await this.url("graphql");
      o(s);
      let a = await dr(s, { method: "POST", headers: this.headerBuilder.build({ traceparent: t, transactionId: i == null ? void 0 : i.id }), body: JSON.stringify(r), clientVersion: this.clientVersion }, n);
      a.ok || Mt("graphql response status", a.status), await this.handleError(await Lt(a, this.clientVersion));
      let l = await a.json();
      if (l.extensions && this.propagateResponseExtensions(l.extensions), "errors" in l) throw this.convertProtocolErrorsToClientError(l.errors);
      return "batchResult" in l ? l.batchResult : l;
    } });
  }
  async transaction(r, t, n) {
    let i = { start: "starting", commit: "committing", rollback: "rolling back" };
    return this.withRetry({ actionGerund: `${i[r]} transaction`, callback: async ({ logHttpCall: o }) => {
      if (r === "start") {
        let s = JSON.stringify({ max_wait: n.maxWait, timeout: n.timeout, isolation_level: n.isolationLevel }), a = await this.url("transaction/start");
        o(a);
        let l = await dr(a, { method: "POST", headers: this.headerBuilder.build({ traceparent: t.traceparent }), body: s, clientVersion: this.clientVersion });
        await this.handleError(await Lt(l, this.clientVersion));
        let u = await l.json(), { extensions: c } = u;
        c && this.propagateResponseExtensions(c);
        let p = u.id, d = u["data-proxy"].endpoint;
        return { id: p, payload: { endpoint: d } };
      } else {
        let s = `${n.payload.endpoint}/${r}`;
        o(s);
        let a = await dr(s, { method: "POST", headers: this.headerBuilder.build({ traceparent: t.traceparent }), clientVersion: this.clientVersion });
        await this.handleError(await Lt(a, this.clientVersion));
        let l = await a.json(), { extensions: u } = l;
        u && this.propagateResponseExtensions(u);
        return;
      }
    } });
  }
  getURLAndAPIKey() {
    return Rl({ clientVersion: this.clientVersion, env: this.env, inlineDatasources: this.inlineDatasources, overrideDatasources: this.config.overrideDatasources });
  }
  metrics() {
    throw new cr("Metrics are not yet supported for Accelerate", { clientVersion: this.clientVersion });
  }
  async withRetry(r) {
    var _a3;
    for (let t = 0; ; t++) {
      let n = (i) => {
        this.logEmitter.emit("info", { message: `Calling ${i} (n=${t})`, timestamp: /* @__PURE__ */ new Date(), target: "" });
      };
      try {
        return await r.callback({ logHttpCall: n });
      } catch (i) {
        if (!(i instanceof se) || !i.isRetryable) throw i;
        if (t >= Nl) throw i instanceof jr ? i.cause : i;
        this.logEmitter.emit("warn", { message: `Attempt ${t + 1}/${Nl} failed for ${r.actionGerund}: ${(_a3 = i.message) != null ? _a3 : "(unknown)"}`, timestamp: /* @__PURE__ */ new Date(), target: "" });
        let o = await Cl(t);
        this.logEmitter.emit("warn", { message: `Retrying after ${o}ms`, timestamp: /* @__PURE__ */ new Date(), target: "" });
      }
    }
  }
  async handleError(r) {
    if (r instanceof pr) throw await this.uploadSchema(), new jr({ clientVersion: this.clientVersion, cause: r });
    if (r) throw r;
  }
  convertProtocolErrorsToClientError(r) {
    return r.length === 1 ? Mr(r[0], this.config.clientVersion, this.config.activeProvider) : new V(JSON.stringify(r), { clientVersion: this.config.clientVersion });
  }
  applyPendingMigrations() {
    throw new Error("Method not implemented.");
  }
};
function Ll(e10) {
  if ((e10 == null ? void 0 : e10.kind) === "itx") return e10.options.id;
}
var xo = A(require$$0), Fl = A(require$$3);
var wo = Symbol("PrismaLibraryEngineCache");
function bf() {
  let e10 = globalThis;
  return e10[wo] === void 0 && (e10[wo] = {}), e10[wo];
}
function Ef(e10) {
  let r = bf();
  if (r[e10] !== void 0) return r[e10];
  let t = Fl.default.toNamespacedPath(e10), n = { exports: {} }, i = 0;
  return process.platform !== "win32" && (i = xo.default.constants.dlopen.RTLD_LAZY | xo.default.constants.dlopen.RTLD_DEEPBIND), process.dlopen(n, t, i), r[e10] = n.exports, n.exports;
}
var Ml = { async loadLibrary(e10) {
  let r = await fi(), t = await yl("library", e10);
  try {
    return e10.tracingHelper.runInChildSpan({ name: "loadLibrary", internal: true }, () => Ef(t));
  } catch (n) {
    let i = Ai({ e: n, platformInfo: r, id: t });
    throw new P(i, e10.clientVersion);
  }
} };
var vo, $l = { async loadLibrary(e10) {
  let { clientVersion: r, adapter: t, engineWasm: n } = e10;
  if (t === void 0) throw new P(`The \`adapter\` option for \`PrismaClient\` is required in this context (${Gn().prettyName})`, r);
  if (n === void 0) throw new P("WASM engine was unexpectedly `undefined`", r);
  vo === void 0 && (vo = (async () => {
    let o = await n.getRuntime(), s = await n.getQueryEngineWasmModule();
    if (s == null) throw new P("The loaded wasm module was unexpectedly `undefined` or `null` once loaded", r);
    let a = { "./query_engine_bg.js": o }, l = new WebAssembly.Instance(s, a), u = l.exports.__wbindgen_start;
    return o.__wbg_set_wasm(l.exports), u(), o.QueryEngine;
  })());
  let i = await vo;
  return { debugPanic() {
    return Promise.reject("{}");
  }, dmmf() {
    return Promise.resolve("{}");
  }, version() {
    return { commit: "unknown", version: "unknown" };
  }, QueryEngine: i };
} };
var wf = "P2036", Re = N("prisma:client:libraryEngine");
function xf(e10) {
  return e10.item_type === "query" && "query" in e10;
}
function vf(e10) {
  return "level" in e10 ? e10.level === "error" && e10.message === "PANIC" : false;
}
var ql = [...li, "native"], Pf = /* @__PURE__ */ BigInt("0xffffffffffffffff"), Po = /* @__PURE__ */ BigInt("1");
function Tf() {
  let e10 = Po++;
  return Po > Pf && (Po = /* @__PURE__ */ BigInt("1")), e10;
}
var Gr = class {
  constructor(r, t) {
    __publicField(this, "name", "LibraryEngine");
    __publicField(this, "engine");
    __publicField(this, "libraryInstantiationPromise");
    __publicField(this, "libraryStartingPromise");
    __publicField(this, "libraryStoppingPromise");
    __publicField(this, "libraryStarted");
    __publicField(this, "executingQueryPromise");
    __publicField(this, "config");
    __publicField(this, "QueryEngineConstructor");
    __publicField(this, "libraryLoader");
    __publicField(this, "library");
    __publicField(this, "logEmitter");
    __publicField(this, "libQueryEnginePath");
    __publicField(this, "binaryTarget");
    __publicField(this, "datasourceOverrides");
    __publicField(this, "datamodel");
    __publicField(this, "logQueries");
    __publicField(this, "logLevel");
    __publicField(this, "lastQuery");
    __publicField(this, "loggerRustPanic");
    __publicField(this, "tracingHelper");
    __publicField(this, "adapterPromise");
    __publicField(this, "versionInfo");
    var _a3, _b2, _c3;
    this.libraryLoader = t != null ? t : Ml, r.engineWasm !== void 0 && (this.libraryLoader = t != null ? t : $l), this.config = r, this.libraryStarted = false, this.logQueries = (_a3 = r.logQueries) != null ? _a3 : false, this.logLevel = (_b2 = r.logLevel) != null ? _b2 : "error", this.logEmitter = r.logEmitter, this.datamodel = r.inlineSchema, this.tracingHelper = r.tracingHelper, r.enableDebugLogs && (this.logLevel = "debug");
    let n = Object.keys(r.overrideDatasources)[0], i = (_c3 = r.overrideDatasources[n]) == null ? void 0 : _c3.url;
    n !== void 0 && i !== void 0 && (this.datasourceOverrides = { [n]: i }), this.libraryInstantiationPromise = this.instantiateLibrary();
  }
  wrapEngine(r) {
    var _a3, _b2, _c3, _d3;
    return { applyPendingMigrations: (_a3 = r.applyPendingMigrations) == null ? void 0 : _a3.bind(r), commitTransaction: this.withRequestId(r.commitTransaction.bind(r)), connect: this.withRequestId(r.connect.bind(r)), disconnect: this.withRequestId(r.disconnect.bind(r)), metrics: (_b2 = r.metrics) == null ? void 0 : _b2.bind(r), query: this.withRequestId(r.query.bind(r)), rollbackTransaction: this.withRequestId(r.rollbackTransaction.bind(r)), sdlSchema: (_c3 = r.sdlSchema) == null ? void 0 : _c3.bind(r), startTransaction: this.withRequestId(r.startTransaction.bind(r)), trace: r.trace.bind(r), free: (_d3 = r.free) == null ? void 0 : _d3.bind(r) };
  }
  withRequestId(r) {
    return async (...t) => {
      var _a3;
      let n = Tf().toString();
      try {
        return await r(...t, n);
      } finally {
        if (this.tracingHelper.isEnabled()) {
          let i = await ((_a3 = this.engine) == null ? void 0 : _a3.trace(n));
          if (i) {
            let o = JSON.parse(i);
            this.tracingHelper.dispatchEngineSpans(o.spans);
          }
        }
      }
    };
  }
  async applyPendingMigrations() {
    throw new Error("Cannot call this method from this type of engine instance");
  }
  async transaction(r, t, n) {
    var _a3, _b2, _c3;
    await this.start();
    let i = await this.adapterPromise, o = JSON.stringify(t), s;
    if (r === "start") {
      let l = JSON.stringify({ max_wait: n.maxWait, timeout: n.timeout, isolation_level: n.isolationLevel });
      s = await ((_a3 = this.engine) == null ? void 0 : _a3.startTransaction(l, o));
    } else r === "commit" ? s = await ((_b2 = this.engine) == null ? void 0 : _b2.commitTransaction(n.id, o)) : r === "rollback" && (s = await ((_c3 = this.engine) == null ? void 0 : _c3.rollbackTransaction(n.id, o)));
    let a = this.parseEngineResponse(s);
    if (Sf(a)) {
      let l = this.getExternalAdapterError(a, i == null ? void 0 : i.errorRegistry);
      throw l ? l.error : new z(a.message, { code: a.error_code, clientVersion: this.config.clientVersion, meta: a.meta });
    } else if (typeof a.message == "string") throw new V(a.message, { clientVersion: this.config.clientVersion });
    return a;
  }
  async instantiateLibrary() {
    if (Re("internalSetup"), this.libraryInstantiationPromise) return this.libraryInstantiationPromise;
    ai(), this.binaryTarget = await this.getCurrentBinaryTarget(), await this.tracingHelper.runInChildSpan("load_engine", () => this.loadEngine()), this.version();
  }
  async getCurrentBinaryTarget() {
    {
      if (this.binaryTarget) return this.binaryTarget;
      let r = await this.tracingHelper.runInChildSpan("detect_platform", () => ir());
      if (!ql.includes(r)) throw new P(`Unknown ${ce("PRISMA_QUERY_ENGINE_LIBRARY")} ${ce(W(r))}. Possible binaryTargets: ${qe(ql.join(", "))} or a path to the query engine library.
You may have to run ${qe("prisma generate")} for your changes to take effect.`, this.config.clientVersion);
      return r;
    }
  }
  parseEngineResponse(r) {
    if (!r) throw new V("Response from the Engine was empty", { clientVersion: this.config.clientVersion });
    try {
      return JSON.parse(r);
    } catch {
      throw new V("Unable to JSON.parse response from engine", { clientVersion: this.config.clientVersion });
    }
  }
  async loadEngine() {
    var _a3, _b2, _c3, _d3;
    if (!this.engine) {
      this.QueryEngineConstructor || (this.library = await this.libraryLoader.loadLibrary(this.config), this.QueryEngineConstructor = this.library.QueryEngine);
      try {
        let r = new WeakRef(this);
        this.adapterPromise || (this.adapterPromise = (_b2 = (_a3 = this.config.adapter) == null ? void 0 : _a3.connect()) == null ? void 0 : _b2.then(rn));
        let t = await this.adapterPromise;
        t && Re("Using driver adapter: %O", t), this.engine = this.wrapEngine(new this.QueryEngineConstructor({ datamodel: this.datamodel, env: process.env, logQueries: (_c3 = this.config.logQueries) != null ? _c3 : false, ignoreEnvVarErrors: true, datasourceOverrides: (_d3 = this.datasourceOverrides) != null ? _d3 : {}, logLevel: this.logLevel, configDir: this.config.cwd, engineProtocol: "json", enableTracing: this.tracingHelper.isEnabled() }, (n) => {
          var _a4;
          (_a4 = r.deref()) == null ? void 0 : _a4.logger(n);
        }, t));
      } catch (r) {
        let t = r, n = this.parseInitError(t.message);
        throw typeof n == "string" ? t : new P(n.message, this.config.clientVersion, n.error_code);
      }
    }
  }
  logger(r) {
    var _a3;
    let t = this.parseEngineResponse(r);
    t && (t.level = (_a3 = t == null ? void 0 : t.level.toLowerCase()) != null ? _a3 : "unknown", xf(t) ? this.logEmitter.emit("query", { timestamp: /* @__PURE__ */ new Date(), query: t.query, params: t.params, duration: Number(t.duration_ms), target: t.module_path }) : vf(t) ? this.loggerRustPanic = new le(To(this, `${t.message}: ${t.reason} in ${t.file}:${t.line}:${t.column}`), this.config.clientVersion) : this.logEmitter.emit(t.level, { timestamp: /* @__PURE__ */ new Date(), message: t.message, target: t.module_path }));
  }
  parseInitError(r) {
    try {
      return JSON.parse(r);
    } catch {
    }
    return r;
  }
  parseRequestError(r) {
    try {
      return JSON.parse(r);
    } catch {
    }
    return r;
  }
  onBeforeExit() {
    throw new Error('"beforeExit" hook is not applicable to the library engine since Prisma 5.0.0, it is only relevant and implemented for the binary engine. Please add your event listener to the `process` object directly instead.');
  }
  async start() {
    if (this.libraryInstantiationPromise || (this.libraryInstantiationPromise = this.instantiateLibrary()), await this.libraryInstantiationPromise, await this.libraryStoppingPromise, this.libraryStartingPromise) return Re(`library already starting, this.libraryStarted: ${this.libraryStarted}`), this.libraryStartingPromise;
    if (this.libraryStarted) return;
    let r = async () => {
      var _a3, _b2, _c3;
      Re("library starting");
      try {
        let t = { traceparent: this.tracingHelper.getTraceParent() };
        await ((_a3 = this.engine) == null ? void 0 : _a3.connect(JSON.stringify(t))), this.libraryStarted = true, this.adapterPromise || (this.adapterPromise = (_c3 = (_b2 = this.config.adapter) == null ? void 0 : _b2.connect()) == null ? void 0 : _c3.then(rn)), await this.adapterPromise, Re("library started");
      } catch (t) {
        let n = this.parseInitError(t.message);
        throw typeof n == "string" ? t : new P(n.message, this.config.clientVersion, n.error_code);
      } finally {
        this.libraryStartingPromise = void 0;
      }
    };
    return this.libraryStartingPromise = this.tracingHelper.runInChildSpan("connect", r), this.libraryStartingPromise;
  }
  async stop() {
    var _a3;
    if (await this.libraryInstantiationPromise, await this.libraryStartingPromise, await this.executingQueryPromise, this.libraryStoppingPromise) return Re("library is already stopping"), this.libraryStoppingPromise;
    if (!this.libraryStarted) {
      await ((_a3 = await this.adapterPromise) == null ? void 0 : _a3.dispose()), this.adapterPromise = void 0;
      return;
    }
    let r = async () => {
      var _a4, _b2, _c3;
      await new Promise((n) => setImmediate(n)), Re("library stopping");
      let t = { traceparent: this.tracingHelper.getTraceParent() };
      await ((_a4 = this.engine) == null ? void 0 : _a4.disconnect(JSON.stringify(t))), ((_b2 = this.engine) == null ? void 0 : _b2.free) && this.engine.free(), this.engine = void 0, this.libraryStarted = false, this.libraryStoppingPromise = void 0, this.libraryInstantiationPromise = void 0, await ((_c3 = await this.adapterPromise) == null ? void 0 : _c3.dispose()), this.adapterPromise = void 0, Re("library stopped");
    };
    return this.libraryStoppingPromise = this.tracingHelper.runInChildSpan("disconnect", r), this.libraryStoppingPromise;
  }
  version() {
    var _a3, _b2, _c3;
    return this.versionInfo = (_a3 = this.library) == null ? void 0 : _a3.version(), (_c3 = (_b2 = this.versionInfo) == null ? void 0 : _b2.version) != null ? _c3 : "unknown";
  }
  debugPanic(r) {
    var _a3;
    return (_a3 = this.library) == null ? void 0 : _a3.debugPanic(r);
  }
  async request(r, { traceparent: t, interactiveTransaction: n }) {
    var _a3, _b2;
    Re(`sending request, this.libraryStarted: ${this.libraryStarted}`);
    let i = JSON.stringify({ traceparent: t }), o = JSON.stringify(r);
    try {
      await this.start();
      let s = await this.adapterPromise;
      this.executingQueryPromise = (_a3 = this.engine) == null ? void 0 : _a3.query(o, i, n == null ? void 0 : n.id), this.lastQuery = o;
      let a = this.parseEngineResponse(await this.executingQueryPromise);
      if (a.errors) throw a.errors.length === 1 ? this.buildQueryError(a.errors[0], s == null ? void 0 : s.errorRegistry) : new V(JSON.stringify(a.errors), { clientVersion: this.config.clientVersion });
      if (this.loggerRustPanic) throw this.loggerRustPanic;
      return { data: a };
    } catch (s) {
      if (s instanceof P) throw s;
      if (s.code === "GenericFailure" && ((_b2 = s.message) == null ? void 0 : _b2.startsWith("PANIC:"))) throw new le(To(this, s.message), this.config.clientVersion);
      let a = this.parseRequestError(s.message);
      throw typeof a == "string" ? s : new V(`${a.message}
${a.backtrace}`, { clientVersion: this.config.clientVersion });
    }
  }
  async requestBatch(r, { transaction: t, traceparent: n }) {
    var _a3;
    Re("requestBatch");
    let i = Fr(r, t);
    await this.start();
    let o = await this.adapterPromise;
    this.lastQuery = JSON.stringify(i), this.executingQueryPromise = (_a3 = this.engine) == null ? void 0 : _a3.query(this.lastQuery, JSON.stringify({ traceparent: n }), Ll(t));
    let s = await this.executingQueryPromise, a = this.parseEngineResponse(s);
    if (a.errors) throw a.errors.length === 1 ? this.buildQueryError(a.errors[0], o == null ? void 0 : o.errorRegistry) : new V(JSON.stringify(a.errors), { clientVersion: this.config.clientVersion });
    let { batchResult: l, errors: u } = a;
    if (Array.isArray(l)) return l.map((c) => {
      var _a4;
      return c.errors && c.errors.length > 0 ? (_a4 = this.loggerRustPanic) != null ? _a4 : this.buildQueryError(c.errors[0], o == null ? void 0 : o.errorRegistry) : { data: c };
    });
    throw u && u.length === 1 ? new Error(u[0].error) : new Error(JSON.stringify(a));
  }
  buildQueryError(r, t) {
    if (r.user_facing_error.is_panic) return new le(To(this, r.user_facing_error.message), this.config.clientVersion);
    let n = this.getExternalAdapterError(r.user_facing_error, t);
    return n ? n.error : Mr(r, this.config.clientVersion, this.config.activeProvider);
  }
  getExternalAdapterError(r, t) {
    var _a3;
    if (r.error_code === wf && t) {
      let n = (_a3 = r.meta) == null ? void 0 : _a3.id;
      an(typeof n == "number", "Malformed external JS error received from the engine");
      let i = t.consumeError(n);
      return an(i, "External error with reported id was not registered"), i;
    }
  }
  async metrics(r) {
    await this.start();
    let t = await this.engine.metrics(JSON.stringify(r));
    return r.format === "prometheus" ? t : this.parseEngineResponse(t);
  }
};
function Sf(e10) {
  return typeof e10 == "object" && e10 !== null && e10.error_code !== void 0;
}
function To(e10, r) {
  var _a3;
  return Pl({ binaryTarget: e10.binaryTarget, title: r, version: e10.config.clientVersion, engineVersion: (_a3 = e10.versionInfo) == null ? void 0 : _a3.commit, database: e10.config.activeProvider, query: e10.lastQuery });
}
function Vl({ url: e10, adapter: r, copyEngine: t, targetBuildType: n }) {
  let i = [], o = [], s = (g) => {
    i.push({ _tag: "warning", value: g });
  }, a = (g) => {
    let D = g.join(`
`);
    o.push({ _tag: "error", value: D });
  }, l = !!(e10 == null ? void 0 : e10.startsWith("prisma://")), u = sn(e10), c = !!r, p = l || u;
  !c && t && p && s(["recommend--no-engine", "In production, we recommend using `prisma generate --no-engine` (See: `prisma generate --help`)"]);
  let d = p || !t;
  c && (d || n === "edge") && (t ? l && a(["Prisma Client was configured to use the `adapter` option but the URL was a `prisma://` URL.", "Please either use the `prisma://` URL or remove the `adapter` from the Prisma Client constructor."]) : a(["Prisma Client was configured to use the `adapter` option but `prisma generate` was run with `--no-engine`.", "Please run `prisma generate` without `--no-engine` to be able to use Prisma Client with the adapter."]));
  let f = { accelerate: d, ppg: u, driverAdapters: c };
  function h(g) {
    return g.length > 0;
  }
  return h(o) ? { ok: false, diagnostics: { warnings: i, errors: o }, isUsing: f } : { ok: true, diagnostics: { warnings: i }, isUsing: f };
}
function jl({ copyEngine: e10 = true }, r) {
  let t;
  try {
    t = Vr({ inlineDatasources: r.inlineDatasources, overrideDatasources: r.overrideDatasources, env: { ...r.env, ...process.env }, clientVersion: r.clientVersion });
  } catch {
  }
  let { ok: n, isUsing: i, diagnostics: o } = Vl({ url: t, adapter: r.adapter, copyEngine: e10, targetBuildType: "library" });
  for (let p of o.warnings) st(...p.value);
  if (!n) {
    let p = o.errors[0];
    throw new Z(p.value, { clientVersion: r.clientVersion });
  }
  let s = Er(r.generator), a = s === "library"; (i.accelerate || i.ppg) && !i.driverAdapters;
  return i.accelerate ? new $t(r) : (i.driverAdapters, a ? new Gr(r) : (i.accelerate, new Gr(r)));
}
function Yn({ generator: e10 }) {
  var _a3;
  return (_a3 = e10 == null ? void 0 : e10.previewFeatures) != null ? _a3 : [];
}
var Bl = (e10) => ({ command: e10 });
var Ul = (e10) => e10.strings.reduce((r, t, n) => `${r}@P${n}${t}`);
function Qr(e10) {
  try {
    return Gl(e10, "fast");
  } catch {
    return Gl(e10, "slow");
  }
}
function Gl(e10, r) {
  return JSON.stringify(e10.map((t) => Wl(t, r)));
}
function Wl(e10, r) {
  if (Array.isArray(e10)) return e10.map((t) => Wl(t, r));
  if (typeof e10 == "bigint") return { prisma__type: "bigint", prisma__value: e10.toString() };
  if (xr(e10)) return { prisma__type: "date", prisma__value: e10.toJSON() };
  if (Fe.isDecimal(e10)) return { prisma__type: "decimal", prisma__value: e10.toJSON() };
  if (Buffer.isBuffer(e10)) return { prisma__type: "bytes", prisma__value: e10.toString("base64") };
  if (Rf(e10)) return { prisma__type: "bytes", prisma__value: Buffer.from(e10).toString("base64") };
  if (ArrayBuffer.isView(e10)) {
    let { buffer: t, byteOffset: n, byteLength: i } = e10;
    return { prisma__type: "bytes", prisma__value: Buffer.from(t, n, i).toString("base64") };
  }
  return typeof e10 == "object" && r === "slow" ? Jl(e10) : e10;
}
function Rf(e10) {
  return e10 instanceof ArrayBuffer || e10 instanceof SharedArrayBuffer ? true : typeof e10 == "object" && e10 !== null ? e10[Symbol.toStringTag] === "ArrayBuffer" || e10[Symbol.toStringTag] === "SharedArrayBuffer" : false;
}
function Jl(e10) {
  if (typeof e10 != "object" || e10 === null) return e10;
  if (typeof e10.toJSON == "function") return e10.toJSON();
  if (Array.isArray(e10)) return e10.map(Ql);
  let r = {};
  for (let t of Object.keys(e10)) r[t] = Ql(e10[t]);
  return r;
}
function Ql(e10) {
  return typeof e10 == "bigint" ? e10.toString() : Jl(e10);
}
var Af = /^(\s*alter\s)/i, Kl = N("prisma:client");
function So(e10, r, t, n) {
  if (!(e10 !== "postgresql" && e10 !== "cockroachdb") && t.length > 0 && Af.exec(r)) throw new Error(`Running ALTER using ${n} is not supported
Using the example below you can still execute your query with Prisma, but please note that it is vulnerable to SQL injection attacks and requires you to take care of input sanitization.

Example:
  await prisma.$executeRawUnsafe(\`ALTER USER prisma WITH PASSWORD '\${password}'\`)

More Information: https://pris.ly/d/execute-raw
`);
}
var Ro = ({ clientMethod: e10, activeProvider: r }) => (t) => {
  let n = "", i;
  if (qn(t)) n = t.sql, i = { values: Qr(t.values), __prismaRawParameters__: true };
  else if (Array.isArray(t)) {
    let [o, ...s] = t;
    n = o, i = { values: Qr(s || []), __prismaRawParameters__: true };
  } else switch (r) {
    case "sqlite":
    case "mysql": {
      n = t.sql, i = { values: Qr(t.values), __prismaRawParameters__: true };
      break;
    }
    case "cockroachdb":
    case "postgresql":
    case "postgres": {
      n = t.text, i = { values: Qr(t.values), __prismaRawParameters__: true };
      break;
    }
    case "sqlserver": {
      n = Ul(t), i = { values: Qr(t.values), __prismaRawParameters__: true };
      break;
    }
    default:
      throw new Error(`The ${r} provider does not support ${e10}`);
  }
  return (i == null ? void 0 : i.values) ? Kl(`prisma.${e10}(${n}, ${i.values})`) : Kl(`prisma.${e10}(${n})`), { query: n, parameters: i };
}, Hl = { requestArgsToMiddlewareArgs(e10) {
  return [e10.strings, ...e10.values];
}, middlewareArgsToRequestArgs(e10) {
  let [r, ...t] = e10;
  return new oe(r, t);
} }, Yl = { requestArgsToMiddlewareArgs(e10) {
  return [e10];
}, middlewareArgsToRequestArgs(e10) {
  return e10[0];
} };
function Ao(e10) {
  return function(t, n) {
    let i, o = (s = e10) => {
      try {
        return s === void 0 || (s == null ? void 0 : s.kind) === "itx" ? i != null ? i : i = zl(t(s)) : zl(t(s));
      } catch (a) {
        return Promise.reject(a);
      }
    };
    return { get spec() {
      return n;
    }, then(s, a) {
      return o().then(s, a);
    }, catch(s) {
      return o().catch(s);
    }, finally(s) {
      return o().finally(s);
    }, requestTransaction(s) {
      let a = o(s);
      return a.requestTransaction ? a.requestTransaction(s) : a;
    }, [Symbol.toStringTag]: "PrismaPromise" };
  };
}
function zl(e10) {
  return typeof e10.then == "function" ? e10 : Promise.resolve(e10);
}
var Cf = xi.split(".")[0], If = { isEnabled() {
  return false;
}, getTraceParent() {
  return "00-10-10-00";
}, dispatchEngineSpans() {
}, getActiveContext() {
}, runInChildSpan(e10, r) {
  return r();
} }, Co = class {
  isEnabled() {
    return this.getGlobalTracingHelper().isEnabled();
  }
  getTraceParent(r) {
    return this.getGlobalTracingHelper().getTraceParent(r);
  }
  dispatchEngineSpans(r) {
    return this.getGlobalTracingHelper().dispatchEngineSpans(r);
  }
  getActiveContext() {
    return this.getGlobalTracingHelper().getActiveContext();
  }
  runInChildSpan(r, t) {
    return this.getGlobalTracingHelper().runInChildSpan(r, t);
  }
  getGlobalTracingHelper() {
    var _a3, _b2;
    let r = globalThis[`V${Cf}_PRISMA_INSTRUMENTATION`], t = globalThis.PRISMA_INSTRUMENTATION;
    return (_b2 = (_a3 = r == null ? void 0 : r.helper) != null ? _a3 : t == null ? void 0 : t.helper) != null ? _b2 : If;
  }
};
function Zl() {
  return new Co();
}
function Xl(e10, r = () => {
}) {
  let t, n = new Promise((i) => t = i);
  return { then(i) {
    return --e10 === 0 && t(r()), i == null ? void 0 : i(n);
  } };
}
function eu(e10) {
  return typeof e10 == "string" ? e10 : e10.reduce((r, t) => {
    let n = typeof t == "string" ? t : t.level;
    return n === "query" ? r : r && (t === "info" || r === "info") ? "info" : n;
  }, void 0);
}
var tu = A(Ni());
function zn(e10) {
  return typeof e10.batchRequestIdx == "number";
}
function ru(e10) {
  if (e10.action !== "findUnique" && e10.action !== "findUniqueOrThrow") return;
  let r = [];
  return e10.modelName && r.push(e10.modelName), e10.query.arguments && r.push(Io(e10.query.arguments)), r.push(Io(e10.query.selection)), r.join("");
}
function Io(e10) {
  return `(${Object.keys(e10).sort().map((t) => {
    let n = e10[t];
    return typeof n == "object" && n !== null ? `(${t} ${Io(n)})` : t;
  }).join(" ")})`;
}
var Df = { aggregate: false, aggregateRaw: false, createMany: true, createManyAndReturn: true, createOne: true, deleteMany: true, deleteOne: true, executeRaw: true, findFirst: false, findFirstOrThrow: false, findMany: false, findRaw: false, findUnique: false, findUniqueOrThrow: false, groupBy: false, queryRaw: false, runCommandRaw: true, updateMany: true, updateManyAndReturn: true, updateOne: true, upsertOne: true };
function Do(e10) {
  return Df[e10];
}
var Zn = class {
  constructor(r) {
    __publicField(this, "batches");
    __publicField(this, "tickActive", false);
    this.options = r;
    this.batches = {};
  }
  request(r) {
    let t = this.options.batchBy(r);
    return t ? (this.batches[t] || (this.batches[t] = [], this.tickActive || (this.tickActive = true, process.nextTick(() => {
      this.dispatchBatches(), this.tickActive = false;
    }))), new Promise((n, i) => {
      this.batches[t].push({ request: r, resolve: n, reject: i });
    })) : this.options.singleLoader(r);
  }
  dispatchBatches() {
    for (let r in this.batches) {
      let t = this.batches[r];
      delete this.batches[r], t.length === 1 ? this.options.singleLoader(t[0].request).then((n) => {
        n instanceof Error ? t[0].reject(n) : t[0].resolve(n);
      }).catch((n) => {
        t[0].reject(n);
      }) : (t.sort((n, i) => this.options.batchOrder(n.request, i.request)), this.options.batchLoader(t.map((n) => n.request)).then((n) => {
        if (n instanceof Error) for (let i = 0; i < t.length; i++) t[i].reject(n);
        else for (let i = 0; i < t.length; i++) {
          let o = n[i];
          o instanceof Error ? t[i].reject(o) : t[i].resolve(o);
        }
      }).catch((n) => {
        for (let i = 0; i < t.length; i++) t[i].reject(n);
      }));
    }
  }
  get [Symbol.toStringTag]() {
    return "DataLoader";
  }
};
function mr(e10, r) {
  if (r === null) return r;
  switch (e10) {
    case "bigint":
      return BigInt(r);
    case "bytes": {
      let { buffer: t, byteOffset: n, byteLength: i } = Buffer.from(r, "base64");
      return new Uint8Array(t, n, i);
    }
    case "decimal":
      return new Fe(r);
    case "datetime":
    case "date":
      return new Date(r);
    case "time":
      return /* @__PURE__ */ new Date(`1970-01-01T${r}Z`);
    case "bigint-array":
      return r.map((t) => mr("bigint", t));
    case "bytes-array":
      return r.map((t) => mr("bytes", t));
    case "decimal-array":
      return r.map((t) => mr("decimal", t));
    case "datetime-array":
      return r.map((t) => mr("datetime", t));
    case "date-array":
      return r.map((t) => mr("date", t));
    case "time-array":
      return r.map((t) => mr("time", t));
    default:
      return r;
  }
}
function Xn(e10) {
  let r = [], t = Of(e10);
  for (let n = 0; n < e10.rows.length; n++) {
    let i = e10.rows[n], o = { ...t };
    for (let s = 0; s < i.length; s++) o[e10.columns[s]] = mr(e10.types[s], i[s]);
    r.push(o);
  }
  return r;
}
function Of(e10) {
  let r = {};
  for (let t = 0; t < e10.columns.length; t++) r[e10.columns[t]] = null;
  return r;
}
var kf = N("prisma:client:request_handler"), ei = class {
  constructor(r, t) {
    __publicField(this, "client");
    __publicField(this, "dataloader");
    __publicField(this, "logEmitter");
    this.logEmitter = t, this.client = r, this.dataloader = new Zn({ batchLoader: ol(async ({ requests: n, customDataProxyFetch: i }) => {
      let { transaction: o, otelParentCtx: s } = n[0], a = n.map((p) => p.protocolQuery), l = this.client._tracingHelper.getTraceParent(s), u = n.some((p) => Do(p.protocolQuery.action));
      return (await this.client._engine.requestBatch(a, { traceparent: l, transaction: _f(o), containsWrite: u, customDataProxyFetch: i })).map((p, d) => {
        if (p instanceof Error) return p;
        try {
          return this.mapQueryEngineResult(n[d], p);
        } catch (f) {
          return f;
        }
      });
    }), singleLoader: async (n) => {
      var _a3;
      let i = ((_a3 = n.transaction) == null ? void 0 : _a3.kind) === "itx" ? nu(n.transaction) : void 0, o = await this.client._engine.request(n.protocolQuery, { traceparent: this.client._tracingHelper.getTraceParent(), interactiveTransaction: i, isWrite: Do(n.protocolQuery.action), customDataProxyFetch: n.customDataProxyFetch });
      return this.mapQueryEngineResult(n, o);
    }, batchBy: (n) => {
      var _a3;
      return ((_a3 = n.transaction) == null ? void 0 : _a3.id) ? `transaction-${n.transaction.id}` : ru(n.protocolQuery);
    }, batchOrder(n, i) {
      var _a3, _b2;
      return ((_a3 = n.transaction) == null ? void 0 : _a3.kind) === "batch" && ((_b2 = i.transaction) == null ? void 0 : _b2.kind) === "batch" ? n.transaction.index - i.transaction.index : 0;
    } });
  }
  async request(r) {
    try {
      return await this.dataloader.request(r);
    } catch (t) {
      let { clientMethod: n, callsite: i, transaction: o, args: s, modelName: a } = r;
      this.handleAndLogRequestError({ error: t, clientMethod: n, callsite: i, transaction: o, args: s, modelName: a, globalOmit: r.globalOmit });
    }
  }
  mapQueryEngineResult({ dataPath: r, unpacker: t }, n) {
    let i = n == null ? void 0 : n.data, o = this.unpack(i, r, t);
    return process.env.PRISMA_CLIENT_GET_TIME ? { data: o } : o;
  }
  handleAndLogRequestError(r) {
    try {
      this.handleRequestError(r);
    } catch (t) {
      throw this.logEmitter && this.logEmitter.emit("error", { message: t.message, target: r.clientMethod, timestamp: /* @__PURE__ */ new Date() }), t;
    }
  }
  handleRequestError({ error: r, clientMethod: t, callsite: n, transaction: i, args: o, modelName: s, globalOmit: a }) {
    if (kf(r), Nf(r, i)) throw r;
    if (r instanceof z && Lf(r)) {
      let u = iu(r.meta);
      _n({ args: o, errors: [u], callsite: n, errorFormat: this.client._errorFormat, originalMethod: t, clientVersion: this.client._clientVersion, globalOmit: a });
    }
    let l = r.message;
    if (n && (l = Pn({ callsite: n, originalMethod: t, isPanic: r.isPanic, showColors: this.client._errorFormat === "pretty", message: l })), l = this.sanitizeMessage(l), r.code) {
      let u = s ? { modelName: s, ...r.meta } : r.meta;
      throw new z(l, { code: r.code, clientVersion: this.client._clientVersion, meta: u, batchRequestIdx: r.batchRequestIdx });
    } else {
      if (r.isPanic) throw new le(l, this.client._clientVersion);
      if (r instanceof V) throw new V(l, { clientVersion: this.client._clientVersion, batchRequestIdx: r.batchRequestIdx });
      if (r instanceof P) throw new P(l, this.client._clientVersion);
      if (r instanceof le) throw new le(l, this.client._clientVersion);
    }
    throw r.clientVersion = this.client._clientVersion, r;
  }
  sanitizeMessage(r) {
    return this.client._errorFormat && this.client._errorFormat !== "pretty" ? (0, tu.default)(r) : r;
  }
  unpack(r, t, n) {
    if (!r || (r.data && (r = r.data), !r)) return r;
    let i = Object.keys(r)[0], o = Object.values(r)[0], s = t.filter((u) => u !== "select" && u !== "include"), a = ao(o, s), l = i === "queryRaw" ? Xn(a) : qr(a);
    return n ? n(l) : l;
  }
  get [Symbol.toStringTag]() {
    return "RequestHandler";
  }
};
function _f(e10) {
  if (e10) {
    if (e10.kind === "batch") return { kind: "batch", options: { isolationLevel: e10.isolationLevel } };
    if (e10.kind === "itx") return { kind: "itx", options: nu(e10) };
    ar(e10, "Unknown transaction kind");
  }
}
function nu(e10) {
  return { id: e10.id, payload: e10.payload };
}
function Nf(e10, r) {
  return zn(e10) && (r == null ? void 0 : r.kind) === "batch" && e10.batchRequestIdx !== r.index;
}
function Lf(e10) {
  return e10.code === "P2009" || e10.code === "P2012";
}
function iu(e10) {
  if (e10.kind === "Union") return { kind: "Union", errors: e10.errors.map(iu) };
  if (Array.isArray(e10.selectionPath)) {
    let [, ...r] = e10.selectionPath;
    return { ...e10, selectionPath: r };
  }
  return e10;
}
var ou = Sl;
var cu = A(Ki());
var k = class extends Error {
  constructor(r) {
    super(r + `
Read more at https://pris.ly/d/client-constructor`), this.name = "PrismaClientConstructorValidationError";
  }
  get [Symbol.toStringTag]() {
    return "PrismaClientConstructorValidationError";
  }
};
x(k, "PrismaClientConstructorValidationError");
var su = ["datasources", "datasourceUrl", "errorFormat", "adapter", "log", "transactionOptions", "omit", "__internal"], au = ["pretty", "colorless", "minimal"], lu = ["info", "query", "warn", "error"], Ff = { datasources: (e10, { datasourceNames: r }) => {
  if (e10) {
    if (typeof e10 != "object" || Array.isArray(e10)) throw new k(`Invalid value ${JSON.stringify(e10)} for "datasources" provided to PrismaClient constructor`);
    for (let [t, n] of Object.entries(e10)) {
      if (!r.includes(t)) {
        let i = Wr(t, r) || ` Available datasources: ${r.join(", ")}`;
        throw new k(`Unknown datasource ${t} provided to PrismaClient constructor.${i}`);
      }
      if (typeof n != "object" || Array.isArray(n)) throw new k(`Invalid value ${JSON.stringify(e10)} for datasource "${t}" provided to PrismaClient constructor.
It should have this form: { url: "CONNECTION_STRING" }`);
      if (n && typeof n == "object") for (let [i, o] of Object.entries(n)) {
        if (i !== "url") throw new k(`Invalid value ${JSON.stringify(e10)} for datasource "${t}" provided to PrismaClient constructor.
It should have this form: { url: "CONNECTION_STRING" }`);
        if (typeof o != "string") throw new k(`Invalid value ${JSON.stringify(o)} for datasource "${t}" provided to PrismaClient constructor.
It should have this form: { url: "CONNECTION_STRING" }`);
      }
    }
  }
}, adapter: (e10, r) => {
  if (!e10 && Er(r.generator) === "client") throw new k('Using engine type "client" requires a driver adapter to be provided to PrismaClient constructor.');
  if (e10 === null) return;
  if (e10 === void 0) throw new k('"adapter" property must not be undefined, use null to conditionally disable driver adapters.');
  if (!Yn(r).includes("driverAdapters")) throw new k('"adapter" property can only be provided to PrismaClient constructor when "driverAdapters" preview feature is enabled.');
  if (Er(r.generator) === "binary") throw new k('Cannot use a driver adapter with the "binary" Query Engine. Please use the "library" Query Engine.');
}, datasourceUrl: (e10) => {
  if (typeof e10 < "u" && typeof e10 != "string") throw new k(`Invalid value ${JSON.stringify(e10)} for "datasourceUrl" provided to PrismaClient constructor.
Expected string or undefined.`);
}, errorFormat: (e10) => {
  if (e10) {
    if (typeof e10 != "string") throw new k(`Invalid value ${JSON.stringify(e10)} for "errorFormat" provided to PrismaClient constructor.`);
    if (!au.includes(e10)) {
      let r = Wr(e10, au);
      throw new k(`Invalid errorFormat ${e10} provided to PrismaClient constructor.${r}`);
    }
  }
}, log: (e10) => {
  if (!e10) return;
  if (!Array.isArray(e10)) throw new k(`Invalid value ${JSON.stringify(e10)} for "log" provided to PrismaClient constructor.`);
  function r(t) {
    if (typeof t == "string" && !lu.includes(t)) {
      let n = Wr(t, lu);
      throw new k(`Invalid log level "${t}" provided to PrismaClient constructor.${n}`);
    }
  }
  for (let t of e10) {
    r(t);
    let n = { level: r, emit: (i) => {
      let o = ["stdout", "event"];
      if (!o.includes(i)) {
        let s = Wr(i, o);
        throw new k(`Invalid value ${JSON.stringify(i)} for "emit" in logLevel provided to PrismaClient constructor.${s}`);
      }
    } };
    if (t && typeof t == "object") for (let [i, o] of Object.entries(t)) if (n[i]) n[i](o);
    else throw new k(`Invalid property ${i} for "log" provided to PrismaClient constructor`);
  }
}, transactionOptions: (e10) => {
  if (!e10) return;
  let r = e10.maxWait;
  if (r != null && r <= 0) throw new k(`Invalid value ${r} for maxWait in "transactionOptions" provided to PrismaClient constructor. maxWait needs to be greater than 0`);
  let t = e10.timeout;
  if (t != null && t <= 0) throw new k(`Invalid value ${t} for timeout in "transactionOptions" provided to PrismaClient constructor. timeout needs to be greater than 0`);
}, omit: (e10, r) => {
  if (typeof e10 != "object") throw new k('"omit" option is expected to be an object.');
  if (e10 === null) throw new k('"omit" option can not be `null`');
  let t = [];
  for (let [n, i] of Object.entries(e10)) {
    let o = $f(n, r.runtimeDataModel);
    if (!o) {
      t.push({ kind: "UnknownModel", modelKey: n });
      continue;
    }
    for (let [s, a] of Object.entries(i)) {
      let l = o.fields.find((u) => u.name === s);
      if (!l) {
        t.push({ kind: "UnknownField", modelKey: n, fieldName: s });
        continue;
      }
      if (l.relationName) {
        t.push({ kind: "RelationInOmit", modelKey: n, fieldName: s });
        continue;
      }
      typeof a != "boolean" && t.push({ kind: "InvalidFieldValue", modelKey: n, fieldName: s });
    }
  }
  if (t.length > 0) throw new k(qf(e10, t));
}, __internal: (e10) => {
  if (!e10) return;
  let r = ["debug", "engine", "configOverride"];
  if (typeof e10 != "object") throw new k(`Invalid value ${JSON.stringify(e10)} for "__internal" to PrismaClient constructor`);
  for (let [t] of Object.entries(e10)) if (!r.includes(t)) {
    let n = Wr(t, r);
    throw new k(`Invalid property ${JSON.stringify(t)} for "__internal" provided to PrismaClient constructor.${n}`);
  }
} };
function pu(e10, r) {
  for (let [t, n] of Object.entries(e10)) {
    if (!su.includes(t)) {
      let i = Wr(t, su);
      throw new k(`Unknown property ${t} provided to PrismaClient constructor.${i}`);
    }
    Ff[t](n, r);
  }
  if (e10.datasourceUrl && e10.datasources) throw new k('Can not use "datasourceUrl" and "datasources" options at the same time. Pick one of them');
}
function Wr(e10, r) {
  if (r.length === 0 || typeof e10 != "string") return "";
  let t = Mf(e10, r);
  return t ? ` Did you mean "${t}"?` : "";
}
function Mf(e10, r) {
  if (r.length === 0) return null;
  let t = r.map((i) => ({ value: i, distance: (0, cu.default)(e10, i) }));
  t.sort((i, o) => i.distance < o.distance ? -1 : 1);
  let n = t[0];
  return n.distance < 3 ? n.value : null;
}
function $f(e10, r) {
  var _a3;
  return (_a3 = uu(r.models, e10)) != null ? _a3 : uu(r.types, e10);
}
function uu(e10, r) {
  let t = Object.keys(e10).find((n) => We(n) === r);
  if (t) return e10[t];
}
function qf(e10, r) {
  var _a3, _b2, _c3, _d3;
  let t = kr(e10);
  for (let o of r) switch (o.kind) {
    case "UnknownModel":
      (_a3 = t.arguments.getField(o.modelKey)) == null ? void 0 : _a3.markAsError(), t.addErrorMessage(() => `Unknown model name: ${o.modelKey}.`);
      break;
    case "UnknownField":
      (_b2 = t.arguments.getDeepField([o.modelKey, o.fieldName])) == null ? void 0 : _b2.markAsError(), t.addErrorMessage(() => `Model "${o.modelKey}" does not have a field named "${o.fieldName}".`);
      break;
    case "RelationInOmit":
      (_c3 = t.arguments.getDeepField([o.modelKey, o.fieldName])) == null ? void 0 : _c3.markAsError(), t.addErrorMessage(() => 'Relations are already excluded by default and can not be specified in "omit".');
      break;
    case "InvalidFieldValue":
      (_d3 = t.arguments.getDeepFieldValue([o.modelKey, o.fieldName])) == null ? void 0 : _d3.markAsError(), t.addErrorMessage(() => "Omit field option value must be a boolean.");
      break;
  }
  let { message: n, args: i } = kn(t, "colorless");
  return `Error validating "omit" option:

${i}

${n}`;
}
function du(e10) {
  return e10.length === 0 ? Promise.resolve([]) : new Promise((r, t) => {
    let n = new Array(e10.length), i = null, o = false, s = 0, a = () => {
      o || (s++, s === e10.length && (o = true, i ? t(i) : r(n)));
    }, l = (u) => {
      o || (o = true, t(u));
    };
    for (let u = 0; u < e10.length; u++) e10[u].then((c) => {
      n[u] = c, a();
    }, (c) => {
      if (!zn(c)) {
        l(c);
        return;
      }
      c.batchRequestIdx === u ? l(c) : (i || (i = c), a());
    });
  });
}
var rr = N("prisma:client");
typeof globalThis == "object" && (globalThis.NODE_CLIENT = true);
var Vf = { requestArgsToMiddlewareArgs: (e10) => e10, middlewareArgsToRequestArgs: (e10) => e10 }, jf = Symbol.for("prisma.client.transaction.id"), Bf = { id: 0, nextId() {
  return ++this.id;
} };
function bu(e10) {
  class r {
    constructor(n) {
      __publicField(this, "_originalClient", this);
      __publicField(this, "_runtimeDataModel");
      __publicField(this, "_requestHandler");
      __publicField(this, "_connectionPromise");
      __publicField(this, "_disconnectionPromise");
      __publicField(this, "_engineConfig");
      __publicField(this, "_accelerateEngineConfig");
      __publicField(this, "_clientVersion");
      __publicField(this, "_errorFormat");
      __publicField(this, "_tracingHelper");
      __publicField(this, "_previewFeatures");
      __publicField(this, "_activeProvider");
      __publicField(this, "_globalOmit");
      __publicField(this, "_extensions");
      __publicField(this, "_engine");
      __publicField(this, "_appliedParent");
      __publicField(this, "_createPrismaPromise", Ao());
      __publicField(this, "$metrics", new Nr(this));
      __publicField(this, "$extends", Ya);
      var _a3, _b2, _c3, _d3, _e5, _f3, _g2, _h2, _i3, _j2, _k2, _l3, _m3;
      e10 = (_c3 = (_b2 = (_a3 = n == null ? void 0 : n.__internal) == null ? void 0 : _a3.configOverride) == null ? void 0 : _b2.call(_a3, e10)) != null ? _c3 : e10, cl(e10), n && pu(n, e10);
      let i = new hu.EventEmitter().on("error", () => {
      });
      this._extensions = _r.empty(), this._previewFeatures = Yn(e10), this._clientVersion = (_d3 = e10.clientVersion) != null ? _d3 : ou, this._activeProvider = e10.activeProvider, this._globalOmit = n == null ? void 0 : n.omit, this._tracingHelper = Zl();
      let o = e10.relativeEnvPaths && { rootEnvPath: e10.relativeEnvPaths.rootEnvPath && ri.default.resolve(e10.dirname, e10.relativeEnvPaths.rootEnvPath), schemaEnvPath: e10.relativeEnvPaths.schemaEnvPath && ri.default.resolve(e10.dirname, e10.relativeEnvPaths.schemaEnvPath) }, s;
      if (n == null ? void 0 : n.adapter) {
        s = n.adapter;
        let l = e10.activeProvider === "postgresql" || e10.activeProvider === "cockroachdb" ? "postgres" : e10.activeProvider;
        if (s.provider !== l) throw new P(`The Driver Adapter \`${s.adapterName}\`, based on \`${s.provider}\`, is not compatible with the provider \`${l}\` specified in the Prisma schema.`, this._clientVersion);
        if (n.datasources || n.datasourceUrl !== void 0) throw new P("Custom datasource configuration is not compatible with Prisma Driver Adapters. Please define the database connection string directly in the Driver Adapter configuration.", this._clientVersion);
      }
      let a = !s && o && ot(o, { conflictCheck: "none" }) || ((_e5 = e10.injectableEdgeEnv) == null ? void 0 : _e5.call(e10));
      try {
        let l = n != null ? n : {}, u = (_f3 = l.__internal) != null ? _f3 : {}, c = u.debug === true;
        c && N.enable("prisma:client");
        let p = ri.default.resolve(e10.dirname, e10.relativePath);
        yu.default.existsSync(p) || (p = e10.dirname), rr("dirname", e10.dirname), rr("relativePath", e10.relativePath), rr("cwd", p);
        let d = u.engine || {};
        if (l.errorFormat ? this._errorFormat = l.errorFormat : true ? this._errorFormat = "minimal" : process.env.NO_COLOR ? this._errorFormat = "colorless" : this._errorFormat = "colorless", this._runtimeDataModel = e10.runtimeDataModel, this._engineConfig = { cwd: p, dirname: e10.dirname, enableDebugLogs: c, allowTriggerPanic: d.allowTriggerPanic, prismaPath: (_g2 = d.binaryPath) != null ? _g2 : void 0, engineEndpoint: d.endpoint, generator: e10.generator, showColors: this._errorFormat === "pretty", logLevel: l.log && eu(l.log), logQueries: l.log && !!(typeof l.log == "string" ? l.log === "query" : l.log.find((f) => typeof f == "string" ? f === "query" : f.level === "query")), env: (_h2 = a == null ? void 0 : a.parsed) != null ? _h2 : {}, flags: [], engineWasm: e10.engineWasm, compilerWasm: e10.compilerWasm, clientVersion: e10.clientVersion, engineVersion: e10.engineVersion, previewFeatures: this._previewFeatures, activeProvider: e10.activeProvider, inlineSchema: e10.inlineSchema, overrideDatasources: pl(l, e10.datasourceNames), inlineDatasources: e10.inlineDatasources, inlineSchemaHash: e10.inlineSchemaHash, tracingHelper: this._tracingHelper, transactionOptions: { maxWait: (_j2 = (_i3 = l.transactionOptions) == null ? void 0 : _i3.maxWait) != null ? _j2 : 2e3, timeout: (_l3 = (_k2 = l.transactionOptions) == null ? void 0 : _k2.timeout) != null ? _l3 : 5e3, isolationLevel: (_m3 = l.transactionOptions) == null ? void 0 : _m3.isolationLevel }, logEmitter: i, isBundled: e10.isBundled, adapter: s }, this._accelerateEngineConfig = { ...this._engineConfig, accelerateUtils: { resolveDatasourceUrl: Vr, getBatchRequestPayload: Fr, prismaGraphQLToJSError: Mr, PrismaClientUnknownRequestError: V, PrismaClientInitializationError: P, PrismaClientKnownRequestError: z, debug: N("prisma:client:accelerateEngine"), engineVersion: fu.version, clientVersion: e10.clientVersion } }, rr("clientVersion", e10.clientVersion), this._engine = jl(e10, this._engineConfig), this._requestHandler = new ei(this, i), l.log) for (let f of l.log) {
          let h = typeof f == "string" ? f : f.emit === "stdout" ? f.level : null;
          h && this.$on(h, (g) => {
            var _a4;
            tt.log(`${(_a4 = tt.tags[h]) != null ? _a4 : ""}`, g.message || g.query);
          });
        }
      } catch (l) {
        throw l.clientVersion = this._clientVersion, l;
      }
      return this._appliedParent = vt(this);
    }
    get [Symbol.toStringTag]() {
      return "PrismaClient";
    }
    $on(n, i) {
      return n === "beforeExit" ? this._engine.onBeforeExit(i) : n && this._engineConfig.logEmitter.on(n, i), this;
    }
    $connect() {
      try {
        return this._engine.start();
      } catch (n) {
        throw n.clientVersion = this._clientVersion, n;
      }
    }
    async $disconnect() {
      try {
        await this._engine.stop();
      } catch (n) {
        throw n.clientVersion = this._clientVersion, n;
      } finally {
        Go();
      }
    }
    $executeRawInternal(n, i, o, s) {
      let a = this._activeProvider;
      return this._request({ action: "executeRaw", args: o, transaction: n, clientMethod: i, argsMapper: Ro({ clientMethod: i, activeProvider: a }), callsite: Ze(this._errorFormat), dataPath: [], middlewareArgsMapper: s });
    }
    $executeRaw(n, ...i) {
      return this._createPrismaPromise((o) => {
        if (n.raw !== void 0 || n.sql !== void 0) {
          let [s, a] = mu(n, i);
          return So(this._activeProvider, s.text, s.values, Array.isArray(n) ? "prisma.$executeRaw`<SQL>`" : "prisma.$executeRaw(sql`<SQL>`)"), this.$executeRawInternal(o, "$executeRaw", s, a);
        }
        throw new Z("`$executeRaw` is a tag function, please use it like the following:\n```\nconst result = await prisma.$executeRaw`UPDATE User SET cool = ${true} WHERE email = ${'user@email.com'};`\n```\n\nOr read our docs at https://www.prisma.io/docs/concepts/components/prisma-client/raw-database-access#executeraw\n", { clientVersion: this._clientVersion });
      });
    }
    $executeRawUnsafe(n, ...i) {
      return this._createPrismaPromise((o) => (So(this._activeProvider, n, i, "prisma.$executeRawUnsafe(<SQL>, [...values])"), this.$executeRawInternal(o, "$executeRawUnsafe", [n, ...i])));
    }
    $runCommandRaw(n) {
      if (e10.activeProvider !== "mongodb") throw new Z(`The ${e10.activeProvider} provider does not support $runCommandRaw. Use the mongodb provider.`, { clientVersion: this._clientVersion });
      return this._createPrismaPromise((i) => this._request({ args: n, clientMethod: "$runCommandRaw", dataPath: [], action: "runCommandRaw", argsMapper: Bl, callsite: Ze(this._errorFormat), transaction: i }));
    }
    async $queryRawInternal(n, i, o, s) {
      let a = this._activeProvider;
      return this._request({ action: "queryRaw", args: o, transaction: n, clientMethod: i, argsMapper: Ro({ clientMethod: i, activeProvider: a }), callsite: Ze(this._errorFormat), dataPath: [], middlewareArgsMapper: s });
    }
    $queryRaw(n, ...i) {
      return this._createPrismaPromise((o) => {
        if (n.raw !== void 0 || n.sql !== void 0) return this.$queryRawInternal(o, "$queryRaw", ...mu(n, i));
        throw new Z("`$queryRaw` is a tag function, please use it like the following:\n```\nconst result = await prisma.$queryRaw`SELECT * FROM User WHERE id = ${1} OR email = ${'user@email.com'};`\n```\n\nOr read our docs at https://www.prisma.io/docs/concepts/components/prisma-client/raw-database-access#queryraw\n", { clientVersion: this._clientVersion });
      });
    }
    $queryRawTyped(n) {
      return this._createPrismaPromise((i) => {
        if (!this._hasPreviewFlag("typedSql")) throw new Z("`typedSql` preview feature must be enabled in order to access $queryRawTyped API", { clientVersion: this._clientVersion });
        return this.$queryRawInternal(i, "$queryRawTyped", n);
      });
    }
    $queryRawUnsafe(n, ...i) {
      return this._createPrismaPromise((o) => this.$queryRawInternal(o, "$queryRawUnsafe", [n, ...i]));
    }
    _transactionWithArray({ promises: n, options: i }) {
      let o = Bf.nextId(), s = Xl(n.length), a = n.map((l, u) => {
        var _a3, _b2, _c3;
        if ((l == null ? void 0 : l[Symbol.toStringTag]) !== "PrismaPromise") throw new Error("All elements of the array need to be Prisma Client promises. Hint: Please make sure you are not awaiting the Prisma client calls you intended to pass in the $transaction function.");
        let c = (_a3 = i == null ? void 0 : i.isolationLevel) != null ? _a3 : this._engineConfig.transactionOptions.isolationLevel, p = { kind: "batch", id: o, index: u, isolationLevel: c, lock: s };
        return (_c3 = (_b2 = l.requestTransaction) == null ? void 0 : _b2.call(l, p)) != null ? _c3 : l;
      });
      return du(a);
    }
    async _transactionWithCallback({ callback: n, options: i }) {
      var _a3, _b2, _c3;
      let o = { traceparent: this._tracingHelper.getTraceParent() }, s = { maxWait: (_a3 = i == null ? void 0 : i.maxWait) != null ? _a3 : this._engineConfig.transactionOptions.maxWait, timeout: (_b2 = i == null ? void 0 : i.timeout) != null ? _b2 : this._engineConfig.transactionOptions.timeout, isolationLevel: (_c3 = i == null ? void 0 : i.isolationLevel) != null ? _c3 : this._engineConfig.transactionOptions.isolationLevel }, a = await this._engine.transaction("start", o, s), l;
      try {
        let u = { kind: "itx", ...a };
        l = await n(this._createItxClient(u)), await this._engine.transaction("commit", o, a);
      } catch (u) {
        throw await this._engine.transaction("rollback", o, a).catch(() => {
        }), u;
      }
      return l;
    }
    _createItxClient(n) {
      return he(vt(he(Ha(this), [re("_appliedParent", () => this._appliedParent._createItxClient(n)), re("_createPrismaPromise", () => Ao(n)), re(jf, () => n.id)])), [Lr(el)]);
    }
    $transaction(n, i) {
      var _a3;
      let o;
      typeof n == "function" ? ((_a3 = this._engineConfig.adapter) == null ? void 0 : _a3.adapterName) === "@prisma/adapter-d1" ? o = () => {
        throw new Error("Cloudflare D1 does not support interactive transactions. We recommend you to refactor your queries with that limitation in mind, and use batch transactions with `prisma.$transactions([])` where applicable.");
      } : o = () => this._transactionWithCallback({ callback: n, options: i }) : o = () => this._transactionWithArray({ promises: n, options: i });
      let s = { name: "transaction", attributes: { method: "$transaction" } };
      return this._tracingHelper.runInChildSpan(s, o);
    }
    _request(n) {
      var _a3;
      n.otelParentCtx = this._tracingHelper.getActiveContext();
      let i = (_a3 = n.middlewareArgsMapper) != null ? _a3 : Vf, o = { args: i.requestArgsToMiddlewareArgs(n.args), dataPath: n.dataPath, runInTransaction: !!n.transaction, action: n.action, model: n.model }, s = { operation: { name: "operation", attributes: { method: o.action, model: o.model, name: o.model ? `${o.model}.${o.action}` : o.action } } }, a = async (l) => {
        let { runInTransaction: u, args: c, ...p } = l, d = { ...n, ...p };
        c && (d.args = i.middlewareArgsToRequestArgs(c)), n.transaction !== void 0 && u === false && delete d.transaction;
        let f = await il(this, d);
        return d.model ? Xa({ result: f, modelName: d.model, args: d.args, extensions: this._extensions, runtimeDataModel: this._runtimeDataModel, globalOmit: this._globalOmit }) : f;
      };
      return this._tracingHelper.runInChildSpan(s.operation, () => new gu.AsyncResource("prisma-client-request").runInAsyncScope(() => a(o)));
    }
    async _executeRequest({ args: n, clientMethod: i, dataPath: o, callsite: s, action: a, model: l, argsMapper: u, transaction: c, unpacker: p, otelParentCtx: d, customDataProxyFetch: f }) {
      try {
        n = u ? u(n) : n;
        let h = { name: "serialize" }, g = this._tracingHelper.runInChildSpan(h, () => Mn({ modelName: l, runtimeDataModel: this._runtimeDataModel, action: a, args: n, clientMethod: i, callsite: s, extensions: this._extensions, errorFormat: this._errorFormat, clientVersion: this._clientVersion, previewFeatures: this._previewFeatures, globalOmit: this._globalOmit }));
        return N.enabled("prisma:client") && (rr("Prisma Client call:"), rr(`prisma.${i}(${$a(n)})`), rr("Generated request:"), rr(JSON.stringify(g, null, 2) + `
`)), (c == null ? void 0 : c.kind) === "batch" && await c.lock, this._requestHandler.request({ protocolQuery: g, modelName: l, action: a, clientMethod: i, dataPath: o, callsite: s, args: n, extensions: this._extensions, transaction: c, unpacker: p, otelParentCtx: d, otelChildCtx: this._tracingHelper.getActiveContext(), globalOmit: this._globalOmit, customDataProxyFetch: f });
      } catch (h) {
        throw h.clientVersion = this._clientVersion, h;
      }
    }
    _hasPreviewFlag(n) {
      var _a3;
      return !!((_a3 = this._engineConfig.previewFeatures) == null ? void 0 : _a3.includes(n));
    }
    $applyPendingMigrations() {
      return this._engine.applyPendingMigrations();
    }
  }
  return r;
}
function mu(e10, r) {
  return Uf(e10) ? [new oe(e10, r), Hl] : [e10, Yl];
}
function Uf(e10) {
  return Array.isArray(e10) && Array.isArray(e10.raw);
}
var Gf = /* @__PURE__ */ new Set(["toJSON", "$$typeof", "asymmetricMatch", Symbol.iterator, Symbol.toStringTag, Symbol.isConcatSpreadable, Symbol.toPrimitive]);
function Eu(e10) {
  return new Proxy(e10, { get(r, t) {
    if (t in r) return r[t];
    if (!Gf.has(t)) throw new TypeError(`Invalid enum value: ${String(t)}`);
  } });
}
function wu(e10) {
  ot(e10, { conflictCheck: "warn" });
}

const require$$1 = /*@__PURE__*/getDefaultExportFromNamespaceIfNotNamed(path);

const require$$2 = /*@__PURE__*/getDefaultExportFromNamespaceIfNotNamed(fs$1);

(function (exports) {
	var _a;
	Object.defineProperty(exports, "__esModule", { value: true });
	const {
	  PrismaClientKnownRequestError,
	  PrismaClientUnknownRequestError,
	  PrismaClientRustPanicError,
	  PrismaClientInitializationError,
	  PrismaClientValidationError,
	  getPrismaClient,
	  sqltag,
	  empty,
	  join,
	  raw,
	  skip,
	  Decimal,
	  Debug,
	  objectEnumValues,
	  makeStrictEnum,
	  Extensions,
	  warnOnce,
	  defineDmmfProperty,
	  Public,
	  getRuntime,
	  createParam
	} = library;
	const Prisma = {};
	exports.Prisma = Prisma;
	exports.$Enums = {};
	Prisma.prismaVersion = {
	  client: "6.15.0",
	  engine: "85179d7826409ee107a6ba334b5e305ae3fba9fb"
	};
	Prisma.PrismaClientKnownRequestError = PrismaClientKnownRequestError;
	Prisma.PrismaClientUnknownRequestError = PrismaClientUnknownRequestError;
	Prisma.PrismaClientRustPanicError = PrismaClientRustPanicError;
	Prisma.PrismaClientInitializationError = PrismaClientInitializationError;
	Prisma.PrismaClientValidationError = PrismaClientValidationError;
	Prisma.Decimal = Decimal;
	Prisma.sql = sqltag;
	Prisma.empty = empty;
	Prisma.join = join;
	Prisma.raw = raw;
	Prisma.validator = Public.validator;
	Prisma.getExtensionContext = Extensions.getExtensionContext;
	Prisma.defineExtension = Extensions.defineExtension;
	Prisma.DbNull = objectEnumValues.instances.DbNull;
	Prisma.JsonNull = objectEnumValues.instances.JsonNull;
	Prisma.AnyNull = objectEnumValues.instances.AnyNull;
	Prisma.NullTypes = {
	  DbNull: objectEnumValues.classes.DbNull,
	  JsonNull: objectEnumValues.classes.JsonNull,
	  AnyNull: objectEnumValues.classes.AnyNull
	};
	const path = require$$1;
	exports.Prisma.TransactionIsolationLevel = makeStrictEnum({
	  ReadUncommitted: "ReadUncommitted",
	  ReadCommitted: "ReadCommitted",
	  RepeatableRead: "RepeatableRead",
	  Serializable: "Serializable"
	});
	exports.Prisma.UserScalarFieldEnum = {
	  id: "id",
	  email: "email",
	  name: "name",
	  password: "password",
	  createdAt: "createdAt",
	  updatedAt: "updatedAt"
	};
	exports.Prisma.SortOrder = {
	  asc: "asc",
	  desc: "desc"
	};
	exports.Prisma.QueryMode = {
	  default: "default",
	  insensitive: "insensitive"
	};
	exports.Prisma.ModelName = {
	  User: "User"
	};
	const config = {
	  "generator": {
	    "name": "client",
	    "provider": {
	      "fromEnvVar": null,
	      "value": "prisma-client-js"
	    },
	    "output": {
	      "value": "/Users/alisherkhan/Desktop/development/invoice-app-nuxt/lib/generated/prisma",
	      "fromEnvVar": null
	    },
	    "config": {
	      "engineType": "library"
	    },
	    "binaryTargets": [
	      {
	        "fromEnvVar": null,
	        "value": "darwin-arm64",
	        "native": true
	      }
	    ],
	    "previewFeatures": [],
	    "sourceFilePath": "/Users/alisherkhan/Desktop/development/invoice-app-nuxt/prisma/schema.prisma",
	    "isCustomOutput": true
	  },
	  "relativeEnvPaths": {
	    "rootEnvPath": null,
	    "schemaEnvPath": "../../../.env"
	  },
	  "relativePath": "../../../prisma",
	  "clientVersion": "6.15.0",
	  "engineVersion": "85179d7826409ee107a6ba334b5e305ae3fba9fb",
	  "datasourceNames": [
	    "db"
	  ],
	  "activeProvider": "postgresql",
	  "postinstall": true,
	  "inlineDatasources": {
	    "db": {
	      "url": {
	        "fromEnvVar": "DATABASE_URL",
	        "value": null
	      }
	    }
	  },
	  "inlineSchema": '// This is your Prisma schema file,\n// learn more about it in the docs: https://pris.ly/d/prisma-schema\n\n// Looking for ways to speed up your queries, or scale easily with your serverless or edge functions?\n// Try Prisma Accelerate: https://pris.ly/cli/accelerate-init\n\ngenerator client {\n  provider = "prisma-client-js"\n  output   = "../lib/generated/prisma"\n}\n\ndatasource db {\n  provider = "postgresql"\n  url      = env("DATABASE_URL")\n}\n\nmodel User {\n  id        Int      @id @unique @default(autoincrement())\n  email     String   @unique\n  name      String\n  password  String\n  createdAt DateTime @default(now())\n  updatedAt DateTime @default(now()) @updatedAt\n}\n',
	  "inlineSchemaHash": "a14b200e1da9059bb75af7dfa64a7d838e9932934e895400d0639315894c2a44",
	  "copyEngine": true
	};
	const fs = require$$2;
	config.dirname = __dirname;
	if (!fs.existsSync(path.join(__dirname, "schema.prisma"))) {
	  const alternativePaths = [
	    "lib/generated/prisma",
	    "generated/prisma"
	  ];
	  const alternativePath = (_a = alternativePaths.find((altPath) => {
	    return fs.existsSync(path.join(process.cwd(), altPath, "schema.prisma"));
	  })) != null ? _a : alternativePaths[0];
	  config.dirname = path.join(process.cwd(), alternativePath);
	  config.isBundled = true;
	}
	config.runtimeDataModel = JSON.parse('{"models":{"User":{"dbName":null,"schema":null,"fields":[{"name":"id","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":true,"isReadOnly":false,"hasDefaultValue":true,"type":"Int","nativeType":null,"default":{"name":"autoincrement","args":[]},"isGenerated":false,"isUpdatedAt":false},{"name":"email","kind":"scalar","isList":false,"isRequired":true,"isUnique":true,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","nativeType":null,"isGenerated":false,"isUpdatedAt":false},{"name":"name","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","nativeType":null,"isGenerated":false,"isUpdatedAt":false},{"name":"password","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","nativeType":null,"isGenerated":false,"isUpdatedAt":false},{"name":"createdAt","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":true,"type":"DateTime","nativeType":null,"default":{"name":"now","args":[]},"isGenerated":false,"isUpdatedAt":false},{"name":"updatedAt","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":true,"type":"DateTime","nativeType":null,"default":{"name":"now","args":[]},"isGenerated":false,"isUpdatedAt":true}],"primaryKey":null,"uniqueFields":[],"uniqueIndexes":[],"isGenerated":false}},"enums":{},"types":{}}');
	defineDmmfProperty(exports.Prisma, config.runtimeDataModel);
	config.engineWasm = void 0;
	config.compilerWasm = void 0;
	const { warnEnvConflicts } = library;
	warnEnvConflicts({
	  rootEnvPath: config.relativeEnvPaths.rootEnvPath && path.resolve(config.dirname, config.relativeEnvPaths.rootEnvPath),
	  schemaEnvPath: config.relativeEnvPaths.schemaEnvPath && path.resolve(config.dirname, config.relativeEnvPaths.schemaEnvPath)
	});
	const PrismaClient = getPrismaClient(config);
	exports.PrismaClient = PrismaClient;
	Object.assign(exports, Prisma);
	path.join(__dirname, "libquery_engine-darwin-arm64.dylib.node");
	path.join(process.cwd(), "lib/generated/prisma/libquery_engine-darwin-arm64.dylib.node");
	path.join(__dirname, "schema.prisma");
	path.join(process.cwd(), "lib/generated/prisma/schema.prisma"); 
} (prisma$1));

let prisma;
{
  prisma = new prisma$1.PrismaClient();
}

const _1RV1Uq = lazyEventHandler(() => {
  const opts = useRuntimeConfig().ipx || {};
  const fsDir = opts?.fs?.dir ? (Array.isArray(opts.fs.dir) ? opts.fs.dir : [opts.fs.dir]).map((dir) => isAbsolute(dir) ? dir : fileURLToPath(new URL(dir, globalThis._importMeta_.url))) : void 0;
  const fsStorage = opts.fs?.dir ? ipxFSStorage({ ...opts.fs, dir: fsDir }) : void 0;
  const httpStorage = opts.http?.domains ? ipxHttpStorage({ ...opts.http }) : void 0;
  if (!fsStorage && !httpStorage) {
    throw new Error("IPX storage is not configured!");
  }
  const ipxOptions = {
    ...opts,
    storage: fsStorage || httpStorage,
    httpStorage
  };
  const ipx = createIPX(ipxOptions);
  const ipxHandler = createIPXH3Handler(ipx);
  return useBase(opts.baseURL, ipxHandler);
});

const _lazy_eQCL3h = () => import('../routes/api/auth/login.post.mjs');
const _lazy_YyJkl4 = () => import('../routes/api/auth/logout.post.mjs');
const _lazy_SqkgP8 = () => import('../routes/api/auth/me.get.mjs');
const _lazy__xkDZ2 = () => import('../routes/api/auth/register.post.mjs');
const _lazy_wpXq4C = () => import('../routes/renderer.mjs').then(function (n) { return n.r; });

const handlers = [
  { route: '', handler: _64KrsE, lazy: false, middleware: true, method: undefined },
  { route: '/api/auth/login', handler: _lazy_eQCL3h, lazy: true, middleware: false, method: "post" },
  { route: '/api/auth/logout', handler: _lazy_YyJkl4, lazy: true, middleware: false, method: "post" },
  { route: '/api/auth/me', handler: _lazy_SqkgP8, lazy: true, middleware: false, method: "get" },
  { route: '/api/auth/register', handler: _lazy__xkDZ2, lazy: true, middleware: false, method: "post" },
  { route: '/__nuxt_error', handler: _lazy_wpXq4C, lazy: true, middleware: false, method: undefined },
  { route: '/__nuxt_island/**', handler: _SxA8c9, lazy: false, middleware: false, method: undefined },
  { route: '/_ipx/**', handler: _1RV1Uq, lazy: false, middleware: false, method: undefined },
  { route: '/**', handler: _lazy_wpXq4C, lazy: true, middleware: false, method: undefined }
];

function createNitroApp() {
  const config = useRuntimeConfig();
  const hooks = createHooks();
  const captureError = (error, context = {}) => {
    const promise = hooks.callHookParallel("error", error, context).catch((error_) => {
      console.error("Error while capturing another error", error_);
    });
    if (context.event && isEvent(context.event)) {
      const errors = context.event.context.nitro?.errors;
      if (errors) {
        errors.push({ error, context });
      }
      if (context.event.waitUntil) {
        context.event.waitUntil(promise);
      }
    }
  };
  const h3App = createApp({
    debug: destr(false),
    onError: (error, event) => {
      captureError(error, { event, tags: ["request"] });
      return errorHandler(error, event);
    },
    onRequest: async (event) => {
      event.context.nitro = event.context.nitro || { errors: [] };
      const fetchContext = event.node.req?.__unenv__;
      if (fetchContext?._platform) {
        event.context = {
          _platform: fetchContext?._platform,
          // #3335
          ...fetchContext._platform,
          ...event.context
        };
      }
      if (!event.context.waitUntil && fetchContext?.waitUntil) {
        event.context.waitUntil = fetchContext.waitUntil;
      }
      event.fetch = (req, init) => fetchWithEvent(event, req, init, { fetch: localFetch });
      event.$fetch = (req, init) => fetchWithEvent(event, req, init, {
        fetch: $fetch
      });
      event.waitUntil = (promise) => {
        if (!event.context.nitro._waitUntilPromises) {
          event.context.nitro._waitUntilPromises = [];
        }
        event.context.nitro._waitUntilPromises.push(promise);
        if (event.context.waitUntil) {
          event.context.waitUntil(promise);
        }
      };
      event.captureError = (error, context) => {
        captureError(error, { event, ...context });
      };
      await nitroApp$1.hooks.callHook("request", event).catch((error) => {
        captureError(error, { event, tags: ["request"] });
      });
    },
    onBeforeResponse: async (event, response) => {
      await nitroApp$1.hooks.callHook("beforeResponse", event, response).catch((error) => {
        captureError(error, { event, tags: ["request", "response"] });
      });
    },
    onAfterResponse: async (event, response) => {
      await nitroApp$1.hooks.callHook("afterResponse", event, response).catch((error) => {
        captureError(error, { event, tags: ["request", "response"] });
      });
    }
  });
  const router = createRouter({
    preemptive: true
  });
  const nodeHandler = toNodeListener(h3App);
  const localCall = (aRequest) => b(
    nodeHandler,
    aRequest
  );
  const localFetch = (input, init) => {
    if (!input.toString().startsWith("/")) {
      return globalThis.fetch(input, init);
    }
    return C$1(
      nodeHandler,
      input,
      init
    ).then((response) => normalizeFetchResponse(response));
  };
  const $fetch = createFetch({
    fetch: localFetch,
    Headers: Headers$1,
    defaults: { baseURL: config.app.baseURL }
  });
  globalThis.$fetch = $fetch;
  h3App.use(createRouteRulesHandler({ localFetch }));
  for (const h of handlers) {
    let handler = h.lazy ? lazyEventHandler(h.handler) : h.handler;
    if (h.middleware || !h.route) {
      const middlewareBase = (config.app.baseURL + (h.route || "/")).replace(
        /\/+/g,
        "/"
      );
      h3App.use(middlewareBase, handler);
    } else {
      const routeRules = getRouteRulesForPath(
        h.route.replace(/:\w+|\*\*/g, "_")
      );
      if (routeRules.cache) {
        handler = cachedEventHandler(handler, {
          group: "nitro/routes",
          ...routeRules.cache
        });
      }
      router.use(h.route, handler, h.method);
    }
  }
  h3App.use(config.app.baseURL, router.handler);
  const app = {
    hooks,
    h3App,
    router,
    localCall,
    localFetch,
    captureError
  };
  return app;
}
function runNitroPlugins(nitroApp2) {
  for (const plugin of plugins) {
    try {
      plugin(nitroApp2);
    } catch (error) {
      nitroApp2.captureError(error, { tags: ["plugin"] });
      throw error;
    }
  }
}
const nitroApp$1 = createNitroApp();
function useNitroApp() {
  return nitroApp$1;
}
runNitroPlugins(nitroApp$1);

const nitroApp = useNitroApp();
const handler = toNodeListener(nitroApp.h3App);
const listener = function(req, res) {
  const query = req.headers["x-now-route-matches"];
  if (query) {
    const { url } = parseQuery(query);
    if (url) {
      req.url = url;
    }
  }
  return handler(req, res);
};

export { $fetch as $, createRouter$1 as A, defu as B, withLeadingSlash as C, parseURL as D, encodeParam as E, encodePath as F, parseQuery as G, withTrailingSlash as H, withoutTrailingSlash as I, listener as J, getResponseStatusText as a, buildAssetsURL as b, createError$1 as c, defineEventHandler as d, getResponseStatus as e, defineRenderHandler as f, getCookie as g, publicAssetsURL as h, getQuery as i, getRouteRules as j, hasProtocol as k, relative as l, joinURL as m, useNitroApp as n, isScriptProtocol as o, prisma as p, sanitizeStatusCode as q, readBody as r, setCookie as s, getContext as t, useRuntimeConfig as u, baseURL as v, withQuery as w, createHooks as x, executeAsync as y, toRouteMatcher as z };
//# sourceMappingURL=nitro.mjs.map
