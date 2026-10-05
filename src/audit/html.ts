// A small, tolerant HTML scanner. It is not a full HTML5 parser: it reads the server-rendered
// markup the way a simple agent fetcher would, which is exactly what the audit wants to measure.

export type FieldKind = "email" | "tel" | "name" | "address" | "card" | "username" | "password" | "other";

export interface ParsedField {
  tag: "input" | "select" | "textarea";
  type: string;
  kind: FieldKind;
  hint: string;
  autocomplete?: string;
  labelled: boolean;
  placeholderOnly: boolean;
}

export interface ParsedForm {
  action?: string;
  method?: string;
  fields: ParsedField[];
  buttons: Array<{ named: boolean; text: string }>;
}

export interface ParsedPage {
  lang?: string;
  title?: string;
  description?: string;
  jsonLd: unknown[];
  jsonLdErrors: number;
  jsonLdTypes: string[];
  forms: ParsedForm[];
  textLength: number;
  needsJavaScript: boolean;
  challengeMarkers: string[];
}

const CHALLENGE_MARKERS: ReadonlyArray<[RegExp, string]> = [
  [/g-recaptcha|google\.com\/recaptcha|recaptcha\/(api|enterprise)\.js/i, "reCAPTCHA"],
  [/hcaptcha\.com|class=["'][^"']*h-captcha/i, "hCaptcha"],
  [/challenges\.cloudflare\.com\/turnstile|class=["'][^"']*cf-turnstile/i, "Cloudflare Turnstile"],
  [/\/cdn-cgi\/challenge-platform|cf-chl-|<title>\s*Just a moment\.\.\./i, "Cloudflare challenge page"],
  [/captcha-delivery\.com|geo\.captcha-delivery/i, "DataDome"],
  [/px-captcha|perimeterx|client\.px-cloud\.net/i, "HUMAN (PerimeterX)"],
  [/arkoselabs\.com|funcaptcha/i, "Arkose Labs"],
  [/awswaf\.com|aws-waf-token|captcha\.awswaf/i, "AWS WAF CAPTCHA"],
  [/ips\.js\?|kpsdk|kasada/i, "Kasada"],
];

export function detectChallengeMarkers(html: string): string[] {
  return CHALLENGE_MARKERS.filter(([re]) => re.test(html)).map(([, name]) => name);
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === "#") {
      const code = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : m;
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

function parseAttrs(src: string): Map<string, string> {
  const attrs = new Map<string, string>();
  const re = /([^\s"'>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src))) {
    const name = m[1]!.toLowerCase();
    if (!attrs.has(name)) attrs.set(name, decodeEntities(m[2] ?? m[3] ?? m[4] ?? ""));
  }
  return attrs;
}

function fieldKind(type: string, hint: string, autocomplete?: string): FieldKind {
  const h = `${hint} ${autocomplete ?? ""}`.toLowerCase();
  if (type === "password") return "password";
  if (type === "email" || /e-?mail/.test(h)) return "email";
  if (type === "tel" || /phone|\btel\b|mobile/.test(h)) return "tel";
  if (/\bcc-|card|cvc|cvv|csc|expir/.test(h)) return "card";
  if (/user(name)?\b|login|\buser_?id/.test(h)) return "username";
  if (/address|street|addr|line[12]|city|town|zip|postal|postcode|province|country|region|\bstate\b/.test(h)) return "address";
  if (/(first|last|full|given|family|sur)[-_ ]?name|^name$|\bname\b/.test(h)) return "name";
  return "other";
}

const SKIP_INPUT_TYPES = new Set(["hidden", "submit", "button", "reset", "image"]);

/** Remove a tag and everything inside it (scripts, styles...). */
function stripBlocks(html: string, tag: string): string {
  return html.replace(new RegExp(`<${tag}\\b[^>]*>[\\s\\S]*?</${tag}\\s*>`, "gi"), " ");
}

export function parseHtml(rawHtml: string): ParsedPage {
  const challengeMarkers = detectChallengeMarkers(rawHtml);
  let html = rawHtml.replace(/<!--[\s\S]*?-->/g, " ");

  // JSON-LD before scripts are stripped.
  const jsonLd: unknown[] = [];
  let jsonLdErrors = 0;
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
    const type = parseAttrs(m[1] ?? "").get("type")?.toLowerCase();
    if (type !== "application/ld+json") continue;
    try {
      jsonLd.push(JSON.parse(m[2]!.trim()));
    } catch {
      jsonLdErrors++;
    }
  }
  const jsonLdTypes = new Set<string>();
  const visit = (node: unknown): void => {
    if (Array.isArray(node)) return node.forEach(visit);
    if (!node || typeof node !== "object") return;
    const obj = node as Record<string, unknown>;
    const t = obj["@type"];
    if (typeof t === "string") jsonLdTypes.add(t);
    if (Array.isArray(t)) t.forEach((x) => typeof x === "string" && jsonLdTypes.add(x));
    if (obj["@graph"]) visit(obj["@graph"]);
  };
  jsonLd.forEach(visit);

  const noscript = [...html.matchAll(/<noscript\b[^>]*>([\s\S]*?)<\/noscript\s*>/gi)].map((m) => m[1] ?? "").join(" ");
  for (const tag of ["script", "style", "noscript", "template", "svg"]) html = stripBlocks(html, tag);

  const lang = /<html\b([^>]*)>/i.exec(html)?.[1];
  const page: ParsedPage = {
    lang: lang ? parseAttrs(lang).get("lang") || undefined : undefined,
    title: decodeEntities(/<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(html)?.[1]?.trim() ?? "") || undefined,
    jsonLd,
    jsonLdErrors,
    jsonLdTypes: [...jsonLdTypes],
    forms: [],
    textLength: 0,
    needsJavaScript: false,
    challengeMarkers,
  };
  for (const m of html.matchAll(/<meta\b([^>]*)>/gi)) {
    const a = parseAttrs(m[1] ?? "");
    if ((a.get("name") ?? "").toLowerCase() === "description" && a.get("content")) page.description = a.get("content");
  }

  // Visible text, as a non-rendering fetcher sees it.
  const bodyHtml = /<body\b[^>]*>([\s\S]*)<\/body\s*>/i.exec(html)?.[1] ?? html;
  const text = decodeEntities(bodyHtml.replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").trim();
  page.textLength = text.length;
  page.needsJavaScript = /enable javascript|requires javascript|javascript is (disabled|required)/i.test(noscript + " " + text);

  // Walk tags for forms, labels and buttons.
  const ids = new Set<string>();
  const labelFor = new Set<string>();
  const pendingById: Array<{ id: string; field: ParsedField }> = [];
  let form: ParsedForm | null = null;
  const looseForm: ParsedForm = { fields: [], buttons: [] };
  let labelDepth = 0;
  let button: { text: string; aria: boolean } | null = null;
  const placeholders = new WeakSet<ParsedField>();

  const tagRe = /<(\/?)([a-zA-Z][a-zA-Z0-9-]*)((?:\s+[^\s"'>\/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*)\s*(\/?)>|([^<]+)/g;
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(bodyHtml))) {
    if (m[5] !== undefined) {
      if (button) button.text += m[5];
      continue;
    }
    const closing = m[1] === "/";
    const tag = m[2]!.toLowerCase();
    const attrs = closing ? new Map<string, string>() : parseAttrs(m[3] ?? "");
    const id = attrs.get("id");
    if (id) ids.add(id);
    const target = form ?? looseForm;

    if (tag === "form") {
      if (closing) {
        if (form) page.forms.push(form);
        form = null;
      } else {
        if (form) page.forms.push(form);
        form = { action: attrs.get("action"), method: attrs.get("method")?.toLowerCase(), fields: [], buttons: [] };
      }
      continue;
    }
    if (tag === "label") {
      if (closing) labelDepth = Math.max(0, labelDepth - 1);
      else {
        labelDepth++;
        const f = attrs.get("for");
        if (f) labelFor.add(f);
      }
      continue;
    }
    if (tag === "button") {
      if (closing && button) {
        const t = decodeEntities(button.text).replace(/\s+/g, " ").trim();
        target.buttons.push({ named: button.aria || t.length > 0, text: t });
        button = null;
      } else if (!closing) {
        button = { text: "", aria: !!(attrs.get("aria-label")?.trim() || attrs.get("title")?.trim() || attrs.get("aria-labelledby")) };
      }
      continue;
    }
    if (closing) continue;
    if (tag === "img" && button && attrs.get("alt")?.trim()) button.text += ` ${attrs.get("alt")}`;
    if (tag !== "input" && tag !== "select" && tag !== "textarea") continue;

    const type = (tag === "input" ? attrs.get("type") ?? "text" : tag).toLowerCase();
    if (tag === "input" && (type === "submit" || type === "button" || type === "image")) {
      const named = !!(attrs.get("value")?.trim() || attrs.get("aria-label")?.trim() || attrs.get("alt")?.trim() || type === "submit");
      target.buttons.push({ named, text: attrs.get("value") ?? "" });
      continue;
    }
    if (SKIP_INPUT_TYPES.has(type)) continue;
    const hint = attrs.get("name") || id || attrs.get("placeholder") || "";
    const kindHint = [attrs.get("name"), id, attrs.get("placeholder")].filter(Boolean).join(" ");
    const autocomplete = attrs.get("autocomplete")?.trim().toLowerCase() || undefined;
    const hasAria = !!(attrs.get("aria-label")?.trim() || attrs.get("aria-labelledby")?.trim() || attrs.get("title")?.trim());
    const field: ParsedField = {
      tag: tag as ParsedField["tag"],
      type,
      kind: fieldKind(type, kindHint, autocomplete),
      hint: hint || "(unnamed)",
      autocomplete,
      labelled: labelDepth > 0 || hasAria,
      placeholderOnly: false,
    };
    if (attrs.get("placeholder")?.trim()) placeholders.add(field);
    if (!field.labelled && id) pendingById.push({ id, field });
    target.fields.push(field);
  }
  if (form) page.forms.push(form);
  if (looseForm.fields.length || looseForm.buttons.length) page.forms.push(looseForm);

  for (const { id, field } of pendingById) if (labelFor.has(id)) field.labelled = true;
  // A placeholder is not a label: it disappears on input and many agents ignore it.
  for (const f of page.forms.flatMap((x) => x.fields)) f.placeholderOnly = !f.labelled && placeholders.has(f);
  return page;
}

const VALID_AUTOCOMPLETE = /^(?:section-\S+\s+)?(?:shipping\s+|billing\s+)?(?:(?:home|work|mobile|fax|pager)\s+)?(name|honorific-prefix|given-name|additional-name|family-name|honorific-suffix|nickname|username|new-password|current-password|one-time-code|organization-title|organization|street-address|address-line[123]|address-level[1-4]|country|country-name|postal-code|cc-name|cc-given-name|cc-additional-name|cc-family-name|cc-number|cc-exp|cc-exp-month|cc-exp-year|cc-csc|cc-type|transaction-currency|transaction-amount|language|bday|bday-day|bday-month|bday-year|sex|url|photo|tel|tel-country-code|tel-national|tel-area-code|tel-local|tel-extension|email|impp|webauthn)(?:\s+webauthn)?$/;

/** True when the field carries a meaningful autocomplete token (not missing, "on" or "off"). */
export function hasUsefulAutocomplete(f: ParsedField): boolean {
  if (!f.autocomplete) return false;
  return VALID_AUTOCOMPLETE.test(f.autocomplete);
}
