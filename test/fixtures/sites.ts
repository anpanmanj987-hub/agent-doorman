// Two demo sites used by the audit tests and by `npm run demo`.
import type { IncomingMessage, ServerResponse } from "node:http";
import { createDoorman, nodeMiddleware, presets } from "../../src/node.js";

const PRODUCT_JSONLD = JSON.stringify({
  "@context": "https://schema.org",
  "@type": "Product",
  name: "Brass door plaque",
  sku: "PLQ-1",
  offers: { "@type": "Offer", price: "49.00", priceCurrency: "USD", availability: "https://schema.org/InStock" },
});

const LONG_TEXT =
  "Hand-finished brass plaques for front doors, offices and hotel lobbies. Every plaque is cut, engraved and polished in our workshop, then sealed so it keeps its colour outdoors. Choose a size, pick a typeface and preview your text before you order. Free delivery on orders over fifty dollars, and returns within thirty days if the engraving is not what you expected.";

export function protectedHtml(path: string): string | null {
  if (path === "/") {
    return `<!doctype html><html lang="en"><head><title>Plaque & Co. | Engraved brass plaques</title>
<meta name="description" content="Engraved brass door plaques made to order.">
<script type="application/ld+json">${PRODUCT_JSONLD}</script></head>
<body><h1>Engraved brass plaques</h1><p>${LONG_TEXT}</p><a href="/checkout">Checkout</a></body></html>`;
  }
  if (path === "/checkout") {
    return `<!doctype html><html lang="en"><head><title>Checkout | Plaque & Co.</title>
<meta name="description" content="Pay for your plaque."></head><body><h1>Checkout</h1><p>${LONG_TEXT}</p>
<form method="post" action="/checkout/pay">
<label for="email">Email</label><input id="email" name="email" type="email" autocomplete="email">
<label for="tel">Phone</label><input id="tel" name="phone" type="tel" autocomplete="tel">
<label>Full name <input name="name" autocomplete="name"></label>
<label for="street">Street address</label><input id="street" name="street" autocomplete="shipping street-address">
<label for="zip">Postal code</label><input id="zip" name="zip" autocomplete="shipping postal-code">
<label for="cc">Card number</label><input id="cc" name="cardnumber" autocomplete="cc-number" inputmode="numeric">
<button type="submit">Pay $49.00</button>
</form></body></html>`;
  }
  return null;
}

export function protectedSite(publicJwk: JsonWebKey, options: { trustProxy?: boolean } = {}) {
  const doorman = createDoorman({
    policy: presets.ecommerce(),
    mode: "enforce",
    trustProxy: options.trustProxy ?? false,
    verify: { keys: [{ jwk: publicJwk, name: "Audit test agent" }], directory: false },
  });
  const mw = nodeMiddleware(doorman);
  return async (req: IncomingMessage, res: ServerResponse) => {
    await mw(req, res, () => {
      const path = new URL(req.url ?? "/", "http://x").pathname;
      if (path === "/robots.txt") {
        res.setHeader("content-type", "text/plain");
        res.end("User-agent: *\nAllow: /\n\nUser-agent: GPTBot\nDisallow: /checkout\n\nSitemap: https://plaque.example/sitemap.xml\n");
        return;
      }
      if (path === "/llms.txt") {
        res.setHeader("content-type", "text/markdown");
        res.end("# Plaque & Co.\n\n> Engraved brass plaques.\n");
        return;
      }
      const html = protectedHtml(path);
      if (!html) {
        res.statusCode = 404;
        res.end("not found");
        return;
      }
      res.setHeader("content-type", "text/html; charset=utf-8");
      res.end(html);
    });
  };
}

/** Typical "protected by User-Agent rules" site with a JS-only shell and an inaccessible form. */
export function naiveSite() {
  return (req: IncomingMessage, res: ServerResponse) => {
    const ua = req.headers["user-agent"] ?? "";
    const path = new URL(req.url ?? "/", "http://x").pathname;
    const trustedBot = /GPTBot|ClaudeBot|PerplexityBot|ChatGPT-User|meta-externalagent/i.test(ua);
    if (!trustedBot && /python-requests|curl|HeadlessChrome/i.test(ua)) {
      res.statusCode = 403;
      res.setHeader("content-type", "text/html");
      res.end("<html><body><h1>Access denied</h1></body></html>");
      return;
    }
    res.setHeader("content-type", "text/html; charset=utf-8");
    if (path === "/") {
      res.end(`<!doctype html><html><head><title>Shop</title></head><body><div id="root"></div>
<noscript>You need to enable JavaScript to run this app.</noscript><script src="/app.js"></script></body></html>`);
      return;
    }
    if (path === "/signup") {
      res.end(`<!doctype html><html><head><title>Sign up</title></head><body><h1>Create account</h1>
<script src="https://www.google.com/recaptcha/api.js"></script>
<form method="post"><input name="email" type="text" placeholder="Email"><input name="phone" placeholder="Phone">
<input name="first_name" placeholder="First name"><input name="password" type="password" autocomplete="off">
<div class="g-recaptcha" data-sitekey="x"></div><button><svg viewBox="0 0 1 1"></svg></button></form></body></html>`);
      return;
    }
    res.statusCode = 404;
    res.end("not found");
  };
}
