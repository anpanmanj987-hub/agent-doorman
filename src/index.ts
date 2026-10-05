// agent-doorman: runtime-agnostic entry point (Workers, Next.js middleware, Deno, Bun, Node).
// Node-specific helpers (http middleware, DNS-aware SSRF guard, file logging) live in "agent-doorman/node".

export { createDoorman, classify, jsonLines, POLICY_PATH, SPEC_URL } from "./gate/doorman.js";
export type { Action, Decision, Doorman, DoormanOptions, TrustInfo } from "./gate/doorman.js";

export {
  compilePolicy,
  parseRate,
  presets,
  publicPolicyDocument,
  TRUST_CLASSES,
  TRUST_CLASS_DESCRIPTIONS,
  validatePolicy,
  PolicyError,
} from "./gate/policy.js";
export type { Policy, PolicyRule, PresetName, TrustClass } from "./gate/policy.js";

export { createMemoryRateLimitStore } from "./gate/ratelimit.js";
export type { RateLimitStore } from "./gate/ratelimit.js";

export { KNOWN_AGENTS, matchKnownAgent, automationHint } from "./gate/agents.js";
export type { KnownAgent } from "./gate/agents.js";

export { createVerifier, verifyWebBotAuth, createMemoryNonceStore } from "./httpsig/verify.js";
export type {
  NonceStore,
  SignatureResult,
  StaticKey,
  VerificationResult,
  Verifier,
  VerifyOptions,
  VerifyOutcome,
} from "./httpsig/verify.js";

export { signRequest, directoryDocument } from "./httpsig/sign.js";
export type { SignOptions, SignatureAgentSpec, SignedHeaders } from "./httpsig/sign.js";

export {
  createDirectoryResolver,
  defaultHostGuard,
  DirectoryError,
  isPrivateAddress,
  normalizeDiscoveryUrl,
  WELL_KNOWN_DIRECTORY,
} from "./httpsig/directory.js";
export type { DirectoryResolver, DirectoryResolverOptions, DiscoveryType, HostGuard } from "./httpsig/directory.js";

export { generateKeyPair, jwkThumbprint, toPublicJwk, KNOWN_TEST_KEY_THUMBPRINTS } from "./httpsig/jwk.js";
export type { SigAlg } from "./httpsig/jwk.js";

export { createSignatureBase } from "./httpsig/base.js";
export type { MessageContext, RequestLike } from "./httpsig/base.js";

export { runAudit, BROWSER_UA } from "./audit/run.js";
export type { AuditOptions, AuditReport, CategoryResult, CheckResult, CheckStatus, Fix, ProbeResult } from "./audit/run.js";
export { renderHtml, renderMarkdown, renderText, badgeUrl } from "./audit/render.js";
export { parseHtml } from "./audit/html.js";

export { VERSION } from "./version.js";
