import { createDoorman, presets, signRequest, runAudit, type Decision, type Policy } from "agent-doorman";
import { nodeMiddleware, fileLogger, nodeHostGuard } from "agent-doorman/node";
const p: Policy = presets.content();
const d = createDoorman({ policy: p, onDecision: (x: Decision) => void x.trust.class });
void nodeMiddleware(d); void fileLogger; void nodeHostGuard; void signRequest; void runAudit;
