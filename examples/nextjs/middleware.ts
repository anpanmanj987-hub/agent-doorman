// Next.js middleware (Edge runtime). Put this file at the root of your app as middleware.ts.
import { NextResponse, type NextRequest } from "next/server";
import { createDoorman, presets } from "agent-doorman";

const doorman = createDoorman({
  policy: presets.ecommerce(),
  mode: "monitor",
  // On Vercel and most hosts the request URL already carries the public host.
  onDecision: (d) => console.log(JSON.stringify(d)),
});

export async function middleware(request: NextRequest) {
  const blocked = await doorman.guard(request);
  return blocked ?? NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
