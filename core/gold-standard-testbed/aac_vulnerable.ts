// Gold testbed: Advanced Agent & Cloud (AAC) — TypeScript / Next.js markers.

// Vulnerable: AAC-003 (Next.js client-side secret)
const stripeKey = process.env.NEXT_PUBLIC_STRIPE_SECRET;

// Vulnerable: AAC-010 (WebRTC / VAD without session gate)
async function startHotMic() {
  await navigator.mediaDevices.getUserMedia({ audio: true });
}
