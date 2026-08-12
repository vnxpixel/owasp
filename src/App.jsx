import { useEffect, useRef, useState } from 'react';
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
    steps: ['Weaponize', 'Sign-in fork', 'Wrong origin', 'Data entry', 'Session replay', 'Impact']
  },
  extension: {
    short: 'Local extension',
    label: 'B · Local extension',
    description: 'The right site with hostile code beside it',
    color: 'var(--extension)',
    steps: ['Install', 'Session created', 'Right origin', 'DOM control', 'Two requests', 'Impact']
  }
};

const journeyBeats = [
  {
    label: 'The setup', time: 'T − 3 days', progress: 0, focus: 'attacker',
    title: 'The click begins before they arrive.',
    thesis: 'The attacker prepares a believable path, then waits for a normal human moment.',
    phishing: {
      user: { location: 'Away from the browser', status: 'Unaware', title: 'Nothing has happened to them yet.', body: 'Their real account and session are still intact.' },
      browser: { location: 'No hostile tab open', status: 'Clean', title: 'The browser has no special knowledge.', body: 'The browser’s HTTPS indicator will show that TLS is active and the certificate is valid for shop-example.help. It does not show that shop-example.help is the intended shop.example domain.' },
      attacker: { location: 'Lookalike kit · remote server', status: 'Building', title: 'Copy the surface. Change the destination.', body: 'A cloned checkout is deployed at shop-example.help with a collector behind the Pay button.', artifact: 'POST /collect  ←  checkout form' },
      evidence: [['origin', 'shop-example.help', 'attacker'], ['cookie', 'none from shop.example', 'browser'], ['surface', 'pixel-matched checkout', 'attacker']]
    },
    extension: {
      user: { location: 'Extension store', status: 'Trust decision', title: 'A useful tool asks for broad access.', body: '“Parcel Price Finder” promises automatic delivery discounts.' },
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
      user: { location: 'Lookalike login', status: 'Types credentials', title: 'The password form feels like a normal interruption.', body: 'They volunteer their email, password, and possibly a one-time code to the attacker origin.' },
      browser: { location: 'Origin · shop-example.help', status: 'No shop session', title: 'The real shop cookie remains isolated.', body: 'Same-origin policy and cookie scoping still work. The lookalike receives only what they submit to it.' },
      attacker: { location: 'Collector → real login', status: 'Credential replay', title: 'Create a new authenticated session.', body: 'The attacker replays the captured credential or relays MFA to shop.example. If login succeeds, the shop issues a separate attacker-controlled session.', artifact: 'Set-Cookie: session=s_attacker' },
      evidence: [['captured', 'password + optional OTP', 'attacker'], ['their shop cookie', 'not exposed', 'secure'], ['attacker session', 'possible after replay', 'attacker']]
    },
    extension: {
      user: { location: 'shop.example/login', status: 'Authenticates normally', title: 'The sign-in is genuine.', body: 'They post their credentials to the real shop and complete MFA on the correct origin.' },
      browser: { location: 'Cookie jar', status: 'Session established', title: 'The browser stores ambient authority.', body: 'The server returns a Secure, HttpOnly, SameSite cookie. JavaScript cannot read the value, but matching requests receive it automatically.' },
      attacker: { location: 'Content script', status: 'document.cookie blocked', title: 'The token stays hidden; the page stays usable.', body: 'Without the separate cookies permission, this extension cannot extract the HttpOnly value. It can still observe DOM state and ride the authenticated session.', artifact: 'Cookie: session=s_7f2a · hidden from page JS' },
      evidence: [['Set-Cookie', 'Secure · HttpOnly · SameSite=Lax', 'secure'], ['script access', 'cookie value blocked', 'secure'], ['ambient use', 'attached on shop requests', 'browser']]
    }
  },
  {
    label: 'The arrival', time: 'T − 18 s', progress: 2, focus: 'user',
    title: 'They see a checkout. The browser checks the web origin.',
    thesis: 'Matching logos and page design do not establish identity. The URL’s scheme, hostname, and port define the web origin.',
    phishing: {
      user: { location: 'Tab · “Shop delivery”', status: 'Believes: shop.example', title: 'The page looks exactly right.', body: 'The cart, total, type, and logo all match the message they expected.' },
      browser: { location: 'Origin · shop-example.help', status: 'Actually: lookalike', title: 'The address bar shows the actual hostname.', body: 'The URL is https://shop-example.help, not https://shop.example. TLS encrypts the connection to shop-example.help and validates its certificate for that hostname. The browser does not attach cookies scoped to shop.example.' },
      attacker: { location: 'Collector · listening', status: 'Waiting', title: 'No exploit is needed yet.', body: 'The attacker needs them to volunteer data to this origin.', artifact: '200 OK  ·  TLS valid' },
      evidence: [['seen by them', 'Shop checkout', 'user'], ['actual origin', 'shop-example.help', 'attacker'], ['shop session', 'not attached', 'secure']]
    },
    extension: {
      user: { location: 'Tab · shop.example/checkout', status: 'Correct destination', title: 'The page really is the shop.', body: 'The address, certificate, and visible checkout are all legitimate.' },
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
      user: { location: 'Lookalike checkout', status: 'Ready to pay', title: 'RM129 · Pay now', body: 'They see the action they came here to complete.' },
      browser: { location: 'DOM · hostile origin', status: 'Form target differs', title: 'The button is wired to the collector.', body: 'Typed card and account fields belong to this page. The real shop never receives this click.' },
      attacker: { location: 'Page JavaScript', status: 'Handler armed', title: 'Prevent the normal submit. Keep the illusion.', body: 'The handler copies fields, posts them to /collect, then paints a local success state.', artifact: 'button → capture() → fakeSuccess()' },
      evidence: [['button label', 'Pay now', 'user'], ['submit target', '/collect', 'attacker'], ['session cookie', 'absent', 'secure']]
    },
    extension: {
      user: { location: 'Legitimate checkout', status: 'Ready to pay', title: 'RM129 · Pay now', body: 'Nothing visible suggests that the page has a second observer.' },
      browser: { location: 'DOM · before serialization', status: 'Field mutated', title: 'A DOM value changes behind the surface.', body: 'The extension swaps delivery.account to drop_772. Page code will later serialize the altered value.' },
      attacker: { location: 'Content script', status: 'Hook armed', title: 'Observe the click. Alter only what matters.', body: 'It cannot read the HttpOnly value through page JavaScript, but it can alter a form value that new FormData(form) will serialize.', artifact: 'delivery.account = "drop_772"' },
      evidence: [['visible total', 'RM129', 'user'], ['delivery.account', 'drop_772', 'attacker'], ['session cookie', 'HttpOnly · unreadable', 'secure']]
    }
  },
  {
    label: 'The click', time: 'T = 0 ms', progress: 4, focus: 'split', pulse: true,
    title: 'They supply intent. The context decides its meaning.',
    thesis: 'A click is physical feedback; the security event is the code and origin that receive it.',
    phishing: {
      user: { location: 'Lookalike checkout', status: 'Clicks Pay', title: 'The button depresses. They are done.', body: 'Their gesture is genuine, but it is addressed to the wrong origin.' },
      browser: { location: 'Event loop · hostile tab', status: 'submit intercepted', title: 'click → listener → fetch()', body: 'The browser correctly executes attacker-owned JavaScript for shop-example.help.' },
      attacker: { location: 'Collector endpoint', status: 'Inbound', title: 'The volunteered fields cross the wire.', body: 'No shop cookie crosses origins. The captured credentials and form data do.', artifact: 'POST shop-example.help/collect' },
      evidence: [['gesture', 'trusted human click', 'user'], ['receiver', 'hostile event listener', 'attacker'], ['request origin', 'shop-example.help', 'browser']]
    },
    extension: {
      user: { location: 'Legitimate checkout', status: 'Clicks Pay', title: 'The button depresses. They are done.', body: 'Their gesture is genuine and occurs on the intended site.' },
      browser: { location: 'Page + extension contexts', status: 'Two flows begin', title: 'One click wakes two listeners.', body: 'The shop builds its checkout request. The content script separately sends DOM-visible data to its MV3 service worker.' },
      attacker: { location: 'MV3 extension service worker', status: 'Outbound queued', title: 'Ambient access turns into action.', body: 'The extension does not need the cookie value: the legitimate browser request already carries it to the shop.', artifact: 'shop fetch()  +  runtime.sendMessage()' },
      evidence: [['gesture', 'trusted human click', 'user'], ['shop request', 'cookie auto-attached', 'browser'], ['extension copy', 'DOM fields', 'attacker']]
    }
  },
  {
    label: 'Under the hood', time: 'T + 3 ms', progress: 4, focus: 'browser',
    title: 'The browser does exactly what each context permits.',
    thesis: 'Compromise is often two valid mechanisms composed into an invalid outcome.',
    phishing: {
      user: { location: 'Waiting for confirmation', status: 'No warning', title: 'A spinner makes the pause feel ordinary.', body: 'The interface buys enough time to collect and relay what they entered.' },
      browser: { location: 'Network · attacker origin', status: 'Encrypted outbound', title: 'The payload is protected in transit.', body: 'TLS makes theft private between them and the attacker. It does not certify business identity.' },
      attacker: { location: 'Collector + real shop', status: 'Relaying', title: 'Captured credentials start a separate session.', body: 'The attacker can attempt a real login or purchase flow with the volunteered data; they never inherit their shop cookie by magic.', artifact: 'collector → separate login attempt' },
      evidence: [['TLS', 'valid', 'browser'], ['shop cookie', 'never exposed', 'secure'], ['captured data', 'credentials + form', 'attacker']]
    },
    extension: {
      user: { location: 'Waiting for confirmation', status: 'No warning', title: 'The real checkout continues normally.', body: 'The compromise does not need to break the happy path.' },
      browser: { location: 'Network · two destinations', status: 'Fan-out', title: 'The same moment produces two requests.', body: 'POST /api/checkout goes to shop.example with ambient credentials; copied fields go to the extension collector.' },
      attacker: { location: 'Collector · remote', status: 'Data received', title: 'Local privilege crosses into remote control.', body: 'The attacker receives the altered delivery account and DOM-visible order details.', artifact: 'POST collector.invalid/events' },
      evidence: [['shop request', 'session=s_7f2a', 'browser'], ['cart body', 'delivery=drop_772', 'attacker'], ['exfil request', 'no HttpOnly cookie', 'secure']]
    }
  },
  {
    label: 'The two receipts', time: 'T + 214 ms', progress: 5, focus: 'split',
    title: 'Success for them can also be success for the attacker.',
    thesis: 'The absence of friction is not evidence that the system stayed whole.',
    phishing: {
      user: { location: 'Lookalike confirmation', status: 'Sees: Payment received', title: 'A receipt appears on schedule.', body: 'It is a local animation, not proof that the shop accepted anything.' },
      browser: { location: 'Hostile tab · no navigation', status: 'Paint complete', title: 'The browser paints what the origin tells it.', body: 'There is no trusted receipt identifier from shop.example to bind this surface to a real order.' },
      attacker: { location: 'Collector dashboard', status: 'Capture complete', title: 'A second receipt records the theft.', body: 'The attacker has the submitted data and a timestamped victim event.', artifact: 'capture_7F2A  ·  200 OK' },
      evidence: [['they see', 'Payment received', 'user'], ['trusted order ID', 'missing', 'attacker'], ['attacker sees', 'capture complete', 'attacker']]
    },
    extension: {
      user: { location: 'Real shop confirmation', status: 'Sees: Payment received', title: 'The receipt is genuine.', body: 'Their payment completed, so the experience gives them no reason to investigate.' },
      browser: { location: 'shop.example + extension', status: 'Both complete', title: 'The good and bad outcomes coexist.', body: 'A 200 response validates processing, not the provenance of every client-controlled field.' },
      attacker: { location: 'Drop account · drop_772', status: 'Order redirected', title: 'The attacker’s state changed too.', body: 'The manipulated delivery value survived because the server trusted a browser-owned invariant.', artifact: 'delivery.account → drop_772' },
      evidence: [['shop response', '200 · ord_8821', 'secure'], ['delivery owner', 'not reverified', 'attacker'], ['attacker sees', 'order redirected', 'attacker']]
    }
  },
  {
    label: 'The rewind', time: 'T ↶', progress: 5, focus: 'browser', controls: true,
    title: 'Stop the chain where the truth first diverges.',
    thesis: 'Good controls do not ask them to become a security engine. They remove attacker leverage at the boundary.',
    phishing: {
      user: { location: 'Before the lure', status: 'Protected by context', title: 'Make destination identity hard to miss.', body: 'Password-manager origin binding and trusted navigation remove the lookalike’s strongest illusion.' },
      browser: { location: 'Origin boundary', status: 'Divergence visible', title: 'Bind secrets and proof to the real origin.', body: 'Passkeys resist credential relay; a shop-issued receipt must carry a verifiable order ID.' },
      attacker: { location: 'Lookalike origin', status: 'Capability reduced', title: 'The clone can copy pixels, not origin-bound proof.', body: 'The attacker is left with a convincing page that cannot obtain reusable authentication material.', artifact: 'PASSKEY ORIGIN MISMATCH' },
      evidence: [['01', 'Password manager will not fill', 'secure'], ['02', 'Passkey checks origin', 'secure'], ['03', 'Receipt verified with shop', 'secure']]
    },
    extension: {
      user: { location: 'Permission decision', status: 'Least access', title: 'Make broad capability exceptional.', body: 'Use-on-click access and permission reviews shorten the time hostile code can inhabit a trusted page.' },
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
      { title: 'The session cookie identifies their session.', body: 'The cookie does not prove that they approved this payment.', signal: 'Claim: identity and intent', result: 'CLAIMS NOT VERIFIED' },
      { title: 'A hostile page sends the request.', body: 'A CSRF attack uses cookies that the browser adds automatically. An XSS attack runs a malicious script with the user’s permissions.', signal: 'Attack: false intent', result: 'REQUEST FORGED' },
      { title: 'Verify the source and intent.', body: 'Verify the Origin header and a CSRF token that is bound to the session. Use a SameSite cookie as an additional control. Prevent script injection with correct output encoding and a strict CSP.', signal: 'Control: browser and server', result: 'INTENT VERIFIED', actions: ['SameSite cookie', 'Origin + CSRF token', 'Output encoding + strict CSP'] }
    ],
    note: 'Ask the question before you show the answer. HTTPS protects data while it moves across the network. It does not verify the request data. The application must verify each claim.'
  },
  {
    label: 'The edge', zone: 'edge', time: '31.700 ms', minutes: 2.5, lenses: ['A02', 'A04'],
    title: 'TLS protects data in transit.',
    thesis: 'TLS prevents a network observer from reading or changing the data. TLS does not verify the sender or the edge configuration.',
    prompt: 'What does the browser’s HTTPS indicator confirm about the connection and certificate? What application checks are still required?',
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
    note: 'Do not describe the WAF as a complete control. The edge can block known bad traffic and enforce the transport policy. The application must decide if they can buy the cart.'
  },
  {
    label: 'The API gate', zone: 'api', time: '64.200 ms', minutes: 3, lenses: ['A01', 'A07'],
    title: 'Authenticate the user. Authorize the action.',
    thesis: 'A valid session identifies the user. It does not give the user access to every action or object.',
    prompt: 'Where must the system verify that they own the cart?',
    packet: [
      { label: 'session.user', values: ['user', 'user', 'user'] },
      { label: 'action', values: ['checkout', 'checkout', 'checkout'] },
      { label: 'cartId', values: ['cart_1042', 'cart_1043', 'cart_1043'] },
      { label: 'cart.owner', values: ['user', 'devon', 'devon'] },
      { label: 'decision', values: ['not checked', '200 OK', '403 + req_7F2A'] }
    ],
    phases: [
      { title: 'They have a valid session.', body: 'Authentication identifies them. The server must also verify that they can check out this cart.', signal: 'Claim: session is valid', result: 'IDENTITY KNOWN' },
      { title: 'The attacker changes the cart ID.', body: 'The server does not check the cart owner. As a result, their session can access Devon’s cart.', signal: 'Attack: cart_1042 → cart_1043', result: 'DEVON’S CART EXPOSED' },
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

const reflectionCheckpoints = [
  {
    ...checkpoints[0], label: 'Browser threats', minutes: 3.5,
    title: 'Match the control to the browser threat.',
    thesis: 'A session cookie proves identity, not intent.',
    prompt: 'Where does the attacker run, and what can they access?',
    phases: [
      { title: 'Cookies are ambient authority.', body: 'The browser can attach them without a deliberate user action.', signal: 'Claim: session = intent', result: 'IDENTITY ONLY' },
      { title: 'CSRF sends; XSS reads and acts.', body: 'CSRF is cross-origin. XSS executes inside the trusted origin.', signal: 'Attack: different capabilities', result: 'CONTEXT COMPROMISED' },
      { title: 'Use threat-specific controls.', body: 'CSRF: token, Origin, SameSite. XSS: contextual encoding, safe DOM APIs, then CSP.', signal: 'Control: match mechanism', result: 'CONTEXT VERIFIED', actions: ['CSRF token + Origin', 'Safe DOM + encoding', 'CSP defense-in-depth'] }
    ],
    note: 'Key takeaway: authentication never replaces authorization or request-context checks.'
  },
  {
    ...checkpoints[1], label: 'Transport and edge', minutes: 3,
    thesis: 'TLS protects the channel—not the application.',
    prompt: 'What remains untrusted after TLS succeeds?',
    packet: checkpoints[1].packet.map(line => line.label === 'CORS' ? { ...line, values: ['shop.example', 'Origin reflected + credentials', 'explicit origins'] } : line),
    phases: [
      { title: 'TLS secures data in transit.', body: 'It authenticates the hostname and prevents network tampering.', signal: 'Claim: protected channel', result: 'TLS OK' },
      { title: 'HTTPS can still serve an unsafe app.', body: 'Lookalikes, debug routes, bad CORS, and spoofed proxy headers remain possible.', signal: 'Attack: valid channel, unsafe service', result: 'EDGE POLICY FAILED' },
      { title: 'Constrain the edge.', body: 'Use HSTS, route and CORS allow-lists, and trusted proxy chains.', signal: 'Control: explicit policy', result: 'EDGE POLICY PASSED', actions: ['TLS + HSTS', 'Explicit CORS origins', 'Trusted proxies'] }
    ],
    note: 'Key takeaway: HTTPS does not prove user intent, authorization, or valid input.'
  },
  {
    ...checkpoints[2], label: 'Application decisions', minutes: 4, lenses: ['A01', 'A05', 'A07'],
    title: 'Make four separate server decisions.',
    thesis: 'Identify. Authorize. Validate. Keep data out of code.',
    prompt: 'Which check fails first?',
    packet: [
      { label: 'identity', values: ['session.user = user', 'session.user = user', 'session.user = user · rotated'] },
      { label: 'action', values: ['checkout', 'checkout cart_1043', 'checkout cart_1043'] },
      { label: 'ownership', values: ['not checked', 'owner = devon', 'owner = devon · denied'] },
      { label: 'coupon', values: ['WELCOME10', "x\' OR \'1\'=\'1", "parameter: x\' OR \'1\'=\'1"] },
      { label: 'decision', values: ['claims pending', 'access + query unsafe', '403 · parameterized'] }
    ],
    phases: [
      { title: 'A session answers only “who?”', body: 'It does not grant every action or object.', signal: 'Claim: authenticated = allowed', result: 'AUTHZ REQUIRED' },
      { title: 'Valid input can still be dangerous.', body: 'Wrong object access breaks authorization; concatenated input becomes SQL.', signal: 'Attack: object + injection', result: 'TWO CHECKS FAILED' },
      { title: 'Enforce every decision server-side.', body: 'Deny by default, check ownership, validate formats, and parameterize queries.', signal: 'Control: explicit decisions', result: '403 · INPUT STAYS DATA', actions: ['Object authorization', 'Parameterized APIs', 'Contextual encoding'] }
    ],
    note: 'Key takeaway: authentication, authorization, validation, and encoding are different controls.'
  },
  {
    ...checkpoints[4], label: 'Data and business integrity', minutes: 4, lenses: ['A04', 'A06', 'A08'],
    title: 'The server owns business-critical values.',
    thesis: 'Valid JSON can still violate price, ownership, state, or replay rules.',
    prompt: 'Which values must the server derive?',
    packet: [
      { label: 'clientTotal', values: ['129.00', '1.00', 'ignored'] },
      { label: 'catalogTotal', values: ['not loaded', 'not loaded', '129.00'] },
      { label: 'recipient', values: ['user_home', 'drop_772', 'owner verified'] },
      { label: 'db role', values: ['app_owner', 'all tables + writes', 'checkout_writer'] },
      { label: 'repeat', values: ['ik_7f2a', 'replayed ×12', 'seen · no-op'] }
    ],
    phases: [
      { title: 'Schema-valid is not business-valid.', body: 'Price, recipient, state, and replay rules belong to the server.', signal: 'Claim: valid JSON = valid action', result: 'RULES UNCHECKED' },
      { title: 'Small changes create real loss.', body: 'An attacker changes the price, recipient, or repeats the request.', signal: 'Attack: valid but harmful values', result: 'INTEGRITY FAILED' },
      { title: 'Re-derive and contain.', body: 'Use server state, idempotency, narrow database roles, and minimal stored data.', signal: 'Control: invariants + least privilege', result: 'RM129 · ONCE · LIMITED', actions: ['Server-owned values', 'Idempotency', 'Least privilege'] }
    ],
    note: 'Key takeaway: never trust the client with business invariants.'
  },
  {
    ...checkpoints[6], label: 'Resilience and operations', minutes: 4, lenses: ['A09', 'A10'],
    title: 'Design the failure path.',
    thesis: 'Failures must be bounded, observable, and recoverable.',
    prompt: 'What happens when payment state is uncertain?',
    packet: [
      { label: 'dependency', values: ['risk pending', 'timeout', 'timeout · bounded'] },
      { label: 'state', values: ['unspecified', 'charge ✓ · order ✕', 'atomic · review'] },
      { label: 'client', values: ['Error', 'stack + SQL', 'Payment pending · req_7F2A'] },
      { label: 'evidence', values: ['console.log', 'token + stack', 'structured · redacted'] },
      { label: 'response', values: ['no owner', 'no alert', 'owner paged · runbook'] }
    ],
    phases: [
      { title: 'Failure behavior needs a policy.', body: 'Define timeout, retry, and partial-write outcomes before production.', signal: 'Claim: happy path is enough', result: 'POLICY REQUIRED' },
      { title: 'Unsafe fallback multiplies harm.', body: 'Approve-on-error, endless retries, and leaked logs turn faults into incidents.', signal: 'Attack: induce failure', result: 'FAILURE AMPLIFIED' },
      { title: 'Contain and recover.', body: 'Use bounded retries, atomic state, request IDs, redacted logs, alerts, and a runbook.', signal: 'Control: operational readiness', result: 'HELD · ALERTED · RECOVERABLE', actions: ['Safe failure state', 'Correlated evidence', 'Owned runbook'] }
    ],
    note: 'Key takeaway: every alert needs a threshold, owner, and response.'
  }
];

const quiz = [
  { question: 'A hostile site submits a credentialed request but cannot read the response. Which threat best matches?', choices: ['CSRF', 'XSS', 'TLS downgrade'], right: 0, why: 'CSRF abuses ambient authority across origins. Origin and token checks, supported by SameSite and Fetch Metadata, address that context.' },
  { question: 'Hostile script executes inside shop.example and reads the response. Which foundation prevents this?', choices: ['CORS alone', 'Contextual output encoding and safe DOM APIs', 'A random session ID'], right: 1, why: 'XSS executes in the trusted origin. Safe output handling is foundational; CSP and Trusted Types add defense-in-depth.' },
  { question: 'They have a valid session. Cart cart_1043 belongs to Devon. Which control prevents access?', choices: ['Use random IDs', 'Check the user, action, and object', 'Hide the cart ID'], right: 1, why: 'The server must authorize their action on cart_1043.' },
  { question: 'The risk service stops after the card charge but before the order write. Which control is required?', choices: ['Use a longer timeout', 'Use atomic or recoverable writes and a safe failure policy', 'Return more error details'], right: 1, why: 'The system needs consistent state and a defined safe outcome.' },
  { question: 'A request uses TLS and valid JSON. Is the request trusted?', choices: ['Yes, because both checks passed', 'Yes, if a WAF accepts it', 'No; neither proves authorization, intent, or business validity'], right: 2, why: 'TLS protects the channel and JSON proves syntax. Each component must still verify the claims it uses.' }
];

const journeyNotes = {
  'The sign-in': 'Separate the browser cookie jars aloud. In phishing, they submit reusable proof to the collector; an optional server-side replay may create session=s_attacker in the attacker client. In the extension path, the real shop rotates their session and sets an HttpOnly cookie. Use the storage switcher to emphasize that JWT is a format—storage and attachment define XSS and CSRF exposure.',
  'Under the hood': 'Open each envelope. Collector and replay are separate requests; only replay reaches the shop. In the extension path, Request A passes authentication and CSRF but contains an attacker-chosen recipient. Request B is independent exfiltration through the extension worker. Ask which server invariant failed.'
};
const journeyScenes = journeyBeats.map((item, index) => ({ ...item, type: 'journey', zone: `journey-${index + 1}`, minutes: item.label === 'The sign-in' ? 2.5 : 1.5, note: journeyNotes[item.label] || `Let the ${item.label.toLowerCase()} visual complete before explaining it. Point to the colored route or highlighted object first; use the evidence chips only to confirm what the audience has already seen.` }));

const certificateChapters = [
  {
    label: 'The rabbit hole', zone: 'cert-intro', visual: 'plot', time: 'the missing manual', minutes: 3,
    eyebrow: 'Everything PKI · 01', title: 'Certificates and PKI are hard.',
    thesis: 'The math is complicated, and the standards are stupidly baroque, but the core concepts are actually quite simple. PKI is powerful because it lets us define a system cryptographically—universally, without making the network itself the security boundary.',
    takeaway: 'The goal of certificates and PKI is to bind names to public keys. That’s it.',
    points: [['NAME', 'Something the system understands', 'api.shop.example'], ['PUBLIC KEY', 'Something the system can verify', 'EC P-256 · 03:A7…'], ['THE BINDING', 'One signed, portable claim', 'name ↔ public key']],
    note: 'This is the article’s opening promise: the important concepts fit in one session. Let the one-sentence summary land before introducing terminology.'
  },
  {
    label: 'A broad overview', zone: 'cert-overview', visual: 'roles', time: 'some words to know', minutes: 4,
    eyebrow: 'A broad overview · 02', title: 'First, name the cast.',
    thesis: 'An entity is anything that exists. Every entity has an identity; a name is merely a unique reference to it. An entity can claim a name, and authentication is the process of confirming the truth of that claim.',
    takeaway: 'Identity is not an identifier. “Mike” is a name, not an identity.',
    points: [['SUBSCRIBER', 'The entity named by a certificate', 'also called the subject'], ['ISSUER', 'The CA that issues the certificate', 'vouches for the binding'], ['RELYING PARTY', 'The user that verifies it', 'decides whether to trust']],
    note: 'A single entity can be both subscriber and relying party. That is exactly what happens in mutual TLS.'
  },
  {
    label: 'MACs and signatures', zone: 'cert-signatures', visual: 'proof', time: 'authenticate stuff', minutes: 4,
    eyebrow: 'MACs and signatures · 03', title: 'MACs authenticate stuff.',
    thesis: 'Feed a shared secret and a message through a hash function and you get a message authentication code. A recipient with the same secret can reproduce the MAC and confirm both who sent the message and that it was not modified.',
    takeaway: 'Do not invent your own MAC algorithm. Use HMAC.',
    points: [['MAC', 'Sender and recipient share a secret', 'both can create proof'], ['SIGNATURE', 'Only the private-key holder signs', 'authorship is controlled'], ['VERIFY', 'The public key checks the signature', 'verification cannot forge']],
    note: 'MACs are prologue. The real story starts with signatures: similar purpose, but a radically different distribution of authority.'
  },
  {
    label: 'Public key cryptography', zone: 'cert-cryptography', visual: 'keypair', time: 'computers can see', minutes: 4,
    eyebrow: 'Public key cryptography · 04', title: 'Public key cryptography lets computers see.',
    thesis: 'A key pair has a public key that can be shared with the world and a private key that must remain private. One computer can prove to another that it knows something without ever sharing that knowledge directly.',
    takeaway: 'Public encrypts → private decrypts. Private signs → public verifies.',
    points: [['CHALLENGE', 'Send a big fresh random number', '7F 2A 91 D4…'], ['PRIVATE KEY', 'Sign it without revealing the key', 'knowledge stays local'], ['PUBLIC KEY', 'Verify the answer across the network', 'the computer can “see” you']],
    note: 'Use the article’s vision analogy: knowing what I look like lets you recognize me, but it does not let you shape-shift into me. Thanks, math.'
  },
  {
    label: 'Certificates', zone: 'cert-certificate', visual: 'certificate', time: 'driver’s licenses', minutes: 4,
    eyebrow: 'Certificates · 05', title: 'Driver’s licenses for computers and code.',
    thesis: 'What if you do not already know my public key? That is what certificates are for. A certificate contains a public key and a name, and the issuer signs the whole data structure so the signature binds the key to the name.',
    takeaway: '“Some Issuer says Bob’s public key is 01:23:42…”',
    points: [['SUBJECT', 'api.shop.example', 'the entity named'], ['PUBLIC KEY', 'EC P-256 · 03:A7…', 'the key being vouched for'], ['ISSUER', 'Northstar Intermediate CA', 'the signer you trust']],
    note: 'Like a license, a real certificate has extra fields: expiry, allowed uses, and whether the holder may act as a CA. None of that changes the fundamental plot.'
  },
  {
    label: 'X.509 and friends', zone: 'cert-formats', visual: 'formats', time: 'oh my…', minutes: 5,
    eyebrow: 'X.509, ASN.1, OIDs, DER, PEM, PKCS · 06', title: 'This part actually is annoyingly complicated.',
    thesis: 'Most certificate frustration comes from the esoteric way certificates and keys are represented as bits and bytes. Usually “certificate” means an X.509 v3 certificate in the PKIX form browsers understand.',
    takeaway: 'If this is confusing, it is not you. It is the world.',
    points: [['ASN.1 → DER', 'Schema → canonical binary encoding', 'X.509 is defined here'], ['DER → PEM', 'Binary → Base64 with labels', 'BEGIN CERTIFICATE'], ['PKCS ENVELOPES', '#7 carries chains; #12 can carry keys', '.p7b / .p12 / .pfx']],
    note: 'Teach the layers, not every OID. Extensions and file names are inconsistent; inspect the content rather than trusting the suffix.'
  },
  {
    label: 'Public Key Infrastructure', zone: 'cert-pki', visual: 'infrastructure', time: 'the whole system', minutes: 4,
    eyebrow: 'Public Key Infrastructure · 07', title: 'A certificate is less than half the story.',
    thesis: 'PKI is the umbrella term for everything needed to issue, distribute, store, use, verify, revoke, and otherwise manage certificates and keys. It is intentionally vague, like “database infrastructure.”',
    takeaway: 'Certificates are building blocks. PKI is libraries, protocols, people, policy, and automation.',
    points: [['ISSUE', 'Names, registration, CAs, requests', 'create the binding'], ['DISTRIBUTE + USE', 'Roots, chains, clients, servers', 'make it useful'], ['OPERATE', 'Renewal, revocation, monitoring', 'keep it trustworthy']],
    note: 'A PKI does not even have to use certificates: authorized_keys is a simple public-key infrastructure that binds keys to names in a flat file.'
  },
  {
    label: 'Web PKI vs Internal PKI', zone: 'cert-scope', visual: 'scope', time: 'choose the right one', minutes: 5,
    eyebrow: 'Web PKI vs Internal PKI · 08', title: 'Use Web PKI outside. Internal PKI inside.',
    thesis: 'Web PKI is the public system your browser uses for HTTPS. Internal PKI is the system you run for your own services, containers, VMs, laptops, phones, code, and devices.',
    takeaway: 'Use Web PKI for public websites and APIs. Use your own internal PKI for everything else.',
    points: [['WEB PKI', 'Public DNS and browser trust', 'universal interoperability'], ['INTERNAL PKI', 'Private names and workload identity', 'your policy and automation'], ['WHY', 'Control lifetime, renewal, algorithms, scale', 'smaller trust domain']],
    note: 'Public CAs cannot bind private IPs or names like foo.ns.svc.cluster.local. Public issuance limits and availability also make a poor dependency for fast-moving internal systems.'
  },
  {
    label: 'Trust stores', zone: 'cert-trust-stores', visual: 'trust', time: 'trust begins locally', minutes: 5,
    eyebrow: 'Trust & Trustworthiness · 09', title: 'How do I know the issuer’s public key?',
    thesis: 'Relying parties are preconfigured with trusted root certificates in a trust store. The answer is simple, if not entirely satisfying: the roots are already there because some other trusted process put them there.',
    takeaway: 'Every trust chain ends in meatspace.',
    points: [['ROOT CERTIFICATE', 'A local trust anchor', 'often self-signed'], ['TRUST STORE', 'Roots accepted by this relying party', 'OS / browser / application'], ['PROVENANCE', 'How the root got there', 'the actual source of trust']],
    note: 'A self-signature only proves possession of the root private key. Anyone can self-sign any name. A root deserves trust because of its provenance.'
  },
  {
    label: 'Trustworthiness', zone: 'cert-trustworthiness', visual: 'trust', time: 'trusted ≠ trustworthy', minutes: 4,
    eyebrow: 'Trustworthiness · 10', title: 'Trusted is descriptive. Trustworthy is moral.',
    thesis: 'Public trust stores contain many certificate authorities. Browsers trust them by default, but history includes compromise, mistaken issuance, government pressure, and malformed certificates.',
    takeaway: 'Your security depends on the discipline and scruples of organizations you did not choose.',
    points: [['DESCRIPTIVE TRUST', 'The root is accepted by software', 'configured reality'], ['TRUSTWORTHINESS', 'The issuer behaves correctly', 'an empirical question'], ['INTERNAL POLICY', 'Trust fewer roots for private systems', 'reduce exposure']],
    note: 'For internal TLS, avoid trusting the entire public CA ecosystem when a dedicated internal root set will do.'
  },
  {
    label: 'Federation', zone: 'cert-federation', visual: 'infrastructure', time: 'the least secure CA', minutes: 5,
    eyebrow: 'Federation · 11', title: 'Every public CA can vouch for almost anyone.',
    thesis: 'Web PKI relying parties generally trust every CA in their store to sign for every subscriber. The security of the federation is therefore only as good as its least secure member.',
    takeaway: 'A CA you have never met may still be able to issue a certificate your browser accepts for your domain.',
    points: [['CAA', 'Restrict which CAs may issue', 'DNS policy signal'], ['TRANSPARENCY', 'Put issued certificates in public logs', 'detect fraudulent issuance'], ['DEDICATED ROOTS', 'Separate internal trust stores', 'shrink the federation']],
    note: 'Policy only works when relying parties enforce it. CAA and Certificate Transparency help; a narrow internal trust domain helps more for private systems.'
  },
  {
    label: 'Intermediates and chains', zone: 'cert-chain', visual: 'chain', time: 'delegate issuance', minutes: 5,
    eyebrow: 'Intermediates, Chains, and Bundling · 12', title: 'Keep root keys offline. Put intermediates to work.',
    thesis: 'A broadly distributed root is hard to revoke, so its private key should be used rarely. It signs intermediate certificates; online intermediate CAs do the routine job of signing leaf certificates.',
    takeaway: 'Leaf is signed by intermediate. Intermediate is signed by root. Root signs itself.',
    points: [['ROOT CA', 'Broadly trusted and rarely used', 'offline trust anchor'], ['INTERMEDIATE CA', 'Online, automated, replaceable', 'issues subscribers'], ['LEAF CERTIFICATE', 'The service, person, or device', 'presented with intermediates']],
    note: 'The server usually sends the leaf and intermediate bundle. The relying party already has the root. Ordering conventions are, annoyingly, not perfectly consistent.'
  },
  {
    label: 'Certificate path validation', zone: 'cert-validation', visual: 'validation', time: 'authenticate the path', minutes: 5,
    eyebrow: 'Certificate path validation · 13', title: 'A chain is evidence, not an automatic pass.',
    thesis: 'The relying party builds a path from the leaf to a trusted root, then verifies signatures, expiration, names, constraints, key usage, policies, and—where supported—revocation.',
    takeaway: 'Do not disable certificate path validation.',
    points: [['SIGNATURES', 'Every issuer verifies the next certificate', 'chain intact'], ['NAME + TIME', 'SAN matches; validity window passes', 'right peer, right now'], ['CONSTRAINTS', 'CA status, key usage, policy, revocation', 'permitted purpose']],
    note: 'Encryption without authentication is pretty worthless: a private conversation with no idea who is on the other side. Do not normalize curl -k as a fix.'
  },
  {
    label: 'Key & Certificate Lifecycle', zone: 'cert-lifecycle', visual: 'issuance', time: 'from request to rotation', minutes: 4,
    eyebrow: 'Key & Certificate Lifecycle · 14', title: 'Simple in outline. Intricate in operation.',
    thesis: 'A subscriber generates a key pair, asks a CA for a certificate, proves the requested name, receives the signed certificate, uses it, replaces it before expiry, and sometimes needs to revoke it.',
    takeaway: 'The hard problems hiding in the details are cache invalidation and naming things.',
    points: [['CREATE', 'Name + local key pair', 'private key stays private'], ['ISSUE', 'CSR + identity proofing', 'CA signs the claim'], ['OPERATE', 'Use + renew + revoke', 'continuous lifecycle']],
    note: 'This page is the lifecycle map. The next pages follow the article through every stage in order.'
  },
  {
    label: 'Naming things', zone: 'cert-naming', visual: 'names', time: 'use SANs', minutes: 4,
    eyebrow: 'Naming things · 15', title: 'Distinguished names were built for a phone book.',
    thesis: 'X.509 inherited names like locality, state, country, organization, and common name from X.500. They do not map cleanly to the web. Modern certificates should bind useful names with Subject Alternative Names.',
    takeaway: 'Use SANs: DNS, email, IP, or URI.',
    points: [['DNS SAN', 'api.shop.example', 'machines and services'], ['EMAIL SAN', 'mike@example.com', 'people'], ['URI SAN', 'spiffe://prod/payments/api', 'workload identities']],
    note: 'Certificates may carry multiple SANs and wildcards. That can be useful, but every extra name broadens what a compromised key can impersonate.'
  },
  {
    label: 'Generating key pairs', zone: 'cert-key-generation', visual: 'keypair', time: 'keep it local', minutes: 4,
    eyebrow: 'Generating key pairs · 16', title: 'Only the subscriber should ever know its private key.',
    thesis: 'The central invariant of PKI is that the private key belongs only to the entity named by the certificate. The safest way to preserve that invariant is for the subscriber to generate its own key pair.',
    takeaway: 'Definitely avoid transmitting a private key across the network.',
    points: [['GENERATE', 'Create the pair at the workload', 'inside its security boundary'], ['PUBLIC HALF', 'Place this in the CSR', 'safe to distribute'], ['PRIVATE HALF', 'Keep local or hardware-backed', 'never export if possible']],
    note: 'Modern deployments commonly use elliptic-curve keys; compatibility and policy matter more than chasing exotic key sizes.'
  },
  {
    label: 'Issuance', zone: 'cert-issuance', visual: 'issuance', time: 'obtain the leaf', minutes: 4,
    eyebrow: 'Issuance · 17', title: 'The CA must prove two different things.',
    thesis: 'Before issuing a leaf certificate, the CA needs evidence that the requester controls the corresponding private key and that the requested name is actually the requester’s name.',
    takeaway: 'Key possession and identity proofing are separate checks.',
    points: [['PUBLIC KEY', 'Does the requester know the private half?', 'proof of possession'], ['NAME', 'Does this identity belong to the requester?', 'registration / proofing'], ['POLICY', 'Is the request allowed?', 'CA template and constraints']],
    note: 'The CSR handles the first question. Registration and identity proofing handle the second.'
  },
  {
    label: 'Certificate signing requests', zone: 'cert-csr', visual: 'issuance', time: 'PKCS#10', minutes: 4,
    eyebrow: 'Certificate signing requests · 18', title: 'A CSR is signed by the requester.',
    thesis: 'A certificate signing request is another ASN.1 structure containing a public key, requested name, and signature. It is self-signed with the matching private key so the CA can verify proof of possession.',
    takeaway: 'A CSR can prove possession. It cannot prove the requested identity by itself.',
    points: [['PUBLIC KEY', 'The key to put in the certificate', 'safe to send'], ['REQUESTED NAMES', 'The SANs the subscriber wants', 'subject to CA policy'], ['SIGNATURE', 'Created by the matching private key', 'tamper evidence + possession']],
    note: 'CAs often ignore optional CSR details and apply their own certificate templates. The private key still never leaves the subscriber.'
  },
  {
    label: 'Identity proofing', zone: 'cert-proofing', visual: 'issuance', time: 'who are you?', minutes: 5,
    eyebrow: 'Identity proofing · 19', title: 'How does the CA authenticate you before you have a certificate?',
    thesis: 'It depends. Web PKI usually proves control of a domain through email, HTTP, or DNS challenges. Internal PKI can bootstrap from infrastructure that already knows what it is provisioning.',
    takeaway: 'A DV certificate proves control of a validation channel at a point in time—not moral ownership.',
    points: [['ACME', 'HTTP or DNS challenge', 'automated domain control'], ['ORGANIZATION PROOFING', 'Legal identity and records', 'OV / EV processes'], ['INTERNAL ATTESTATION', 'Cloud, orchestrator, or device identity', 'trusted provisioning context']],
    note: 'If Kubernetes, Ansible, or a cloud platform is trusted to start the right code in the right place, it already has identity evidence your CA can leverage.'
  },
  {
    label: 'Expiration', zone: 'cert-expiration', visual: 'expiry', time: 'credentials die', minutes: 5,
    eyebrow: 'Expiration · 20', title: 'As we approach forever, compromise approaches certainty.',
    thesis: 'Certificates carry a not-before and not-after time because relying parties usually verify them without calling a central authority. Without an expiry, a stolen credential could remain trusted forever.',
    takeaway: 'Synchronize your clocks. Delete signing keys when they are no longer needed.',
    points: [['NOT BEFORE', 'The certificate is not valid yet', 'clock sync matters'], ['VALID NOW', 'The relying party may accept it', 'all other checks still apply'], ['NOT AFTER', 'The relying party must reject it', 'credential expires']],
    note: 'Signing and encryption keys have different retention needs. A key still needed to decrypt old data cannot simply be deleted when its signing certificate expires.'
  },
  {
    label: 'Renewal', zone: 'cert-renewal', visual: 'expiry', time: 'replace before expiry', minutes: 4,
    eyebrow: 'Renewal · 21', title: 'There is no magic “extend” button.',
    thesis: 'Renewal means obtaining and deploying a new certificate before the old one expires. For internal PKI, the current certificate can often authenticate the renewal request and make the whole process automatic.',
    takeaway: 'If something hurts, do it more. Use short-lived certificates and automate the problem away.',
    points: [['ISSUE NEW', 'Authenticate and request another certificate', 'often with a fresh key'], ['DEPLOY', 'Reload without dropping connections', 'rotate early'], ['OBSERVE', 'Monitor expiry and renewal health', 'avoid surprise outages']],
    note: 'Short lifetimes turn renewal from an annual emergency into ordinary plumbing. That pressure is healthy only if the automation is reliable.'
  },
  {
    label: 'Revocation', zone: 'cert-revocation', visual: 'revocation', time: 'stop trusting early', minutes: 6,
    eyebrow: 'Revocation · 22', title: 'Revocation is a big mess.',
    thesis: 'A CA can declare a certificate invalid before expiry, but every relying party must discover and enforce that decision. CRLs and OCSP introduce caching, latency, privacy, availability, and fail-open problems.',
    takeaway: 'For internal PKI, passive revocation with short-lived certificates is often the sane answer.',
    points: [['CRL', 'A signed list of revoked serial numbers', 'large, cached, sometimes stale'], ['OCSP', 'Ask a responder about one certificate', 'privacy + availability'], ['PASSIVE REVOCATION', 'Deny renewal and wait for expiry', 'simple bounded exposure']],
    note: 'Very short lifetimes increase load on the online CA and make clock synchronization critical. “How short?” depends on the threat model.'
  },
  {
    label: 'Using certificates', zone: 'cert-using', visual: 'using', time: 'TLS is the easy part', minutes: 4,
    eyebrow: 'Using certificates · 23', title: 'Actually using certificates is really easy.',
    thesis: 'Configure a relying party with the root certificates it should trust. Configure a subscriber with its certificate chain and private key. In mutual TLS, each entity has both sets of configuration.',
    takeaway: 'Verifier: roots. Presenter: certificate chain + private key.',
    points: [['RELYING PARTY', 'Trust the intended root set', '--cacert root.pem'], ['SUBSCRIBER', 'Present leaf + intermediate chain', 'server.crt + server.key'], ['MUTUAL TLS', 'Both peers present and validate', 'two-way identity']],
    note: 'Most TLS clients and servers take the same parameters. They usually punt on how certificates appear, rotate, reload, and remain observable—that lifecycle is the real work.'
  },
  {
    label: 'In Summary', zone: 'cert-summary', visual: 'summary', time: 'the field guide', minutes: 4,
    eyebrow: 'In Summary · 24', title: 'Bind names to public keys.',
    thesis: 'Public key cryptography lets computers see across networks. Certificates teach them which public key belongs to which name. CAs vouch for the binding, and relying parties decide whether the evidence deserves trust.',
    takeaway: 'The rest is just details—important, annoying, operable details.',
    points: [['01', 'Use SANs for useful names', 'name'], ['02', 'Keep private keys private', 'key'], ['03', 'Use internal PKI for internal stuff', 'scope'], ['04', 'Present complete chains', 'bundle'], ['05', 'Never disable path validation', 'verify'], ['06', 'Issue short and renew automatically', 'operate']],
    note: 'Close on the original one-sentence summary. Ask the room to identify one name, one public key, one issuer, one trust store, and one renewal path in their own system.'
  }
];

const scenes = [
  ...certificateChapters.map(item => ({ ...item, type: 'certificate-chapter', section: 'certificates' })),
  { type: 'pki-bridge', section: 'certificates', label: 'Beyond the handshake', zone: 'pki-to-app', time: 'connection established', minutes: 2, note: 'Close the certificate session here. A certificate authenticates a name and TLS protects the channel. Neither proves that the person intended this origin, that local code is honest, or that the resulting request is authorized and valid. The button starts the separate Request Under Fire session.' },
  { type: 'opening', section: 'journey', label: 'Case open', zone: 'open', time: 'before the click', minutes: 1.5, note: 'Now open the concrete case: “The connection is protected. When they click Pay, whose code receives their intent?” Let the audience choose which compromise path to trace first.' },
  { type: 'recon', section: 'journey', label: 'Recon workbench', zone: 'recon', time: 'T − 24 h', minutes: 4, note: 'Let the room choose commands. Each result is simulated and intentionally harmless: the point is how small public clues compose into an attack plan. After three clues, ask which exposure they would fix first—and which one is merely information, not a vulnerability by itself.' },
  ...journeyScenes.map(item => ({ ...item, section: 'journey' })),
  { type: 'bridge', section: 'reflections', label: 'What we learned', zone: 'reflect', time: 'rewind complete', minutes: 1.5, note: 'The audience has seen the incident. The next five lessons apply the same claim → attack → control method across the system.' },
  ...reflectionCheckpoints.map(item => ({ ...item, type: 'checkpoint', section: 'reflections' })),
  { type: 'quiz', section: 'reflections', label: 'Field test', zone: 'replay', time: 'replay', minutes: 4, note: 'Ask the audience to vote before selecting an answer. Have them name the attacker context, failed claim, and restoring control.' },
  { type: 'lifecycle', section: 'reflections', label: 'Security lifecycle', zone: 'lifecycle', time: 'continuous', minutes: 2.5, note: 'Security is a product and operational practice, not a final penetration test. Assign ownership and evidence to every stage.' },
  { type: 'appendix', section: 'reflections', label: 'Future deep dives', zone: 'appendix', time: 'placeholder', minutes: 1, note: 'This is a roadmap placeholder only. Use it to acknowledge important topics that deserve their own optional modules rather than rushing through them.' },
  { type: 'closing', section: 'reflections', label: 'Case closed', zone: 'closed', time: 'complete', minutes: 2, note: 'Review the six questions. Ask each person to select one production request this week and draw each boundary and verification step.' }
];
const certificateEndIndex = scenes.findIndex(item => item.type === 'pki-bridge');
const requestStartIndex = scenes.findIndex(item => item.type === 'opening');
const reflectionStartIndex = scenes.findIndex(item => item.type === 'bridge');

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
        <p className="scene-kicker">Checkout incident · They click Pay</p>
        <h1 id="opening-title">Follow one<span>.</span><br />checkout request.</h1>
        <p className="opening-lede">They want to pay RM129. <strong>An attacker changes what happens after they click Pay.</strong></p>
        <p className="opening-thesis">Select the phishing path or the browser extension path. The presentation shows what they do, what the browser does, and what the attacker does.</p>
        <PathSwitch branch={branch} setBranch={setBranch} />
        <button className="primary-action" type="button" onClick={next}>Start the incident <span aria-hidden="true">→</span></button>
      </div>
      <div className="opening-visual opening-diorama" role="img" aria-label="A checkout page whose Pay button sends data along a compromised route">
        <div className="case-label"><span>LIVE INCIDENT · req_7F2A</span><strong>{compromisePaths[branch].short.toUpperCase()}</strong></div>
        <BrowserWindow branch={branch} />
        <div className="opening-route-preview">
          <span><i>U</i>Their browser</span><b>→</b>
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
          <label>Email<input tabIndex={-1} readOnly value="user@example.com" /></label>
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
          <div className="demo-delivery"><span>Delivery account</span><strong>{inspector && !phishing ? 'drop_772' : 'user@home'}</strong>{inspector && !phishing && <em>CHANGED LOCALLY</em>}</div>
          <div className="demo-total"><span>Total</span><strong>RM129.00</strong></div>
          <motion.button key={playKey} className="demo-pay" type="button" tabIndex={interactive ? 0 : -1} aria-label={interactive ? 'Replay their Pay now click' : undefined} aria-hidden={!interactive}
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
      <DiagramNode x={145} y={170} tone="user" label="USER’S BROWSER" detail={phishing ? 'shop-example.help' : 'shop.example + EXT'} />
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
        { label: 'Fake prompt', actor: 'USER’S BROWSER · shop-example.help', title: 'A sign-in modal appears on the phishing site.', body: 'It only looks like the shop. Their password is submitted to the attacker origin—not to shop.example.', visual: 'password' },
        { label: 'Relay login', actor: 'ATTACKER SERVER → shop.example', title: 'The attacker starts a second, real login.', body: 'Using their password, the attacker’s server or automated browser sends its own request to the real shop. The shop replies to the attacker with an MFA challenge.', visual: 'relay' },
        { label: 'Live MFA', actor: 'ATTACKER SERVER ↔ USER', title: 'The challenge is copied back into the fake modal.', body: 'They enter the current code. The attacker forwards it immediately to the real shop before it expires.', visual: 'mfa' },
        { label: 'Session owned', actor: 'shop.example → ATTACKER HTTP CLIENT', title: bearer ? 'The real shop returns a bearer token to the attacker.' : `The real shop returns a Set-Cookie header to the attacker.`, body: bearer
          ? 'Because the attacker made the successful login request, its client receives and stores the bearer JWT. Their browser never receives this token.'
          : `Because the attacker—not their browser—made the real login request, the response goes back to the attacker’s HTTP client. Its server-side cookie jar saves “${tokenName}=…“ for shop.example. This does not place a shop cookie on the phishing origin.`, visual: 'cookie' },
        { label: 'Impersonation', actor: 'ATTACKER HTTP CLIENT → shop.example', title: 'The attacker can now act as them.', body: bearer
          ? 'The attacker sends Authorization: Bearer … from any client. The shop sees a valid authenticated session even though they never approved these later actions.'
          : `On later requests, the attacker’s HTTP client attaches its stored ${tokenName} to shop.example. The shop sees a valid authenticated session controlled entirely by the attacker. That enables account access, purchases, or data theft as them.`, visual: 'impact' }
      ],
      facts: [['!', 'Password + MFA relayed', 'danger'], ['→', 'Attacker owns new session', 'danger'], ['✓', 'Their cookie not copied', 'safe']]
    };
  }

  if (bearer) {
    return {
      tone: 'danger',
      scenes: [
        { label: 'Real prompt', actor: 'USER · shop.example', title: 'They sign in to the real shop.', body: 'The shop verifies their password and MFA normally.', visual: 'password' },
        { label: 'Token stored', actor: 'SHOP RESPONSE → USER’S BROWSER', title: 'The app stores its bearer JWT in localStorage.', body: 'The token is reusable proof of their session and is readable by code with access to the page.', visual: 'cookie' },
        { label: 'Token copied', actor: 'HOSTILE EXTENSION → COLLECTOR', title: 'The extension reads and exfiltrates the token.', body: 'Unlike an HttpOnly cookie, the token value can be copied out of the browser.', visual: 'relay' },
        { label: 'Off-device replay', actor: 'ATTACKER CLIENT → shop.example', title: 'The attacker replays it anywhere.', body: 'Authorization: Bearer … gives the attacker their authenticated authority until the token expires or is revoked.', visual: 'impact' }
      ],
      facts: [['!', 'Token value exposed', 'danger'], ['→', 'Off-device replay', 'danger'], ['—', 'Not ambient CSRF', 'safe']]
    };
  }

  return {
    tone: 'warning',
    scenes: [
      { label: 'Real prompt', actor: 'USER · shop.example', title: 'They sign in to the real shop.', body: 'The shop verifies their password and MFA normally.', visual: 'password' },
      { label: 'Cookie stored', actor: 'SHOP RESPONSE → USER’S BROWSER', title: `The browser stores the ${tokenName}.`, body: 'HttpOnly prevents page and extension content scripts from reading the credential value.', visual: 'cookie' },
      { label: 'Read blocked', actor: 'HOSTILE EXTENSION · PAGE CONTEXT', title: 'The extension cannot copy the token.', body: 'Cookie secrecy still holds. But the authenticated page remains available to hostile local code.', visual: 'blocked' },
      { label: 'Session ridden', actor: 'USER’S BROWSER → shop.example', title: 'The extension triggers or changes a shop request.', body: `The browser automatically attaches the ${tokenName}. The attacker gains an authenticated action without ever learning the token string.`, visual: 'impact' }
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
              <div className="auth-popup-fields">{scene.visual === 'mfa' ? <code>4 8 1 2 0 6</code> : <><i>user@example.com</i><i>••••••••••••</i></>}</div><b>{scene.visual === 'mfa' ? 'VERIFY' : 'CONTINUE'} →</b>
            </div> : <div className="auth-transfer">
              <span>{scene.visual === 'cookie' ? 'RESPONSE RECEIVED' : scene.visual === 'blocked' ? 'READ ATTEMPT' : scene.visual === 'impact' ? 'AUTHENTICATED REQUEST' : 'SERVER RELAY'}</span>
              <code>{scene.visual === 'cookie' ? (model === 'bearer' ? 'Authorization token → attacker client' : 'Set-Cookie: __Host-session=eyJ…') : scene.visual === 'blocked' ? 'document.cookie  ✕  HttpOnly' : scene.visual === 'impact' ? 'Cookie: __Host-session=eyJ…  ✓' : 'POST shop.example/login'}</code>
              <strong>{scene.visual === 'blocked' ? 'VALUE HIDDEN' : scene.visual === 'impact' ? 'ACTING AS USER' : 'ATTACKER-CONTROLLED CLIENT'}</strong>
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
        <strong>{branch === 'phishing' ? 'Watch the attacker relay sign-in, receive a new session, then impersonate them.' : 'Watch where local code can intercept—or ride—the stored session.'}</strong>
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
      <motion.div className="user-thought" initial={reduceMotion ? false : { opacity: 0, transform: 'translateY(8px)' }} animate={{ opacity: 1, transform: 'translateY(0px)' }} transition={{ duration: .35, ease: [.23, 1, .32, 1] }}><span>THEY SEE</span><strong>“The checkout I expected.”</strong></motion.div>
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
        {phishing ? <div className="handler-chain"><motion.b initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: .08 }}>Pay click</motion.b><i>→</i><motion.b initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: .2 }}>preventDefault()</motion.b><i>→</i><motion.b className="is-danger" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: .32 }}>POST /collect</motion.b></div> : <div className="dom-diff"><code><del>delivery.account = "user@home"</del><ins>delivery.account = "drop_772"</ins></code><motion.i initial={reduceMotion ? false : { transform: 'scaleX(0)' }} animate={{ transform: 'scaleX(1)' }} transition={{ duration: .45, delay: .22, ease: [.23, 1, .32, 1] }} /></div>}
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
      <div className="click-route"><RequestMap branch={branch} run={run} reduceMotion={reduceMotion} /><button type="button" onClick={() => setRun(value => value + 1)}>Replay their click ↻</button></div>
    </div>
  );
}

function RequestJourneyVisual({ branch, reduceMotion }) {
  const requestOptions = branch === 'phishing'
    ? {
        collector: { label: '1 · Collector', method: 'POST shop-example.help/collect', origin: 'Origin: https://shop-example.help', credential: 'Cookie[shop.example]: not attached', intent: 'They voluntarily submitted fields', authority: 'Attacker stores password, OTP, checkout data', outcome: 'CAPTURED · browser controls intact' },
        replay: { label: '2 · Replay', method: 'POST shop.example/session', origin: 'Server-to-server · no browser Origin', credential: 'email + password + live OTP', intent: 'Stolen proof; not their current intent', authority: 'Shop may mint session=s_attacker', outcome: 'NEW SESSION · not their cookie' }
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
    power: 'They can hand over secrets and form data.',
    crossed: 'Human destination checking',
    standing: 'The browser still isolates the real shop session.',
    request: 'POST shop-example.help/collect/login',
    detail: 'The collector receives only what they submit. A separate replay may create a new attacker session; their original HttpOnly cookie is not stolen.'
  },
  csrf: {
    label: 'CSRF', hint: 'borrowed session', icon: '↪', context: 'On another site, sending toward the shop',
    power: 'The browser may attach their session for one action.',
    crossed: 'Proof that they intended this request',
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
      <div className="receipt-column"><span>USER’S SCREEN</span><BrowserWindow branch={branch} view="receipt" /></div>
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
          {scene.label !== 'The sign-in' && <VisualEvidence items={story.evidence} reduceMotion={reduceMotion} />}
        </motion.div>
      </AnimatePresence>
    </section>
  );
}

function BrowserAttackLab() {
  const reduceMotion = useReducedMotion();
  const [mode, setMode] = useState('csrf');
  const [run, setRun] = useState(0);
  const csrf = mode === 'csrf';
  const steps = csrf
    ? [['evil.example', 'HTML form submits cross-site'], ['browser', 'Cookie may attach automatically'], ['shop.example', 'Request arrives; response stays opaque']]
    : [['stored comment', '<img onerror=attack()>'], ['shop.example DOM', 'Unsafe HTML sink creates code'], ['same-origin script', 'Reads DOM, token, and response']];
  return <div className={`browser-attack-lab mode-${mode}`}>
    <div className="lab-mode-tabs" role="group" aria-label="Choose browser attack demonstration">{['csrf', 'xss'].map(value => <button type="button" key={value} className={mode === value ? 'is-selected' : ''} onClick={() => { setMode(value); setRun(count => count + 1); }}>{value.toUpperCase()}<small>{value === 'csrf' ? 'cross-site send' : 'same-origin execution'}</small></button>)}</div>
    <div className="attack-demo" key={`${mode}-${run}`}>
      <div className="attack-code"><span>ATTACK INPUT</span><code>{csrf ? '<form action="https://shop.example/api/pay" method="POST">' : 'results.innerHTML = userComment'}</code><code>{csrf ? '<input name="amount" value="129">' : 'userComment = `<img src=x onerror=attack()>`'}</code></div>
      <div className="attack-route">{steps.map(([title, body], index) => <motion.div key={title} initial={reduceMotion ? false : { opacity: 0, transform: 'translateX(-12px)' }} animate={{ opacity: 1, transform: 'translateX(0)' }} transition={{ duration: .28, delay: reduceMotion ? 0 : index * .22, ease: [.23, 1, .32, 1] }}><span>0{index + 1}</span><strong>{title}</strong><small>{body}</small>{index < 2 && <i>→</i>}</motion.div>)}</div>
      <div className="attack-verdict"><div><span>ATTACKER CAN</span><strong>{csrf ? 'Cause a state-changing request' : 'Act and read as shop.example'}</strong></div><div><span>PRIMARY CONTROLS</span><strong>{csrf ? 'SameSite + Origin + Fetch Metadata + CSRF token' : 'Contextual encoding + safe sinks; CSP/Trusted Types layer'}</strong></div></div>
      <button type="button" className="diagram-replay" onClick={() => setRun(count => count + 1)}>Replay mechanism ↻</button>
    </div>
  </div>;
}

function TLSChainVisual() {
  const reduceMotion = useReducedMotion();
  const chain = [
    ['LEAF', 'shop.example', 'SAN contains shop.example · valid now · signed by intermediate'],
    ['INTERMEDIATE', 'Example Issuing CA 02', 'CA=true · keyCertSign · signed by root'],
    ['TRUST ANCHOR', 'Example Root CA', 'Public key preinstalled in OS/browser trust store']
  ];
  return <div className="tls-chain-visual"><div className="certificate-chain">{chain.map(([type, name, detail], index) => <motion.div key={type} initial={reduceMotion ? false : { opacity: 0, transform: 'translateY(8px)' }} animate={{ opacity: 1, transform: 'translateY(0)' }} transition={{ duration: .3, delay: reduceMotion ? 0 : index * .16 }}><span>{type}</span><strong>{name}</strong><code>{detail}</code>{index < 2 && <i>signature verifies ↓</i>}</motion.div>)}</div><div className="tls-checks"><span>CLIENT VALIDATES</span>{['Hostname / SAN match', 'Signature path to trusted root', 'Validity period + constraints', 'Revocation policy where applicable'].map(item => <strong key={item}>✓ {item}</strong>)}<code>ECDHE → shared traffic keys<br />AEAD → confidentiality + integrity</code></div></div>;
}

function HeadersVisual() {
  const [selected, setSelected] = useState('csp');
  const headers = {
    csp: ['Content-Security-Policy', "default-src 'self'; script-src 'nonce-r4nd0m'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", 'Constrain script, plugin, base URL, and framing capabilities. Prefer nonces/hashes; avoid unsafe-inline.'],
    hsts: ['Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload', 'Tell clients to use HTTPS for future requests. Only trusted when received over HTTPS.'],
    nosniff: ['X-Content-Type-Options', 'nosniff', 'Require declared MIME types for script and style destinations.'],
    referrer: ['Referrer-Policy', 'strict-origin-when-cross-origin', 'Limit URL detail sent in the Referer header across origins.'],
    permissions: ['Permissions-Policy', 'camera=(), microphone=(), geolocation=(self)', 'Delegate or disable powerful browser features for this document and frames.'],
    isolation: ['COOP + COEP', 'same-origin · require-corp', 'Isolate the browsing context group; required for cross-origin isolation and SharedArrayBuffer.']
  };
  const item = headers[selected];
  return <div className="headers-visual"><div className="header-list">{Object.entries(headers).map(([key, [name]]) => <button type="button" key={key} className={selected === key ? 'is-selected' : ''} onClick={() => setSelected(key)}><span>{name}</span><small>{selected === key ? 'INSPECTING' : 'RESPONSE HEADER'}</small></button>)}</div><div className="header-inspector" aria-live="polite"><span>HTTP/2 200</span><code><b>{item[0]}:</b> {item[1]}</code><strong>{item[2]}</strong><div><i>NOT A SUBSTITUTE FOR</i><p>Server authorization · safe query APIs · output encoding · business-rule enforcement</p></div></div></div>;
}

function SupplyChainVisual() {
  const reduceMotion = useReducedMotion();
  const stages = [['SOURCE', 'review + protected branch'], ['RESOLVE', 'lockfile + registry policy'], ['BUILD', 'isolated ephemeral runner'], ['ATTEST', 'SBOM + provenance + signature'], ['DEPLOY', 'verify digest + signature'], ['RUN', 'least privilege + inventory']];
  return <div className="supply-visual"><div className="supply-pipeline">{stages.map(([title, control], index) => <motion.div key={title} initial={reduceMotion ? false : { opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: .25, delay: reduceMotion ? 0 : index * .12 }}><span>0{index + 1}</span><strong>{title}</strong><small>{control}</small>{index < stages.length - 1 && <i>→</i>}</motion.div>)}</div><div className="supply-evidence"><div><span>ARTIFACT IDENTITY</span><code>sha256:9b71…e2c4</code></div><div><span>PROVENANCE</span><code>repo@a813c2 · workflow/build.yml</code></div><div><span>DEPLOY POLICY</span><code>signature ✓ · builder allowed ✓</code></div></div><p><strong>Lockfiles answer “which version?”</strong> Signatures and provenance help answer “who built this artifact from what?” An SBOM answers “what is inside?” Runtime isolation limits what compromised code can reach.</p></div>;
}

function CertificateExhibit({ scene }) {
  const reduceMotion = useReducedMotion();
  const enter = index => ({
    initial: reduceMotion ? false : { opacity: 0, transform: 'translateY(12px)' },
    animate: { opacity: 1, transform: 'translateY(0px)' },
    transition: { duration: .38, delay: reduceMotion ? 0 : .12 + index * .07, ease: [.23, 1, .32, 1] }
  });

  const cards = scene.points.map(([label, title, detail], index) => (
    <motion.article key={`${label}-${title}`} {...enter(index)}>
      <span>{label}</span><strong>{title}</strong><code>{detail}</code>
    </motion.article>
  ));

  if (scene.visual === 'certificate') return (
    <div className="cert-exhibit exhibit-certificate" aria-label="Anatomy of a certificate">
      <motion.div className="cert-passport" {...enter(0)}>
        <header><span>X.509 · LEAF CERTIFICATE</span><b>VALID</b></header>
        <div className="cert-seal">N</div>
        <h3>api.shop.example</h3>
        <dl><div><dt>PUBLIC KEY</dt><dd>EC P-256 · 03:A7:91…</dd></div><div><dt>VALIDITY</dt><dd>24 hours</dd></div><div><dt>ISSUER</dt><dd>Northstar Intermediate CA</dd></div></dl>
        <footer>✦ issuer signature verified</footer>
      </motion.div>
      <p className="exhibit-caption">Public document <b>≠</b> private key</p>
    </div>
  );

  if (scene.visual === 'formats') return (
    <div className="cert-exhibit exhibit-formats" aria-label="Certificate format layers">
      <div className="format-sheets">{cards}</div>
      <motion.pre {...enter(4)}>-----BEGIN CERTIFICATE-----{`\n`}MIIBwzCCAWqgAwIBAgIR…{`\n`}-----END CERTIFICATE-----</motion.pre>
    </div>
  );

  if (scene.visual === 'chain') return (
    <div className="cert-exhibit exhibit-chain" aria-label="Leaf, intermediate, and root certificate chain">
      {scene.points.slice().reverse().map(([label, title, detail], index) => <motion.article key={label} {...enter(index)}><i>{index === 0 ? 'presented first' : index === 2 ? 'already trusted' : 'issuer verified'}</i><span>{label}</span><strong>{title}</strong><code>{detail}</code></motion.article>)}
    </div>
  );

  if (scene.visual === 'validation') return (
    <div className="cert-exhibit exhibit-validation" aria-label="Certificate path validation checklist">
      <div className="validation-terminal"><span>$ connect api.shop.example</span>{cards}<footer><b>ACCEPT</b> · authenticated encrypted channel</footer></div>
      <div className="validation-warning"><code>curl -k</code><strong>turns authentication off</strong></div>
    </div>
  );

  if (scene.visual === 'expiry') return (
    <div className="cert-exhibit exhibit-expiry" aria-label="Certificate validity and renewal timeline">
      <div className="expiry-track"><span>NOT BEFORE</span><i><b /></i><span>NOT AFTER</span><em>ROTATE HERE</em></div>
      <div className="cert-card-grid">{cards}</div>
    </div>
  );

  if (scene.visual === 'scope') return (
    <div className="cert-exhibit exhibit-scope" aria-label="Comparison between Web PKI and internal PKI">
      <section><span>OPEN INTERNET</span><strong>Web PKI</strong><p>Universal browser trust<br />Public DNS identities</p></section>
      <div><b>VS</b><small>different trust domains</small></div>
      <section><span>YOUR SYSTEM</span><strong>Internal PKI</strong><p>Private workload identity<br />Your issuance policy</p></section>
    </div>
  );

  if (scene.visual === 'proof') return (
    <div className="cert-exhibit exhibit-proof" aria-label="MAC and signature authority comparison">
      <section><span>MAC · SHARED</span><strong>Secret</strong><div><b>CREATE</b><b>VERIFY</b></div><p>Both parties hold both powers.</p></section>
      <section><span>SIGNATURE · ASYMMETRIC</span><strong>Key pair</strong><div><b>PRIVATE · SIGN</b><b>PUBLIC · VERIFY</b></div><p>Verification does not grant forgery.</p></section>
    </div>
  );

  if (scene.visual === 'keypair' || scene.visual === 'issuance') return (
    <div className={`cert-exhibit exhibit-sequence exhibit-${scene.visual}`} aria-label={`${scene.title} sequence`}>
      {cards}
    </div>
  );

  return <div className={`cert-exhibit cert-card-grid exhibit-${scene.visual}`} aria-label={`${scene.title} key ideas`}>{cards}</div>;
}

function CertificateChapter({ scene }) {
  const reduceMotion = useReducedMotion();
  return (
    <section className={`scene-shell certificate-chapter chapter-${scene.visual}`} aria-labelledby={`chapter-${scene.zone}`}>
      <div className="chapter-copy">
        <div className="scene-index"><span>{scene.eyebrow}</span><strong>{scene.time}</strong></div>
        <motion.h2 id={`chapter-${scene.zone}`} initial={reduceMotion ? false : { opacity: 0, transform: 'translateY(14px)' }} animate={{ opacity: 1, transform: 'translateY(0px)' }} transition={{ duration: .48, ease: [.23, 1, .32, 1] }}>{scene.title}</motion.h2>
        <p className="scene-thesis">{scene.thesis}</p>
        <div className="chapter-takeaway"><span>KEEP THIS</span><strong>{scene.takeaway}</strong></div>
      </div>
      <CertificateExhibit scene={scene} />
      <footer className="chapter-footer"><span>{scene.label}</span><a href="https://smallstep.com/blog/everything-pki/" target="_blank" rel="noreferrer">Based on Everything PKI by Smallstep ↗</a></footer>
    </section>
  );
}
function PkiToAppBridge({ next }) {
  const reduceMotion = useReducedMotion();
  const checks = [
    ['CERTIFICATE', 'A trusted issuer bound a public key to the server name.', 'api.shop.example ↔ EC public key'],
    ['TLS CHANNEL', 'The browser protected confidentiality and integrity in transit.', 'network observer blocked'],
    ['APPLICATION', 'Intent, authorization, input, and business rules are still unproven.', 'the request remains untrusted']
  ];
  return (
    <section className="scene-shell pki-app-bridge" aria-labelledby="pki-app-bridge-title">
      <div className="pki-app-bridge-copy">
        <div className="scene-index"><span>Certificates → application security</span><strong>connection established</strong></div>
        <p className="scene-kicker">The handshake is done</p>
        <h2 id="pki-app-bridge-title">The certificate got us to a named server. Now what?</h2>
        <p className="scene-thesis">A protected connection can still reach the wrong origin, carry a harmful request, or run beside hostile local code. TLS authenticates the endpoint—not the person’s intent or the application’s decisions.</p>
        <button className="primary-action" type="button" onClick={next}>Start Request Under Fire <span aria-hidden="true">→</span></button>
      </div>
      <div className="pki-app-handoff" role="img" aria-label="A certificate establishes server identity and TLS protects the channel before application checks begin">
        <div className="handoff-route" aria-hidden="true"><span>BROWSER</span><i /><b>TLS</b><i /><span>SERVER</span></div>
        {checks.map(([label, title, detail], index) => (
          <motion.article key={label}
            initial={reduceMotion ? false : { opacity: 0, transform: 'translateY(14px)' }}
            animate={{ opacity: 1, transform: 'translateY(0)' }}
            transition={{ duration: .38, delay: reduceMotion ? 0 : index * .13, ease: [.23, 1, .32, 1] }}>
            <span>0{index + 1} · {label}</span><strong>{title}</strong><code>{detail}</code>
          </motion.article>
        ))}
        <div className="handoff-verdict"><span>THE HANDOFF</span><strong>The certificate answered who is on the other end. The application must decide what happens next.</strong></div>
      </div>
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
        <p className="scene-thesis">You saw how one request caused harm. Now apply five reusable lessons across browser, edge, application, data, and operational boundaries. At each one, identify the claim, the attack, and the control.</p>
        <button className="primary-action" type="button" onClick={next}>Start the review <span aria-hidden="true">→</span></button>
      </div>
      <div className="bridge-map" role="img" aria-label="Moving from the concrete incident to reusable security questions">
        <div><span>INCIDENT</span><strong>{branch === 'phishing' ? 'They used a checkout page on the wrong origin.' : 'A hostile browser extension changed data on the correct site.'}</strong></div>
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

function LifecycleScene() {
  const stages = [
    ['01', 'DESIGN', 'Model assets, threats, boundaries, abuse cases, and safe failure states.'],
    ['02', 'BUILD', 'Use secure defaults, managed secrets, reviewed dependencies, and least privilege.'],
    ['03', 'VERIFY', 'Test access rules, misuse cases, code, dependencies, and configurations.'],
    ['04', 'DEPLOY', 'Harden transport and runtime policy; patch and inventory what ships.'],
    ['05', 'MONITOR', 'Collect redacted evidence and alert on owned, actionable signals.'],
    ['06', 'RESPOND', 'Contain, revoke, communicate, recover, and test restoration.']
  ];
  return <section className="scene-shell lifecycle-scene" aria-labelledby="lifecycle-title">
    <div className="foundation-heading"><div className="scene-index"><span>Secure development lifecycle</span><strong>continuous</strong></div><h2 id="lifecycle-title">Security continues after the request.</h2><p className="scene-thesis">Layer controls so the system can prevent vulnerabilities, constrain exploitation, limit blast radius, detect abuse, and recover.</p></div>
    <div className="lifecycle-track">{stages.map(([number, title, body]) => <article key={number}><span>{number}</span><strong>{title}</strong><p>{body}</p></article>)}</div>
    <div className="foundation-footer"><span>OWNERSHIP</span><strong>Every control needs an owner, evidence, and a review cadence.</strong></div>
  </section>;
}

function AppendixPlaceholder() {
  const topics = ['Cookie and JWT storage', 'XSS output contexts and sanitization', 'Password storage and passkeys', 'CORS and cross-origin isolation', 'File upload security', 'SSRF and outbound request policy', 'Secrets and key management', 'API abuse and rate limiting', 'Cloud identity and metadata services', 'Incident response checklist'];
  return <section className="scene-shell appendix-scene" aria-labelledby="appendix-title">
    <div className="foundation-heading"><div className="scene-index"><span>Optional modules · deferred</span><strong>placeholder</strong></div><h2 id="appendix-title">Future deep dives.</h2><p className="scene-thesis">These topics deserve focused optional scenes. They are listed here without expanding the core presentation.</p></div>
    <div className="appendix-list">{topics.map((topic, index) => <div key={topic}><span>{String(index + 1).padStart(2, '0')}</span><strong>{topic}</strong><small>PLANNED MODULE</small></div>)}</div>
  </section>;
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
        <div className="scene-index"><span>Field test</span><strong>replay · {String(quiz.length).padStart(2, '0')} signals</strong></div>
        <p className="scene-kicker">Apply the method</p>
        <h2 id="field-title">Identify the failed check.</h2>
        <p className="scene-thesis">First, find the system boundary. Then select the control that verifies the claim.</p>
        <div className="field-score"><span>SECURITY SCORE</span><strong>{score} / {quiz.length}</strong></div>
      </div>
      <div className="quiz-card">
        <div className="quiz-meta"><span>SIGNAL {String(index + 1).padStart(2, '0')} / {String(quiz.length).padStart(2, '0')}</span><strong>req_7F2A · REPLAY</strong></div>
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
    ['01', 'What asset can be harmed?', 'Name confidentiality, integrity, availability, and impact.'],
    ['02', 'Who sent each claim?', 'Verify identity, origin, and request context.'],
    ['03', 'Can this user do this action?', 'Authorize the action and object for every request.'],
    ['04', 'Can input become code?', 'Use safe APIs and encode for the output context.'],
    ['05', 'Which system owns this value?', 'Re-derive price, ownership, state, and sequence server-side.'],
    ['06', 'What happens when controls fail?', 'Contain, detect, respond, and recover safely.']
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
  const [inputMode, setInputMode] = useState('pointer');
  const [direction, setDirection] = useState(1);
  const [sceneBrowserOpen, setSceneBrowserOpen] = useState(false);
  const scene = scenes[sceneIndex];
  const currentSection = scene.section ?? (sceneIndex < reflectionStartIndex ? 'journey' : 'reflections');
  const currentSession = sceneIndex <= certificateEndIndex ? 'certificates' : 'request';
  const sessionStartIndex = currentSession === 'certificates' ? 0 : requestStartIndex;
  const sessionEndIndex = currentSession === 'certificates' ? certificateEndIndex : scenes.length - 1;
  const sessionScenes = scenes.slice(sessionStartIndex, sessionEndIndex + 1);
  const sessionSceneIndex = sceneIndex - sessionStartIndex;

  useEffect(() => {
    document.body.dataset.input = inputMode;
  }, [inputMode]);

  useEffect(() => {
    document.body.dataset.session = currentSession;
  }, [currentSession]);

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

  function startSession(index) {
    goTo(index);
  }

  useEffect(() => {
    function onKeyDown(event) {
      if (document.querySelector('dialog[open], [role="dialog"][aria-modal="true"]') || sceneBrowserOpen) return;
      if (['INPUT', 'TEXTAREA', 'BUTTON', 'A'].includes(document.activeElement?.tagName)) return;
      if (event.key === 'ArrowRight' || event.key === 'PageDown') { event.preventDefault(); goTo(Math.min(sceneIndex + 1, sessionEndIndex), 'keyboard'); }
      if (event.key === 'ArrowLeft' || event.key === 'PageUp') { event.preventDefault(); goTo(Math.max(sceneIndex - 1, sessionStartIndex), 'keyboard'); }
      if (event.key === ' ') {
        event.preventDefault();
        if (scene.type === 'checkpoint' && phase < 2) { setInputMode('keyboard'); setPhase(value => value + 1); }
        else goTo(Math.min(sceneIndex + 1, sessionEndIndex), 'keyboard');
      }
      if (['1', '2', '3'].includes(event.key) && scene.type === 'checkpoint') { setInputMode('keyboard'); setPhase(Number(event.key) - 1); }
      if (event.key.toLowerCase() === 'o') lensRef.current?.showModal();
      if (event.key === 'Home') goTo(sessionStartIndex, 'keyboard');
      if (event.key === 'End') goTo(sessionEndIndex, 'keyboard');
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [sceneIndex, phase, scene.type, sceneBrowserOpen, sessionStartIndex, sessionEndIndex]);

  return (
    <>
      <a className="skip-link" href="#presentation">Skip to presentation</a>
      <header className="topbar">
        <button className="brand" type="button" onClick={() => goTo(sessionStartIndex)} aria-label="Go to beginning of current session">
          <span className="brand-orbit" aria-hidden="true"><i /><i /></span>
          <span>{currentSession === 'certificates' ? <>CERTIFICATES <em>&amp; PKI</em></> : <>REQUEST <em>UNDER FIRE</em></>}</span>
        </button>
        <div className="live-clock" aria-live="polite"><span>{scene.zone.toUpperCase()}</span><strong>{scene.time === 'complete' || scene.time === 'replay' ? scene.time : `t = ${scene.time}`}</strong></div>
        <div className="top-actions">
          <div className="section-switcher" role="group" aria-label="Presentation sessions">
            <button type="button" className={currentSession === 'certificates' ? 'is-selected' : ''} onClick={() => startSession(0)}>Certificates &amp; PKI</button>
            <button type="button" className={currentSession === 'request' ? 'is-selected' : ''} onClick={() => startSession(requestStartIndex)}>Request Under Fire</button>
          </div>
          <button className="lens-button" type="button" onClick={() => lensRef.current?.showModal()}>OWASP <span>REFERENCE</span></button>
        </div>
      </header>

      <main id="presentation" className="stage" ref={stageRef} tabIndex="-1">
        <AnimatePresence mode="popLayout" initial={false}>
          <motion.div className="scene-frame" key={sceneIndex}
            initial={reduceMotion || inputMode === 'keyboard' ? false : { opacity: 0, transform: `translateX(${direction * 28}px) scale(.996)` }}
            animate={{ opacity: 1, transform: 'translateX(0px) scale(1)' }}
            exit={reduceMotion || inputMode === 'keyboard' ? { opacity: 0 } : { opacity: 0, transform: `translateX(${direction * -20}px) scale(.998)` }}
            transition={{ type: 'spring', visualDuration: .34, bounce: .04 }}>
            {scene.type !== 'opening' && <h1 className="sr-only">{currentSession === 'certificates' ? 'Certificates & PKI' : 'Request Under Fire'}: {scene.label}</h1>}
            {scene.type === 'opening' && <Opening next={() => goTo(sceneIndex + 1)} branch={branch} setBranch={setBranch} />}
            {scene.type === 'certificate-chapter' && <CertificateChapter scene={scene} />}
            {scene.type === 'pki-bridge' && <PkiToAppBridge next={() => startSession(requestStartIndex)} />}
            {scene.type === 'recon' && <ReconWorkbench next={() => goTo(sceneIndex + 1)} />}
            {scene.type === 'journey' && <JourneyScene scene={scene} branch={branch} setBranch={setBranch} />}
            {scene.type === 'bridge' && <ReflectionBridge branch={branch} next={() => goTo(sceneIndex + 1)} />}
            {scene.type === 'checkpoint' && <Checkpoint scene={scene} phase={phase} setPhase={setPhase} />}
            {scene.type === 'quiz' && <FieldTest />}
            {scene.type === 'lifecycle' && <LifecycleScene />}
            {scene.type === 'appendix' && <AppendixPlaceholder />}
            {scene.type === 'closing' && <Closing restart={() => goTo(requestStartIndex)} openLens={() => lensRef.current?.showModal()} />}
          </motion.div>
        </AnimatePresence>
      </main>

      <SceneBrowser open={sceneBrowserOpen} currentIndex={sceneIndex} onClose={() => setSceneBrowserOpen(false)} onSelect={goTo} />

      <nav className="deck-nav" aria-label="Presentation scenes">
        <button className="nav-arrow" type="button" onClick={() => goTo(sceneIndex - 1)} disabled={sceneIndex === sessionStartIndex} aria-label="Previous scene">←</button>
        <div className="nav-center">
          <button className="nav-meta" type="button" aria-expanded={sceneBrowserOpen} onClick={() => setSceneBrowserOpen(value => !value)}>
            <span>{currentSection} · {scene.label} <i>⌃ scene map</i></span><strong>{scene.minutes} MIN · {String(sessionSceneIndex + 1).padStart(2, '0')} / {String(sessionScenes.length).padStart(2, '0')}</strong>
          </button>
          <div className="progress-track" style={{ '--scene-count': sessionScenes.length }} role="tablist" aria-label={`${currentSession === 'certificates' ? 'Certificates and PKI' : 'Request Under Fire'} session scenes`}>
            <i className="progress-fill" style={{ transform: `scaleX(${sessionScenes.length === 1 ? 1 : sessionSceneIndex / (sessionScenes.length - 1)})` }} aria-hidden="true" />
            {sessionScenes.map((item, index) => {
              const globalIndex = sessionStartIndex + index;
              return <button type="button" role="tab" aria-selected={sceneIndex === globalIndex} aria-label={`Scene ${index + 1}: ${item.label}`} className={index === sessionSceneIndex ? 'is-current' : index < sessionSceneIndex ? 'is-past' : ''} onClick={() => goTo(globalIndex)} key={`${item.label}-${globalIndex}`}><i />{index === sessionSceneIndex && <motion.span className="progress-packet" layoutId="deck-playhead" transition={reduceMotion || inputMode === 'keyboard' ? { duration: 0 } : { type: 'spring', duration: .5, bounce: .1 }} aria-hidden="true" />}</button>;
            })}
          </div>
          <div className="nav-hint"><span>SPACE · reveal</span><span>← → · navigate</span></div>
        </div>
        <button className="nav-arrow" type="button" onClick={() => goTo(sceneIndex + 1)} disabled={sceneIndex === sessionEndIndex} aria-label="Next scene">→</button>
      </nav>

      <div className="scene-announcer sr-only" aria-live="polite">Scene {sessionSceneIndex + 1} of {sessionScenes.length} in the current session: {scene.label}</div>
      <LensDialog dialogRef={lensRef} />
    </>
  );
}
