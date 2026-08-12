import { useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'motion/react';
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
const phaseLabels = ['Trust claim', 'Break it', 'Restore it'];

const compromisePaths = {
  phishing: {
    short: 'Phishing site',
    label: 'A · Phishing site',
    description: 'A convincing surface on the wrong origin',
    color: 'var(--phish)',
    steps: ['The lure', 'Wrong origin', 'Maya types', 'Collector', 'Fake receipt']
  },
  extension: {
    short: 'Local extension',
    label: 'B · Local extension',
    description: 'The right site with hostile code beside it',
    color: 'var(--extension)',
    steps: ['The install', 'Right origin', 'DOM hook', 'Two requests', 'Real receipt']
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
      evidence: [['permission', 'read + change site data', 'browser'], ['trigger', '/checkout', 'attacker'], ['cookie', 'HttpOnly remains unreadable', 'secure']]
    }
  },
  {
    label: 'The arrival', time: 'T − 18 s', progress: 1, focus: 'maya',
    title: 'Maya sees a checkout. The browser sees a context.',
    thesis: 'Visual familiarity and technical identity are different signals.',
    phishing: {
      maya: { location: 'Tab · “Shop delivery”', status: 'Believes: shop.example', title: 'The page looks exactly right.', body: 'The cart, total, type, and logo all match the message she expected.' },
      browser: { location: 'Origin · shop-example.help', status: 'Actually: lookalike', title: 'The address bar tells the quieter story.', body: 'TLS protects this connection to the attacker-controlled domain. Same-origin rules keep the real shop cookie away.' },
      attacker: { location: 'Collector · listening', status: 'Waiting', title: 'No exploit is needed yet.', body: 'The attacker needs Maya to volunteer data to this origin.', artifact: '200 OK  ·  TLS valid' },
      evidence: [['seen by Maya', 'Shop checkout', 'maya'], ['actual origin', 'shop-example.help', 'attacker'], ['shop session', 'not attached', 'secure']]
    },
    extension: {
      maya: { location: 'Tab · shop.example/checkout', status: 'Correct destination', title: 'The page really is the shop.', body: 'The address, certificate, and visible checkout are all legitimate.' },
      browser: { location: 'Origin · shop.example', status: 'Extension active', title: 'A second execution context wakes up.', body: 'The granted extension injects a content script next to the page and observes DOM-visible fields.' },
      attacker: { location: 'Extension background worker', status: 'Connected', title: 'The foothold arrived locally.', body: 'Its command channel receives “checkout detected” and returns the collection rule.', artifact: 'event: CHECKOUT_DETECTED' },
      evidence: [['actual origin', 'shop.example', 'secure'], ['content script', 'active', 'attacker'], ['HttpOnly cookie', 'still unreadable', 'secure']]
    }
  },
  {
    label: 'The invisible edit', time: 'T − 400 ms', progress: 2, focus: 'browser',
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
      attacker: { location: 'Content script', status: 'Hook armed', title: 'Observe the click. Alter only what matters.', body: 'It cannot read the HttpOnly session cookie, but it can influence data the trusted page is about to submit.', artifact: 'delivery.account = "drop_772"' },
      evidence: [['visible total', 'RM129', 'maya'], ['delivery.account', 'drop_772', 'attacker'], ['session cookie', 'HttpOnly · unreadable', 'secure']]
    }
  },
  {
    label: 'The click', time: 'T = 0 ms', progress: 2, focus: 'split', pulse: true,
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
      browser: { location: 'Page + extension contexts', status: 'Two flows begin', title: 'One click wakes two listeners.', body: 'The shop builds its checkout request. The extension separately copies DOM-visible data to its background worker.' },
      attacker: { location: 'Extension background worker', status: 'Outbound queued', title: 'Ambient access turns into action.', body: 'The extension does not need the cookie value: the legitimate browser request already carries it to the shop.', artifact: 'shop fetch()  +  extension message' },
      evidence: [['gesture', 'trusted human click', 'maya'], ['shop request', 'cookie auto-attached', 'browser'], ['extension copy', 'DOM fields', 'attacker']]
    }
  },
  {
    label: 'Under the hood', time: 'T + 3 ms', progress: 3, focus: 'browser',
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
    label: 'The two receipts', time: 'T + 214 ms', progress: 4, focus: 'split',
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
    label: 'The rewind', time: 'T ↶', progress: 4, focus: 'browser', controls: true,
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
    title: 'A request is testimony.',
    thesis: 'The browser reports identity, origin, and intent. Every field is a claim—not a fact.',
    prompt: 'Which value becomes trustworthy merely because it arrived over HTTPS?',
    packet: [
      { label: 'POST', values: ['/api/checkout', '/api/checkout', '/api/checkout'] },
      { label: 'Cookie', values: ['session=s_7f2a', 'session=s_7f2a', 'session=s_7f2a · HttpOnly'] },
      { label: 'Origin', values: ['https://shop.example', 'https://evil.example', 'https://shop.example · verified'] },
      { label: 'X-CSRF', values: ['—', '—', 'csrf_91d… · verified'] },
      { label: 'Body', values: ['cart_1042 · RM129', 'cart_1042 · RM129', 'cart_1042 · RM129'] }
    ],
    phases: [
      { title: 'The browser says this is Maya.', body: 'A valid session cookie identifies a session. It does not prove that Maya intended this payment.', signal: 'Claim: identity + intent', result: 'UNVERIFIED CLAIMS' },
      { title: 'A hostile page can send a convincing request.', body: 'CSRF rides the browser’s ambient credentials. XSS is worse: malicious script acts with the user’s privileges.', signal: 'Attack: forged intent', result: 'REQUEST FORGED' },
      { title: 'Make intent expensive to forge.', body: 'Use secure cookie attributes, verify Origin or a CSRF token, and reduce script execution with a strict CSP.', signal: 'Control: browser + server', result: 'INTENT VERIFIED', actions: ['SameSite + HttpOnly', 'Origin / CSRF check', 'Strict CSP'] }
    ],
    note: 'Ask the room the prompt before revealing the answer: none of the values are facts just because TLS delivered them. TLS protects transport; the application still has to verify the claims.'
  },
  {
    label: 'The edge', zone: 'edge', time: '31.700 ms', minutes: 2.5, lenses: ['A02', 'A04'],
    title: 'TLS protects the trip. Not the story.',
    thesis: 'Encryption stops observers from reading or changing bytes in transit. It does not make the sender honest or the edge correctly configured.',
    prompt: 'What does the padlock actually prove—and what does it leave unproven?',
    packet: [
      { label: 'TLS', values: ['1.3 · certificate valid', '1.3 · certificate valid', '1.3 + HSTS'] },
      { label: 'Host', values: ['shop.example', 'admin.shop.example', 'shop.example · allow-listed'] },
      { label: 'Route', values: ['/api/checkout', '/debug/config', '/api/checkout'] },
      { label: 'CORS', values: ['shop.example', '* + credentials', 'explicit origins'] },
      { label: 'Client IP', values: ['203.0.113.42', 'X-Forwarded-For: 127.0.0.1', 'trusted proxy chain'] }
    ],
    phases: [
      { title: 'The tunnel is encrypted.', body: 'Good. The request crossed the network privately and with transport integrity.', signal: 'Claim: protected transit', result: 'TLS OK' },
      { title: 'The side door is still open.', body: 'A public debug route, permissive origin policy, or spoofed proxy header can bypass otherwise secure code.', signal: 'Attack: unintended exposure', result: 'EDGE MISCONFIGURED' },
      { title: 'Expose only the contract you intend.', body: 'Use hardened baselines, explicit routes and origins, modern TLS, HSTS, and trusted proxy configuration.', signal: 'Control: minimize exposure', result: 'EDGE POLICY PASSED', actions: ['Explicit routes', 'Origin allow-list', 'Trusted proxies'] }
    ],
    note: 'Do not sell the WAF as a universal fix. The edge can reject obvious abuse and enforce transport policy, but it cannot decide whether Maya may buy this cart.'
  },
  {
    label: 'The API gate', zone: 'api', time: '64.200 ms', minutes: 3, lenses: ['A01', 'A07'],
    title: 'Authenticated is not authorized.',
    thesis: 'The session can be genuine while the requested object, action, or tenant is forbidden.',
    prompt: 'Where must the ownership check live if the UI already hides other people’s carts?',
    packet: [
      { label: 'session.user', values: ['maya', 'maya', 'maya'] },
      { label: 'action', values: ['checkout', 'checkout', 'checkout'] },
      { label: 'cartId', values: ['cart_1042', 'cart_1043', 'cart_1043'] },
      { label: 'cart.owner', values: ['maya', 'devon', 'devon'] },
      { label: 'decision', values: ['not checked', '200 OK', '403 + req_7F2A'] }
    ],
    phases: [
      { title: 'Maya has a valid session.', body: 'Authentication answers “who?” The request still needs an answer to “may this user do this to this object?”', signal: 'Claim: session is valid', result: 'IDENTITY KNOWN' },
      { title: 'One changed identifier crosses a tenant boundary.', body: 'The predictable ID reveals the test. Missing object-level authorization creates the breach.', signal: 'Attack: cart_1042 → cart_1043', result: 'DEVON’S CART EXPOSED' },
      { title: 'Bind subject, action, and object.', body: 'Authorize on the trusted server for every request, deny by default, and test the full access matrix.', signal: 'Control: object authorization', result: '403 FORBIDDEN', actions: ['Deny by default', 'Check ownership', 'Test the matrix'] }
    ],
    note: 'Pause after the attack. Predictable identifiers are not the root cause. Random IDs are useful defense in depth; only server-side authorization restores the promise.'
  },
  {
    label: 'The parser', zone: 'parser', time: '68.900 ms', minutes: 3, lenses: ['A05'],
    title: 'Data can become code.',
    thesis: 'The moment untrusted bytes reach an interpreter, separation between structure and data becomes a security boundary.',
    prompt: 'What is safer than trying to write the perfect list of forbidden characters?',
    packet: [
      { label: 'coupon', values: ['WELCOME10', "x' OR '1'='1", "x' OR '1'='1"] },
      { label: 'query', values: ["… code = 'WELCOME10'", "… code = 'x' OR '1'='1'", '… code = $1'] },
      { label: 'params', values: ['—', '—', '["x\' OR \'1\'=\'1"]'] },
      { label: 'rows', values: ['1 coupon', 'all coupons', '0 coupons'] },
      { label: 'mode', values: ['concatenated', 'concatenated', 'parameterized'] }
    ],
    phases: [
      { title: 'The coupon is supposed to be data.', body: 'String concatenation quietly grants it the power to rewrite SQL structure.', signal: 'Claim: a string stays a string', result: 'STRUCTURE + DATA MIXED' },
      { title: 'One quote changes the program.', body: 'The payload closes the string and appends syntax. The interpreter does exactly what the application asked.', signal: 'Attack: syntax injection', result: 'QUERY REWRITTEN' },
      { title: 'Separate structure from values.', body: 'Parameterized APIs send the query and its data independently. Validate shape; encode for the output context.', signal: 'Control: safe interpreter API', result: 'PAYLOAD STAYS DATA', actions: ['Parameterized SQL', 'Contextual encoding', 'Allow-list shape'] }
    ],
    note: '“Sanitize input” is too vague to be useful. SQL, HTML, shell, and URLs have different grammars. Prefer APIs that make the safe structure explicit.'
  },
  {
    label: 'Business logic', zone: 'logic', time: '70.100 ms', minutes: 3, lenses: ['A06'],
    title: 'Valid can still be fraudulent.',
    thesis: 'Schemas catch malformed input. They cannot define who owns price, sequence, frequency, or state.',
    prompt: 'The JSON is valid and the total is positive. Why is this request still wrong?',
    packet: [
      { label: 'sku', values: ['COURSE-01', 'COURSE-01', 'COURSE-01'] },
      { label: 'quantity', values: ['1', '1', '1'] },
      { label: 'clientTotal', values: ['129.00', '1.00', 'ignored'] },
      { label: 'catalogTotal', values: ['not loaded', 'not loaded', '129.00'] },
      { label: 'idempotency', values: ['ik_7f2a', 'replayed ×12', 'ik_7f2a · seen'] }
    ],
    phases: [
      { title: 'The payload passes validation.', body: 'Every field has the correct type. The client still controls a value that only the domain should own.', signal: 'Claim: valid means allowed', result: 'SCHEMA VALID' },
      { title: 'The attacker stays inside the schema.', body: 'They lower the total and replay the request. No parser error is required to abuse missing business rules.', signal: 'Attack: price + replay abuse', result: 'RM1.00 × 12' },
      { title: 'Derive truth on the trusted side.', body: 'Load catalog price, enforce state transitions, and make the sensitive operation idempotent.', signal: 'Control: domain invariants', result: 'RM129.00 · ONCE', actions: ['Server-owned price', 'State machine', 'Idempotency key'] }
    ],
    note: 'This is the pivot from input validation to secure design. Ask which invariant was missing. The strongest answer: the server, not the buyer, owns the payable amount.'
  },
  {
    label: 'The data layer', zone: 'data', time: '71.800 ms', minutes: 2.5, lenses: ['A04', 'A08'],
    title: 'Contain the blast radius.',
    thesis: 'Assume a request eventually reaches deeper than intended. Data minimization and least privilege decide whether one bug becomes a breach.',
    prompt: 'If the application role is compromised, what should it still be unable to read or change?',
    packet: [
      { label: 'db role', values: ['app_owner', 'app_owner', 'checkout_writer'] },
      { label: 'can read', values: ['all tables', 'users + secrets + cards', 'checkout view only'] },
      { label: 'payment data', values: ['stored PAN', 'exported PAN', 'provider token'] },
      { label: 'key', values: ['long-lived env key', 'copied from process', 'scoped KMS identity'] },
      { label: 'write', values: ['any state', 'paid=true', 'approved transition only'] }
    ],
    phases: [
      { title: 'The application can reach the database.', body: 'That is necessary. Ownership-level privileges and unnecessary sensitive data are not.', signal: 'Claim: the app is trusted', result: 'BLAST RADIUS: ENTIRE DB' },
      { title: 'One app bug inherits database-owner power.', body: 'A compromised process reads secrets, exports payment data, or writes impossible state.', signal: 'Attack: privilege amplification', result: 'BREACH EXPANDS' },
      { title: 'Keep less. Permit less. Rotate faster.', body: 'Tokenize payment data, use narrow roles and views, manage keys outside code, and enforce valid writes.', signal: 'Control: least privilege', result: 'BLAST RADIUS CONTAINED', actions: ['Minimize data', 'Narrow DB role', 'Managed keys'] }
    ],
    note: 'Cryptography does not rescue an overprivileged process holding the decryption key. Minimize the data first, then choose the right primitive and key lifecycle.'
  },
  {
    label: 'The failure path', zone: 'failure', time: '83.400 ms', minutes: 3, lenses: ['A10'],
    title: 'Failure is attacker-controlled input.',
    thesis: 'Timeouts, retries, races, and partial writes are alternate routes through the same security model.',
    prompt: 'When the risk service times out, which state is safe for this payment?',
    packet: [
      { label: 'risk service', values: ['pending', 'timeout', 'timeout'] },
      { label: 'fallback', values: ['unspecified', 'approve()', 'queueForReview()'] },
      { label: 'retry', values: ['unbounded', '×47', 'bounded + jitter'] },
      { label: 'database', values: ['charge → order', 'charge ✓ · order ✕', 'atomic transition'] },
      { label: 'decision', values: ['unknown', 'approved', 'review'] }
    ],
    phases: [
      { title: 'The happy path has a guard.', body: 'But the product has not decided what happens when that guard is unavailable.', signal: 'Claim: dependencies answer', result: 'FAILURE STATE UNDEFINED' },
      { title: 'The attacker removes the guard.', body: 'Resource exhaustion or a crafted edge case drives execution into “approve on error” and retry storms.', signal: 'Attack: force exceptional path', result: 'FAIL OPEN' },
      { title: 'Choose the safe state before production does.', body: 'Bound retries and resources, make writes atomic, and route uncertain payments to review or rejection.', signal: 'Control: explicit failure policy', result: 'HELD FOR REVIEW', actions: ['Fail to a safe state', 'Bound everything', 'Atomic writes'] }
    ],
    note: '“Fail closed” is context-dependent. A recommendation can degrade; a payment authorization may need review or rejection. The non-negotiable part is an explicit, tested state.'
  },
  {
    label: 'The return', zone: 'return', time: '214.000 ms', minutes: 3, lenses: ['A02', 'A09'],
    title: 'Return less. Record more.',
    thesis: 'The client needs a stable outcome. Defenders need a correlated story. Those are different audiences and different contracts.',
    prompt: 'Which details help the user recover, and which only help an attacker map the system?',
    packet: [
      { label: 'status', values: ['500', '500', '503'] },
      { label: 'client body', values: ['Error', 'stack + SQL + host', 'Payment pending'] },
      { label: 'request ID', values: ['—', '—', 'req_7F2A'] },
      { label: 'server log', values: ['console.log(error)', 'token + stack', 'structured + redacted'] },
      { label: 'alert', values: ['none', 'none', 'owner paged'] }
    ],
    phases: [
      { title: 'Something went wrong.', body: 'A generic error without a request ID leaves the user stuck and the defender blind.', signal: 'Claim: failure is self-evident', result: 'NO SHARED HANDLE' },
      { title: 'The response becomes reconnaissance.', body: 'A raw stack trace reveals paths, versions, database hosts, and queries while logs may leak tokens.', signal: 'Attack: harvest internals', result: 'INTERNALS DISCLOSED' },
      { title: 'Split the public and private contracts.', body: 'Return a safe message plus request ID. Keep redacted detail in correlated logs with thresholds and an owner.', signal: 'Control: least disclosure + evidence', result: '503 · req_7F2A', actions: ['Stable client error', 'Correlated events', 'Owned alert'] }
    ],
    note: 'Logging is not evidence until events correlate, cross a threshold, and reach an owner. Also show that logs are a data store: never place credentials or tokens in them.'
  }
];

const quiz = [
  { question: 'The session is valid, but cart_1043 belongs to Devon. What restores the broken promise?', choices: ['Use random IDs', 'Check subject + action + object', 'Hide the cart ID'], right: 1, why: 'Authorization must bind Maya, checkout, and cart_1043 on the trusted server.' },
  { question: 'The risk service times out after the card is charged but before the order commits. What was missing?', choices: ['A longer timeout', 'Atomic state and a safe failure policy', 'A more detailed client error'], right: 1, why: 'The failure route needs an explicit safe state and an atomic or recoverable write model.' },
  { question: 'A request is protected by TLS and carries valid JSON. Is it trusted?', choices: ['Yes—both layers passed', 'Only behind a WAF', 'No—transport and syntax do not prove authority or intent'], right: 2, why: 'Each handoff must verify its own promise. No earlier green check can substitute for that.' }
];

const journeyScenes = journeyBeats.map((item, index) => ({ ...item, type: 'journey', zone: `journey-${index + 1}`, minutes: 1.5, note: `Let the ${item.label.toLowerCase()} visual complete before explaining it. Point to the colored route or highlighted object first; use the evidence chips only to confirm what the audience has already seen.` }));
const scenes = [
  { type: 'opening', section: 'journey', label: 'Case open', zone: 'open', time: 'before the click', minutes: 1.5, note: 'Open with the central question: “When Maya clicks Pay, whose code receives her intent?” Let the audience choose which compromise path to trace first.' },
  ...journeyScenes.map(item => ({ ...item, section: 'journey' })),
  { type: 'bridge', section: 'reflections', label: 'What we learned', zone: 'reflect', time: 'rewind complete', minutes: 1.5, note: 'The incident has now been witnessed. Move from story to method: the remaining scenes name the trust boundaries and controls the audience just saw.' },
  ...checkpoints.map(item => ({ ...item, type: 'checkpoint', section: 'reflections' })),
  { type: 'quiz', section: 'reflections', label: 'Field test', zone: 'replay', time: 'replay', minutes: 3, note: 'Let the room vote before selecting an answer. Reward the reasoning, not the acronym. The method is: locate the boundary, name the promise, then choose the control.' },
  { type: 'closing', section: 'reflections', label: 'Case closed', zone: 'closed', time: 'complete', minutes: 2, note: 'Close on the five questions. Ask each person to choose one production request this week and draw its trust boundaries with their team.' }
];
const reflectionStartIndex = scenes.findIndex(item => item.type === 'bridge');

function formatClock(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

function LensBadges({ lenses = [] }) {
  return <div className="lens-badges" role="group" aria-label="OWASP lenses">{lenses.map(code => <span key={code}>{code} <small>{owasp[code][0]}</small></span>)}</div>;
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

function RequestLab({ scene, phase, setPhase }) {
  const beat = scene.phases[phase];
  return (
    <div className={`request-lab phase-${phase}`}>
      <div className="lab-header">
        <span>LIVE REQUEST · req_7F2A</span>
        <strong>{scene.time}</strong>
      </div>
      <RouteLine zone={scene.zone} />
      <div className="packet-grid" role="group" aria-label="Request facts at this checkpoint">
        {scene.packet.map((line, index) => (
          <div className={`packet-line ${index === phase + 1 || (phase === 2 && index === scene.packet.length - 1) ? 'is-hot' : ''}`} key={line.label}>
            <span>{line.label}</span><code>{line.values[phase]}</code>
          </div>
        ))}
      </div>
      <div className="beat-card" aria-live="polite">
        <div className="beat-meta"><span>{beat.signal}</span><strong>{beat.result}</strong></div>
        <h3>{beat.title}</h3>
        <p>{beat.body}</p>
        {beat.actions && <div className="control-chips">{beat.actions.map(action => <span key={action}>✓ {action}</span>)}</div>}
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
        <p className="scene-kicker">Incident theatre · Maya clicks Pay</p>
        <h1 id="opening-title">One click<span>.</span><br />Three realities.</h1>
        <p className="opening-lede">Maya sees a button. The browser sees a context. <strong>The attacker sees an opportunity.</strong></p>
        <p className="opening-thesis">Trace the same moment through every pair of eyes. Choose how the compromise entered Maya’s world.</p>
        <PathSwitch branch={branch} setBranch={setBranch} />
        <button className="primary-action" type="button" onClick={next}>Enter the incident <span aria-hidden="true">→</span></button>
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

function CausalThread({ path, progress, reduceMotion }) {
  return (
    <div className="causal-thread" role="group" aria-label={`${path.short} journey progress: ${path.steps[progress]}`}>
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

function BrowserWindow({ branch, view = 'checkout', interactive = false, onPay, playKey = 0, inspector = false }) {
  const phishing = branch === 'phishing';
  return (
    <div className={`demo-browser ${phishing ? 'is-phishing' : 'is-extension'} ${inspector ? 'has-inspector' : ''}`}>
      <div className="demo-browser-chrome">
        <i /><i /><i />
        <div className="demo-address"><span>⌁</span><strong>{phishing ? 'shop-example.help' : 'shop.example'}</strong><em>{phishing ? 'LOOKALIKE ORIGIN' : 'VERIFIED ORIGIN'}</em></div>
        {!phishing && <b className="extension-badge">EXT <span>1</span></b>}
      </div>
      <div className="demo-shop-header"><b>NORTHSTAR</b><span>Bag · 1</span></div>
      {view === 'receipt' ? (
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
      {inspector && <div className="browser-xray"><span>{phishing ? 'onclick handler' : 'content script'}</span><code>{phishing ? "fetch('/collect', form)" : "account.value = 'drop_772'"}</code></div>}
    </div>
  );
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
      <DiagramNode x={855} y={86} tone="secure" label="ACTUAL SHOP" detail="api.shop.example" />
      <DiagramNode x={855} y={254} tone={phishing ? 'attack' : 'extension'} label={phishing ? 'ATTACKER RELAY' : 'ATTACKER COLLECTOR'} detail={phishing ? 'shop-example.help' : 'collector.invalid'} />

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
            <text className="route-label relay-label" x="670" y="170">separate login relay · no Maya cookie</text>
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
          <text className="route-label safe-label" x="412" y="73">POST /api/checkout · session attached</text>
          <text className="route-label extension-label" x="405" y="282">extension message · DOM fields copied</text>
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
          <code>{phishing ? <><span>&lt;form action=</span><b>"/collect"</b><span>&gt;</span><br /><span> clone(</span><em>"shop checkout"</em><span>)</span><br /><span> onPay(</span><b>capture</b><span>)</span><br /><span> show(</span><em>"Payment received"</em><span>)</span><br /><strong> deploy → shop-example.help</strong></> : <><span>"matches": [</span><b>"*://shop.example/*"</b><span>]</span><br /><span>"permissions": [</span><b>"scripting"</b><span>]</span><br /><span>if (path === </span><em>"/checkout"</em><span>)</span><br /><span> inject(</span><b>"observer.js"</b><span>)</span><br /><strong> publish → version 2.4.1</strong></>}</code>
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

function ArrivalVisual({ branch, reduceMotion }) {
  const phishing = branch === 'phishing';
  return (
    <div className="visual-stage arrival-visual">
      <motion.div className="maya-thought" initial={reduceMotion ? false : { opacity: 0, transform: 'translateY(8px)' }} animate={{ opacity: 1, transform: 'translateY(0px)' }} transition={{ duration: .35, ease: [.23, 1, .32, 1] }}><span>MAYA SEES</span><strong>“The checkout I expected.”</strong></motion.div>
      <BrowserWindow branch={branch} />
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
  const [run, setRun] = useState(1);
  return (
    <div className="visual-stage journey-map-visual">
      <RequestMap branch={branch} phase="relay" run={run} reduceMotion={reduceMotion} />
      <div className="packet-inspector">
        <span>REQUEST PROVENANCE</span>
        {branch === 'phishing' ? <><code><b>origin</b> shop-example.help</code><code><b>payload</b> typed form fields</code><code className="is-safe"><b>shop cookie</b> never attached</code></> : <><code className="is-safe"><b>shop request</b> session=s_7f2a</code><code><b>extension copy</b> DOM-visible fields</code><code className="is-safe"><b>HttpOnly cookie</b> not readable</code></>}
      </div>
      <button className="diagram-replay" type="button" onClick={() => setRun(value => value + 1)}>Replay packets ↻</button>
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
          <VisualEvidence items={story.evidence} reduceMotion={reduceMotion} />
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
        <p className="scene-kicker">From incident to understanding</p>
        <h2 id="reflection-title">Now name what you saw.</h2>
        <p className="scene-thesis">The journey showed the divergence. The original presentation now becomes the reflection: eight boundaries, each asking which promise failed and which control restores it.</p>
        <button className="primary-action" type="button" onClick={next}>Begin the reflections <span aria-hidden="true">→</span></button>
      </div>
      <div className="bridge-map" role="img" aria-label="Moving from the concrete incident to reusable security questions">
        <div><span>YOU WITNESSED</span><strong>{branch === 'phishing' ? 'A trusted gesture on the wrong origin' : 'A trusted origin with a hostile local observer'}</strong></div>
        <i>→</i>
        <div><span>NOW ASK</span><strong>What claim crossed each boundary—and who verified it?</strong></div>
        <i>→</i>
        <div><span>LEAVE WITH</span><strong>A method for tracing any sensitive request</strong></div>
      </div>
    </section>
  );
}

function Checkpoint({ scene, phase, setPhase }) {
  return (
    <section className="scene-shell checkpoint-scene" aria-labelledby={`scene-${scene.zone}-title`}>
      <div className="story-column">
        <div className="scene-index"><span>{scene.label}</span><strong>t = {scene.time}</strong></div>
        <LensBadges lenses={scene.lenses} />
        <h2 id={`scene-${scene.zone}-title`}>{scene.title}</h2>
        <p className="scene-thesis">{scene.thesis}</p>
        <div className="audience-prompt"><span>ASK THE ROOM</span><p>{scene.prompt}</p></div>
        <p className="method-line"><span>Trace</span><i>→</i><span>Attack</span><i>→</i><span>Verify</span></p>
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
        <p className="scene-kicker">You are on call</p>
        <h2 id="field-title">Name the promise before the category.</h2>
        <p className="scene-thesis">Find the trust boundary first. Then choose the control that restores it.</p>
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
          <p>{answer === null ? 'Let the room vote before revealing the control.' : item.why}</p>
          {answer !== null && index < quiz.length - 1 && <button type="button" onClick={nextQuestion}>Next signal →</button>}
          {answer !== null && index === quiz.length - 1 && <strong>Trace complete.</strong>}
        </div>
      </div>
    </section>
  );
}

function Closing({ restart, openLens }) {
  const questions = [
    ['01', 'Who is making the claim?', 'Identity and origin are inputs, not facts.'],
    ['02', 'May they do this here?', 'Authorize the action and object every time.'],
    ['03', 'Can data change meaning?', 'Keep untrusted values out of interpreter structure.'],
    ['04', 'Who owns the invariant?', 'Derive price, state, and sequence on the trusted side.'],
    ['05', 'What happens when it fails?', 'Choose a safe state and leave owned evidence.']
  ];
  return (
    <section className="scene-shell closing-scene" aria-labelledby="closing-title">
      <div className="story-column">
        <div className="scene-index"><span>Case closed</span><strong>req_7F2A · 214 ms</strong></div>
        <p className="scene-kicker">The security model</p>
        <h2 id="closing-title">Trace the promise, not the acronym.</h2>
        <p className="scene-thesis">OWASP names common failure patterns. The request journey shows where your system must make—and verify—trust decisions.</p>
        <div className="closing-actions"><button className="primary-action" type="button" onClick={restart}>Replay the request</button><button className="secondary-action" type="button" onClick={openLens}>Open OWASP lens</button></div>
      </div>
      <div className="question-stack" role="group" aria-label="Five questions to apply to every sensitive request">
        {questions.map(([number, title, body]) => <div key={number}><span>{number}</span><strong>{title}</strong><small>{body}</small></div>)}
        <p><span>THIS WEEK</span> Pick one production request. Draw its handoffs. Put one verifier at every boundary.</p>
      </div>
    </section>
  );
}

function LensDialog({ dialogRef }) {
  return (
    <dialog className="lens-dialog" ref={dialogRef} aria-labelledby="lens-title">
      <div className="dialog-heading"><div><span>REFERENCE, NOT ROUTE</span><h2 id="lens-title">OWASP Top 10:2025</h2></div><button type="button" aria-label="Close OWASP lens" onClick={() => dialogRef.current?.close()}>×</button></div>
      <p>The journey is the narrative spine. OWASP is a set of failure lenses. Several lenses can appear at one boundary; one lens can appear at several boundaries.</p>
      <div className="lens-grid">
        {Object.entries(owasp).map(([code, [name, href]]) => <a href={href} target="_blank" rel="noreferrer" key={code}><b>{code}</b><span>{name}</span><i>↗</i></a>)}
      </div>
      <div className="dialog-note"><strong>A03 sits before the first byte.</strong><span>Supply-chain provenance decides which software receives req_7F2A. Essential—but deliberately outside the runtime route.</span></div>
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
      setSceneIndex(next);
      setPhase(0);
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  function goTo(index, mode = 'pointer') {
    const next = Math.min(Math.max(index, 0), scenes.length - 1);
    setInputMode(mode);
    setSceneIndex(next);
    setPhase(0);
    window.history.replaceState(null, '', `#scene-${next}`);
    stageRef.current?.scrollTo({ top: 0, behavior: 'auto' });
  }

  useEffect(() => {
    function onKeyDown(event) {
      if (document.querySelector('dialog[open]')) return;
      if (['INPUT', 'TEXTAREA'].includes(document.activeElement?.tagName)) return;
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
  }, [sceneIndex, phase, scene.type]);

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
          <button className="lens-button" type="button" onClick={() => lensRef.current?.showModal()}>OWASP <span>LENS</span></button>
          <button className="icon-button" type="button" onClick={() => setShowNotes(value => !value)} aria-label="Toggle speaker notes" aria-pressed={showNotes}>N</button>
          <button className="icon-button" type="button" onClick={() => setHighContrast(value => !value)} aria-label="Toggle high contrast" aria-pressed={highContrast}>◐</button>
        </div>
      </header>

      <main id="presentation" className="stage" ref={stageRef} tabIndex="-1">
        {scene.type === 'opening' && <Opening next={() => goTo(1)} branch={branch} setBranch={setBranch} />}
        {scene.type === 'journey' && <JourneyScene scene={scene} branch={branch} setBranch={setBranch} />}
        {scene.type === 'bridge' && <ReflectionBridge branch={branch} next={() => goTo(sceneIndex + 1)} />}
        {scene.type === 'checkpoint' && <Checkpoint scene={scene} phase={phase} setPhase={setPhase} />}
        {scene.type === 'quiz' && <FieldTest />}
        {scene.type === 'closing' && <Closing restart={() => goTo(0)} openLens={() => lensRef.current?.showModal()} />}
      </main>

      <nav className="deck-nav" aria-label="Presentation scenes">
        <button className="nav-arrow" type="button" onClick={() => goTo(sceneIndex - 1)} disabled={sceneIndex === 0} aria-label="Previous scene">←</button>
        <div className="nav-center">
          <div className="nav-meta"><span>{currentSection} · {scene.label}</span><strong>{scene.minutes} MIN · {String(sceneIndex + 1).padStart(2, '0')} / {String(scenes.length).padStart(2, '0')}</strong></div>
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
