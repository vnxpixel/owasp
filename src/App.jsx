import { useEffect, useMemo, useRef, useState } from 'react';
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

const scenes = [
  { type: 'opening', label: 'Case open', zone: 'open', time: '0.000 ms', minutes: 2.5, note: 'Open with a show of hands: “How many security decisions happen after Maya clicks Pay?” Do not reveal a number. Establish the rule: every handoff must justify one trust decision.' },
  ...checkpoints.map(item => ({ ...item, type: 'checkpoint' })),
  { type: 'quiz', label: 'Field test', zone: 'replay', time: 'replay', minutes: 3, note: 'Let the room vote before selecting an answer. Reward the reasoning, not the acronym. The method is: locate the boundary, name the promise, then choose the control.' },
  { type: 'closing', label: 'Case closed', zone: 'closed', time: 'complete', minutes: 2, note: 'Close on the five questions. Ask each person to choose one production request this week and draw its trust boundaries with their team.' }
];

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

function Opening({ next }) {
  return (
    <section className="scene-shell opening-scene" aria-labelledby="opening-title">
      <div className="opening-copy">
        <p className="scene-kicker">09:41:00.000 · Maya clicks</p>
        <h1 id="opening-title">Pay<span>.</span></h1>
        <p className="opening-lede">The screen says “Payment received” <strong>214 milliseconds</strong> later.</p>
        <p className="opening-thesis">In between, one request crosses eight trust boundaries. Every boundary asks a different security question.</p>
        <button className="primary-action" type="button" onClick={next}>Put the request under fire <span aria-hidden="true">→</span></button>
      </div>
      <div className="opening-visual" role="img" aria-label="A checkout request traveling from browser to edge, application, database, and back">
        <div className="case-label"><span>CASE FILE · req_7F2A</span><strong>POST /api/checkout</strong></div>
        <svg viewBox="0 0 720 440" aria-hidden="true">
          <path className="journey-base" d="M82 84 C210 18 320 66 374 136 S546 210 638 134 C704 80 704 260 604 286 S424 392 330 328 S164 304 82 380" />
          <path className="journey-signal" pathLength="100" d="M82 84 C210 18 320 66 374 136 S546 210 638 134 C704 80 704 260 604 286 S424 392 330 328 S164 304 82 380" />
          <circle className="journey-packet" r="7"><animateMotion dur="6s" repeatCount="indefinite" path="M82 84 C210 18 320 66 374 136 S546 210 638 134 C704 80 704 260 604 286 S424 392 330 328 S164 304 82 380" /></circle>
        </svg>
        <div className="visual-node node-browser"><span>00.3 ms</span><strong>Browser</strong><small>identity · intent</small></div>
        <div className="visual-node node-edge"><span>31.7 ms</span><strong>Edge</strong><small>transport · exposure</small></div>
        <div className="visual-node node-app"><span>64–70 ms</span><strong>Application</strong><small>authority · meaning · rules</small></div>
        <div className="visual-node node-data"><span>71.8 ms</span><strong>Data</strong><small>secrets · integrity</small></div>
        <div className="visual-node node-return"><span>214 ms</span><strong>Return</strong><small>evidence · disclosure</small></div>
        <div className="request-core"><span>THE RULE</span><strong>Trust nothing.<br />Verify one promise.</strong></div>
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
  const stageRef = useRef(null);
  const lensRef = useRef(null);
  const [sceneIndex, setSceneIndex] = useState(() => {
    const match = window.location.hash.match(/scene-(\d+)/);
    return Math.min(Math.max(Number(match?.[1] ?? 0), 0), scenes.length - 1);
  });
  const [phase, setPhase] = useState(0);
  const [showNotes, setShowNotes] = useState(false);
  const [highContrast, setHighContrast] = useState(false);
  const [timerRunning, setTimerRunning] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [inputMode, setInputMode] = useState('pointer');
  const scene = scenes[sceneIndex];

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
          <button className="timer-button" type="button" onClick={() => setTimerRunning(value => !value)} aria-label={`${timerRunning ? 'Pause' : 'Start'} presentation timer`}><span>{timerRunning ? 'LIVE' : 'PACE'}</span>{formatClock(elapsed)} <i>/ {Math.round(totalMinutes)}:00</i></button>
          <button className="lens-button" type="button" onClick={() => lensRef.current?.showModal()}>OWASP <span>LENS</span></button>
          <button className="icon-button" type="button" onClick={() => setShowNotes(value => !value)} aria-label="Toggle speaker notes" aria-pressed={showNotes}>N</button>
          <button className="icon-button" type="button" onClick={() => setHighContrast(value => !value)} aria-label="Toggle high contrast" aria-pressed={highContrast}>◐</button>
        </div>
      </header>

      <main id="presentation" className="stage" ref={stageRef} tabIndex="-1">
        {scene.type === 'opening' && <Opening next={() => goTo(1)} />}
        {scene.type === 'checkpoint' && <Checkpoint scene={scene} phase={phase} setPhase={setPhase} />}
        {scene.type === 'quiz' && <FieldTest />}
        {scene.type === 'closing' && <Closing restart={() => goTo(0)} openLens={() => lensRef.current?.showModal()} />}
      </main>

      <nav className="deck-nav" aria-label="Presentation scenes">
        <button className="nav-arrow" type="button" onClick={() => goTo(sceneIndex - 1)} disabled={sceneIndex === 0} aria-label="Previous scene">←</button>
        <div className="nav-center">
          <div className="nav-meta"><span>{scene.label}</span><strong>{scene.minutes} MIN · {String(sceneIndex + 1).padStart(2, '0')} / {String(scenes.length).padStart(2, '0')}</strong></div>
          <div className="progress-track" role="tablist" aria-label="Request journey scenes">
            <i className="progress-fill" style={{ transform: `scaleX(${sceneIndex / (scenes.length - 1)})` }} aria-hidden="true" />
            {scenes.map((item, index) => <button type="button" role="tab" aria-selected={sceneIndex === index} aria-label={`Scene ${index + 1}: ${item.label}`} className={index === sceneIndex ? 'is-current' : index < sceneIndex ? 'is-past' : ''} onClick={() => goTo(index)} key={`${item.label}-${index}`}><i /></button>)}
            <span className="progress-packet" style={{ '--progress': sceneIndex / (scenes.length - 1) }} aria-hidden="true" />
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
