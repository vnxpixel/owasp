# Request Under Fire

A presenter-ready deck split into two independent sessions: **Certificates & PKI** and **Request Under Fire**. The second session is an interactive security story built around an authenticated checkout. Its journey uses a different visual metaphor for every beat: attacker workbench, login exchange, credential vault, believable storefront, DOM x-ray, replayable Pay click, animated SVG network topology, dual receipts, and a defensive rewind. The audience can replay the incident through two compromise paths—a phishing origin or a hostile local extension—before moving into trust-boundary reflections.

The developer trace distinguishes credential collection from server-side replay, and a legitimate shop request from an extension's out-of-band exfiltration request. Interactive lenses compare CSRF, XSS, phishing, and privileged-extension capabilities, including what each mechanism gains and which browser protections remain intact. The auth scene also compares opaque and JWT credentials by storage and attachment behavior rather than treating “JWT vs cookie” as a binary choice.

The independent **Certificates & PKI** session contains nine foundation chapters adapted from Smallstep’s “Everything you should know about certificates and PKI but are too afraid to ask.” Animated diagrams move from names and claims through signatures, key pairs, certificates, formats, Web vs internal PKI, trust chains, and the certificate lifecycle. Certificate, trust-chain, and lifecycle chapters use full-width vertical scrollytelling, large original Smallstep illustrations, and audience-scale text; the fixed presentation footer remains available throughout. Its closing handoff separates endpoint identity and transport protection from application trust, and can launch the separate checkout session.

The reflections then consolidate the same `POST /api/checkout` request into five reusable lessons: browser threats, transport and edge, application decisions, data and business integrity, and resilience and operations. Every checkpoint uses the reveal: **trust claim → attacker move → restoring control**. A lifecycle scene connects design, build, verification, deployment, monitoring, response, and recovery; a placeholder lists deferred optional deep dives.

The [OWASP Top 10:2025](https://owasp.org/Top10/2025/) is used as a set of failure lenses—not as the presentation’s chapter structure.

The presentation is visually tuned for a 14-inch MacBook Pro at approximately `1512 × 982` logical pixels. It uses the locally installed `MonoLisaText` family for display and prose, and `MonoLisaCode` for request data and interface labels, with system fallbacks when those fonts are unavailable.

## Run locally

```bash
npm install
npm run dev
```

Open the URL printed by Vite (normally `http://localhost:5173`).

## Production build

```bash
npm run build
npm run preview
```

## Presenting

- Use **Certificates & PKI / Request Under Fire** in the header to start either session independently
- The bottom progress rail is scoped to the active session
- Within Request Under Fire, use the scene map to move between the concrete journey and its reusable reflections
- Switch between **Phishing site / Local extension** at any journey beat to compare how the same click is compromised
- Click the checkout’s **Pay now** button or **Replay packets** to rerun the causal animation
- In **The sign-in**, switch between an opaque HttpOnly session, JWT in an HttpOnly cookie, and a bearer JWT in local storage
- In **Under the hood**, open both request envelopes: collector / replay for phishing, or shop / exfiltration for the extension
- Follow the colored SVG routes: red reaches attacker infrastructure, purple is extension traffic, and green reaches the legitimate shop
- In Certificates & PKI, trace the central binding—name ↔ public key—from first principles through issuance, validation, and renewal
- Use **Beyond the handshake** to close the certificate session or launch Request Under Fire
- In **Recon workbench**, let the audience choose simulated commands and distinguish information exposure from exploitable vulnerability
- In Reflections, click **Claim**, **Attack**, and **Control** to reveal each checkpoint in three beats
- `Space`: reveal the next beat; after **Restore it**, advance to the next scene
- `1`, `2`, `3`: jump directly to a reveal beat
- `→` or `Page Down`: next scene
- `←` or `Page Up`: previous scene
- `O`: open the OWASP lens
- `Home` / `End`: jump to the beginning / end

The field test near the end is designed for audience voting before the presenter reveals an answer.

The examples are intentionally simplified, defensive simulations. They do not send attack traffic or interact with external systems.
