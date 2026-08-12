# Request Under Fire

An interactive, presenter-ready security story built around Maya's authenticated checkout. Its **Journey** uses a different visual metaphor for every beat: attacker workbench, login exchange, credential vault, believable storefront, DOM x-ray, replayable Pay click, animated SVG network topology, capability debugger, dual receipts, and a defensive rewind. The audience can replay the incident through two compromise paths—a phishing origin or a hostile local extension—before moving into the original trust-boundary material as reflections.

The developer trace distinguishes credential collection from server-side replay, and a legitimate shop request from an extension's out-of-band exfiltration request. Interactive lenses compare CSRF, XSS, phishing, and privileged-extension capabilities, including what each mechanism gains and which browser protections remain intact. The auth scene also compares opaque and JWT credentials by storage and attachment behavior rather than treating “JWT vs cookie” as a binary choice.

The reflections follow the same `POST /api/checkout` request from browser to edge, application, data, failure path, and response. Every checkpoint uses the reveal: **trust claim → attacker move → restoring control**.

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

- Use **Journey / Reflections** in the header to move between the concrete incident and its reusable lessons
- Switch between **Phishing site / Local extension** at any journey beat to compare how the same click is compromised
- Click the checkout’s **Pay now** button or **Replay packets** to rerun the causal animation
- In **The sign-in**, switch between an opaque HttpOnly session, JWT in an HttpOnly cookie, and a bearer JWT in local storage
- In **Under the hood**, open both request envelopes: collector / replay for phishing, or shop / exfiltration for the extension
- In **The privilege gap**, compare phishing, CSRF, XSS, and extension powers without conflating their threat models
- Follow the colored SVG routes: red reaches attacker infrastructure, purple is extension traffic, and green reaches the legitimate shop
- In Reflections, click **Trust claim**, **Break it**, and **Restore it** to reveal each checkpoint in three beats
- `Space`: reveal the next beat; after **Restore it**, advance to the next scene
- `1`, `2`, `3`: jump directly to a reveal beat
- `→` or `Page Down`: next scene
- `←` or `Page Up`: previous scene
- `N`: toggle speaker notes
- `O`: open the OWASP lens
- `Home` / `End`: jump to the beginning / end
- Click the pace clock to start or pause the presentation timer

The field test near the end is designed for audience voting before the presenter reveals an answer.

The examples are intentionally simplified, defensive simulations. They do not send attack traffic or interact with external systems.
