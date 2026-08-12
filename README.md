# Request Under Fire

An interactive, presenter-ready 30-minute React presentation built around one checkout request under attack. The same `POST /api/checkout` request travels from browser to edge, application, data, failure path, and response. Every checkpoint follows the same reveal: **trust claim → attacker move → restoring control**.

The [OWASP Top 10:2025](https://owasp.org/Top10/2025/) is used as a set of failure lenses—not as the presentation’s chapter structure.

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

- Click **Trust claim**, **Break it**, and **Restore it** to reveal each checkpoint in three beats
- `Space`: reveal the next beat; after **Restore it**, advance to the next scene
- `1`, `2`, `3`: jump directly to a reveal beat
- `→` or `Page Down`: next scene
- `←` or `Page Up`: previous scene
- `N`: toggle speaker notes
- `O`: open the OWASP lens
- `Home` / `End`: jump to the beginning / end
- Click the pace clock to start or pause the 30-minute timer

The field test near the end is designed for audience voting before the presenter reveals an answer.

The examples are intentionally simplified, defensive simulations. They do not send attack traffic or interact with external systems.
