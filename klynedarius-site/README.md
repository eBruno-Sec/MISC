# KlyneDarius Construction Corporation — Website

Static marketing site (HTML/CSS/JS, no build step, no CMS) for KlyneDarius
Construction Corporation, served by Nginx in Docker.

## Structure

```
.
├── index.html              Home
├── about.html               About
├── services.html             Services (Planning & Design / Construction / Remodeling)
├── permit-process.html        Permit & Planning Process
├── projects.html              Project Portfolio
├── quote.html                  Request a Quote (lead form)
├── contact.html                Contact
├── 404.html
├── assets/
│   ├── css/styles.css
│   ├── js/main.js
│   └── img/                    logo, nav logo, favicons
├── Dockerfile
├── docker-compose.yml
├── nginx.conf
└── .dockerignore
```

## Before launch — replace these placeholders

The source handoff did not provide a live phone number or email, so the
site currently uses:

- Phone: `(206) 555-0100` (appears in header, footer, quote, contact)
- Email: `info@klynedariusconstruction.com` (a reasonable default for the
  domain, but not yet a confirmed live inbox)

Find-and-replace both across all `.html` files before going live.

## Connecting the quote/contact forms to a real backend

There is no backend yet — this is a static site. `assets/js/main.js`
already does full client-side validation and submit handling for any
`<form data-kd-form>`. Two ways to wire it up:

1. **Form endpoint (recommended).** Set `window.KD_FORM_ENDPOINT` to a
   POST endpoint (Formspree, Netlify Forms, a custom API, etc.) before
   `main.js` loads, e.g. add this above the `<script src="assets/js/main.js">`
   tag on `quote.html`:
   ```html
   <script>window.KD_FORM_ENDPOINT = "https://your-endpoint.example.com/submit";</script>
   ```
2. **Do nothing.** Without an endpoint, submissions fall back to opening
   a pre-filled `mailto:` draft to `info@klynedariusconstruction.com`, so
   leads are never silently lost — but this depends on the visitor having
   a configured email client.

---

## Docker guide: build → run → verify → clean up

Run these from the project root (where `Dockerfile` lives).

### 1. Build the image

```bash
docker build -t klynedarius-site:latest .
```

### 2. Run the container

```bash
docker run -d --name klynedarius-site -p 8080:80 klynedarius-site:latest
```

Site is now live at **http://localhost:8080**

### 3. Verify it's working

```bash
docker ps
curl -I http://localhost:8080
curl -I http://localhost:8080/services.html
```

You should see `HTTP/1.1 200 OK` for each.

### 4. View logs (if something looks wrong)

```bash
docker logs klynedarius-site
```

### 5. Stop the container

```bash
docker stop klynedarius-site
```

### 6. Restart it later

```bash
docker start klynedarius-site
```

### 7. Remove the container

```bash
docker rm -f klynedarius-site
```

### 8. Remove the image

```bash
docker rmi klynedarius-site:latest
```

### 9. Full cleanup (dangling layers/cache from the build)

```bash
docker image prune -f
docker builder prune -f
```

---

## Or: docker-compose (simpler day-to-day)

```bash
docker compose up -d --build      # build + start
docker compose ps                  # verify it's running
docker compose logs -f             # tail logs
docker compose down                # stop + remove container
docker compose down --rmi local    # stop + remove container + remove image
```

---

## Note on testing

This Dockerfile and nginx config were authored but **could not be build-tested
in this environment**, since Docker isn't available in the sandbox the site
was built in. The Dockerfile is a standard `nginx:alpine` static-file setup
with no unusual steps, but run a build locally and confirm all 7 pages plus
the 404 page load correctly before deploying.
