# Docker Guide: Tiny Knights

Run the app in a container with nginx serving the production build. No Node.js needed on your machine.

## Prerequisites

- Docker Desktop installed and running (Windows/Mac) or Docker Engine (Linux)
- This project folder, with `Dockerfile`, `docker-compose.yml`, `.dockerignore`, and `nginx.conf` present at the root

## Build and Run

From the project root (the folder containing `Dockerfile`):

```
docker compose up --build
```

Then open:

```
http://localhost:8080
```

The first build takes a minute or two (installing dependencies and building the Vite bundle). Subsequent builds are faster thanks to layer caching.

## Run Without Compose

```
docker build -t tiny-knights .
docker run -p 8080:80 tiny-knights
```

## Run in the Background

```
docker compose up --build -d
```

Check logs:

```
docker compose logs -f
```

## Stop the App

```
docker compose down
```

If you started it without compose:

```
docker stop $(docker ps -q --filter ancestor=tiny-knights)
```

## Rebuild From Scratch

If you changed code and want a clean rebuild (ignoring Docker's cache):

```
docker compose build --no-cache
docker compose up
```

## Full Cleanup

Remove containers, networks, and anonymous volumes created by this project:

```
docker compose down --volumes --remove-orphans
```

Remove the built image too:

```
docker rmi tiny-knights
```

Clean up all unused Docker data on your machine (containers, images, networks, build cache not in use):

```
docker system prune
```

To also remove unused volumes:

```
docker system prune --volumes
```

## Troubleshooting

**"Cannot connect to the Docker daemon"**
Docker Desktop isn't running. Start it and wait for the whale icon to show "Docker Desktop is running", then retry.

**"open Dockerfile: no such file or directory"**
You're running the command from the wrong folder. `cd` into the extracted project folder (the one containing `Dockerfile`, `package.json`, `src/`) and confirm with:

```
dir
```
(Windows) or `ls` (Mac/Linux). You should see `Dockerfile` in the listing.

**Port 8080 already in use**
Either stop whatever is using port 8080, or change the host port in `docker-compose.yml`:

```yaml
ports:
  - "3000:80"
```

Then visit `http://localhost:3000` instead.

**Changes to source code aren't showing up**
The image bundles a static build. After editing source files, rebuild:

```
docker compose up --build
```

**Build fails on `npm ci`**
Make sure `package-lock.json` is present in the project root and wasn't excluded by `.dockerignore`.

**Blank page or 404 on refresh at a sub-route**
Confirm `nginx.conf` is present and copied into the image (it provides SPA fallback routing via `try_files`). Rebuild with `--no-cache` if you edited it after a previous build.
