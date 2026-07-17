// Minimal static server for local preview and offline testing.
// Usage: node tools/server.mjs [port]

import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, resolve, sep } from "node:path";

const port = Number(process.argv[2]) || 4180;
const root = resolve(process.cwd());

const types = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".webmanifest": "application/manifest+json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".xml": "application/xml; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".md": "text/markdown; charset=utf-8"
};

createServer(async (request, response) => {
  try {
    const pathname = decodeURIComponent(new URL(request.url, `http://127.0.0.1:${port}`).pathname);
    const target = resolve(root, pathname === "/" ? "index.html" : pathname.slice(1));
    if (target !== root && !target.startsWith(root + sep)) {
      response.writeHead(403, { "Content-Type": "text/plain" }).end("Forbidden");
      return;
    }
    const body = await readFile(target);
    response.writeHead(200, {
      "Content-Type": types[extname(target).toLowerCase()] || "application/octet-stream",
      "Cache-Control": "no-store"
    }).end(body);
  } catch {
    response.writeHead(404, { "Content-Type": "text/plain" }).end("Not found");
  }
}).listen(port, "127.0.0.1", () => {
  console.log(`NestEggHero 2 preview: http://127.0.0.1:${port}/`);
});
