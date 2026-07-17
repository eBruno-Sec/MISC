import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, isAbsolute, join, normalize, relative, resolve } from "node:path";

const port = Number(process.argv[2] || 4173);
const host = "127.0.0.1";
const root = resolve(process.cwd());

const mimeTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".md", "text/markdown; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".txt", "text/plain; charset=utf-8"],
  [".webmanifest", "application/manifest+json; charset=utf-8"],
  [".xml", "application/xml; charset=utf-8"]
]);

function safeResolve(candidate) {
  const filePath = resolve(root, normalize(candidate));
  const distance = relative(root, filePath);
  if (distance.startsWith("..") || isAbsolute(distance)) return null;
  return filePath;
}

async function resolveFile(pathname) {
  const candidate = pathname === "/" ? "index.html" : pathname.slice(1);
  let filePath = safeResolve(candidate);
  if (!filePath) return null;
  let fileStat = await stat(filePath).catch(() => null);
  if (fileStat?.isDirectory()) {
    filePath = safeResolve(join(candidate, "index.html"));
    fileStat = filePath ? await stat(filePath).catch(() => null) : null;
  }
  if (!fileStat?.isFile()) return null;
  return filePath;
}

const server = createServer(async (request, response) => {
  try {
    const requestUrl = new URL(request.url || "/", `http://${host}:${port}`);
    const filePath = await resolveFile(decodeURIComponent(requestUrl.pathname));
    if (!filePath) {
      response.writeHead(404);
      response.end("Not found");
      return;
    }
    const type = mimeTypes.get(extname(filePath)) || "application/octet-stream";
    response.writeHead(200, { "Content-Type": type, "Cache-Control": "no-store" });
    createReadStream(filePath).pipe(response);
  } catch {
    response.writeHead(404);
    response.end("Not found");
  }
});

server.listen(port, host);
