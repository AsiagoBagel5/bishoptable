import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { randomBytes } from "node:crypto";

const root = new URL(".", import.meta.url).pathname;
const publicDir = join(root, "public");

loadDotEnv();

const config = {
  port: Number(process.env.PORT || 4321),
  appBaseUrl: (process.env.APP_BASE_URL || "http://localhost:4321").replace(/\/$/, ""),
  sessionSecret: process.env.SESSION_SECRET || "dev-only-secret-change-me",
  onshapeClientId: process.env.ONSHAPE_CLIENT_ID || "",
  onshapeClientSecret: process.env.ONSHAPE_CLIENT_SECRET || "",
  onshapeOAuthBase: "https://oauth.onshape.com",
  onshapeApiBase: "https://cad.onshape.com",
  prod: process.env.NODE_ENV === "production",
};

// In-memory session store (resets on server restart — fine for dev/FRC use)
const sessions = new Map();

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css":  "text/css; charset=utf-8",
  ".js":   "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png":  "image/png",
  ".svg":  "image/svg+xml",
  ".ico":  "image/x-icon",
};

// ─── SERVER ───────────────────────────────────────────────────────────────────
createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", config.appBaseUrl);
    const session = getSession(req, res);

    // CORS for panel iframe requests
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    // Auth routes
    if (url.pathname === "/auth/onshape")          return onshapeStart(req, res, session, url);
    if (url.pathname === "/auth/onshape/callback") return await onshapeCallback(req, res, session, url);
    if (url.pathname === "/auth/logout")           return logout(res, session);

    // API routes
    if (url.pathname === "/api/session")         return json(res, 200, publicSession(session));
    if (url.pathname === "/api/parts")           return await getParts(req, res, session, url);
    if (url.pathname === "/api/part-details")    return await getPartDetails(req, res, session, url);
    if (url.pathname === "/api/part-writeback" && req.method === "POST") return await writebackPart(req, res, session);

    // Static files
    return await serveStatic(res, url.pathname);
  } catch (err) {
    console.error(err);
    return json(res, err.status || 500, { error: err.message || "Server error" });
  }
}).listen(config.port, () => {
  console.log(`Bishoptable listening on ${config.appBaseUrl}`);
});

// ─── SESSION ──────────────────────────────────────────────────────────────────
function getSession(req, res) {
  const cookies = parseCookies(req.headers.cookie || "");
  let sid = cookies["bt_session"];
  if (!sid || !sessions.has(sid)) {
    sid = randomBytes(24).toString("base64url");
    sessions.set(sid, { id: sid, oauthState: null, accessToken: null, refreshToken: null, user: null });
    res.setHeader("Set-Cookie", `bt_session=${sid}; Path=/; HttpOnly; SameSite=Lax${config.prod ? "; Secure" : ""}`);
  }
  return sessions.get(sid);
}

function parseCookies(str) {
  return Object.fromEntries(str.split(";").map(c => {
    const [k, ...v] = c.trim().split("=");
    return [k, decodeURIComponent(v.join("="))];
  }).filter(([k]) => k));
}

function publicSession(session) {
  return {
    loggedIn: !!session.accessToken,
    user: session.user || null,
    loginUrl: `${config.appBaseUrl}/auth/onshape`,
  };
}

function logout(res, session) {
  session.accessToken = null;
  session.refreshToken = null;
  session.user = null;
  redirect(res, "/");
}

// ─── ONSHAPE OAUTH ────────────────────────────────────────────────────────────
// Store OAuth state separately from session to survive cross-context redirects
const oauthStates = new Map();

function onshapeStart(req, res, session, url) {
  if (!config.onshapeClientId) {
    return json(res, 500, { error: "ONSHAPE_CLIENT_ID not configured" });
  }
  const state = randomBytes(16).toString("hex");
  const returnTo = url.searchParams.get("returnTo") || "/panel.html";
  
  // Store state globally, not in session
  oauthStates.set(state, { sessionId: session.id, returnTo, createdAt: Date.now() });
  
  // Clean up old states (older than 10 minutes)
  for (const [k, v] of oauthStates) {
    if (Date.now() - v.createdAt > 600000) oauthStates.delete(k);
  }

  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.onshapeClientId,
    redirect_uri: `${config.appBaseUrl}/auth/onshape/callback`,
    state,
  });

  redirect(res, `${config.onshapeOAuthBase}/oauth/authorize?${params}`);
}

async function onshapeCallback(req, res, session, url) {
  const code  = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code)  return json(res, 400, { error: "Missing code" });
  
  // Look up state globally
  const stateData = oauthStates.get(state);
  if (!stateData) return json(res, 400, { error: "Invalid state" });
  oauthStates.delete(state);
  
  // Use the session from state if current session is different
  const targetSession = sessions.get(stateData.sessionId) || session;
  const returnTo = stateData.returnTo || "/panel.html";

  // Exchange code for tokens
  const tokenRes = await fetch(`${config.onshapeOAuthBase}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: config.onshapeClientId,
      client_secret: config.onshapeClientSecret,
      redirect_uri: `${config.appBaseUrl}/auth/onshape/callback`,
    }),
  });

  if (!tokenRes.ok) {
    const txt = await tokenRes.text();
    console.error("Token exchange failed:", txt);
    return json(res, 502, { error: "Token exchange failed" });
  }

  const tokens = await tokenRes.json();
  targetSession.accessToken  = tokens.access_token;
  targetSession.refreshToken = tokens.refresh_token;

  // Fetch user info
  try {
    const me = await onshapeGet(targetSession, "/api/users/sessioninfo");
    targetSession.user = { name: me.name, email: me.email, id: me.id };
  } catch (e) {
    console.warn("Could not fetch user info:", e.message);
  }

  redirect(res, returnTo);
}

async function refreshAccessToken(session) {
  if (!session.refreshToken) throw httpError(401, "Not logged in");
  const res = await fetch(`${config.onshapeOAuthBase}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: session.refreshToken,
      client_id: config.onshapeClientId,
      client_secret: config.onshapeClientSecret,
    }),
  });
  if (!res.ok) throw httpError(401, "Token refresh failed — please log in again");
  const tokens = await res.json();
  session.accessToken  = tokens.access_token;
  session.refreshToken = tokens.refresh_token || session.refreshToken;
}

// ─── ONSHAPE API ──────────────────────────────────────────────────────────────
async function onshapeGet(session, path, retry = true) {
  if (!session.accessToken) throw httpError(401, "Not logged in");
  const res = await fetch(`${config.onshapeApiBase}${path}`, {
    headers: {
      Accept: "application/json;charset=UTF-8",
      Authorization: `Bearer ${session.accessToken}`,
    },
  });
  if (res.status === 401 && retry) {
    await refreshAccessToken(session);
    return onshapeGet(session, path, false);
  }
  if (!res.ok) throw httpError(res.status, await res.text());
  return res.json();
}

// ─── API: GET PARTS LIST ──────────────────────────────────────────────────────
// Called by the panel with ?documentId=&workspaceId=&elementId=
// Returns all parts in the Part Studio
async function getParts(req, res, session, url) {
  if (!session.accessToken) {
    return json(res, 401, { error: "Not logged in", loginUrl: `${config.appBaseUrl}/auth/onshape` });
  }

  const did = url.searchParams.get("documentId");
  const wid = url.searchParams.get("workspaceId");
  const eid = url.searchParams.get("elementId");

  if (!did || !wid || !eid) {
    return json(res, 400, { error: "Missing documentId, workspaceId, or elementId" });
  }

  try {
    // Get parts in this Part Studio
    const parts = await onshapeGet(session,
      `/api/parts/d/${did}/w/${wid}/e/${eid}`
    );

    // Get part studio metadata for property values
    let metadata = [];
    try {
      const meta = await onshapeGet(session,
        `/api/metadata/d/${did}/w/${wid}/e/${eid}`
      );
      metadata = meta.items || [];
    } catch (e) {
      console.warn("Could not fetch metadata:", e.message);
    }

    // Build a map of partId -> metadata
    const metaMap = {};
    for (const item of metadata) {
      if (item.partId) metaMap[item.partId] = item;
    }

    const result = parts.map(part => {
      const meta = metaMap[part.partId] || {};
      const props = {};
      for (const p of (meta.properties || [])) {
        props[p.name] = p.value;
      }
      return {
        partId:      part.partId,
        name:        part.name || props["Name"] || "Unnamed Part",
        partNumber:  props["Part Number"] || props["PartNumber"] || "",
        material:    props["Material"] || part.material?.displayName || "",
        description: props["Description"] || "",
      };
    });

    return json(res, 200, { parts: result });
  } catch (err) {
    console.error("getParts error:", err);
    return json(res, err.status || 500, { error: err.message });
  }
}

// ─── API: GET SINGLE PART DETAILS ─────────────────────────────────────────────
async function getPartDetails(req, res, session, url) {
  if (!session.accessToken) {
    return json(res, 401, { error: "Not logged in", loginUrl: `${config.appBaseUrl}/auth/onshape` });
  }

  const did    = url.searchParams.get("documentId");
  const wid    = url.searchParams.get("workspaceId");
  const eid    = url.searchParams.get("elementId");
  const partId = url.searchParams.get("partId");

  if (!did || !wid || !eid || !partId) {
    return json(res, 400, { error: "Missing required parameters" });
  }

  try {
    const meta = await onshapeGet(session,
      `/api/metadata/d/${did}/w/${wid}/e/${eid}/p/${partId}`
    );
    const props = {};
    for (const p of (meta.properties || [])) {
      props[p.name] = p.value;
    }
    return json(res, 200, {
      partId,
      name:        meta.name || props["Name"] || "",
      partNumber:  props["Part Number"] || props["PartNumber"] || "",
      material:    props["Material"] || "",
      description: props["Description"] || "",
    });
  } catch (err) {
    return json(res, err.status || 500, { error: err.message });
  }
}

// ─── API: WRITE BACK TO ONSHAPE ──────────────────────────────────────────────
// Writes part number and color back to Onshape after ticket submission
async function writebackPart(req, res, session) {
  if (!session.accessToken) {
    return json(res, 401, { error: "Not logged in" });
  }

  let body;
  try {
    let raw = "";
    for await (const chunk of req) { raw += chunk; if (raw.length > 100000) break; }
    body = JSON.parse(raw);
  } catch(e) {
    return json(res, 400, { error: "Invalid JSON" });
  }

  const { documentId, workspaceId, elementId, partId, partNumber, colorHex } = body;
  if (!documentId || !workspaceId || !elementId || !partId) {
    return json(res, 400, { error: "Missing required fields" });
  }

  const results = [];

  // 1. Set Part Number property
  if (partNumber) {
    try {
      await onshapePost(session,
        `/api/metadata/d/${documentId}/w/${workspaceId}/e/${elementId}/p/${partId}`,
        {
          properties: [
            { name: "Part Number", value: partNumber },
            { name: "Name", value: partNumber }
          ]
        }
      );
      results.push("Part number set");
    } catch(e) {
      console.warn("Could not set part number:", e.message);
      results.push("Part number failed: " + e.message);
    }
  }

  // 2. Set Color appearance
  if (colorHex) {
    try {
      // Parse hex to RGB (0-1 range)
      const hex = colorHex.replace("#", "");
      const r = parseInt(hex.slice(0,2), 16) / 255;
      const g = parseInt(hex.slice(2,4), 16) / 255;
      const b = parseInt(hex.slice(4,6), 16) / 255;

      await onshapePost(session,
        `/api/metadata/d/${documentId}/w/${workspaceId}/e/${elementId}/p/${partId}`,
        {
          properties: [
            {
              name: "Appearance",
              value: { color: { red: r, green: g, blue: b }, opacity: 1 }
            }
          ]
        }
      );
      results.push("Color set");
    } catch(e) {
      console.warn("Could not set color:", e.message);
      results.push("Color failed: " + e.message);
    }
  }

  return json(res, 200, { ok: true, results });
}

async function onshapePost(session, path, body, retry = true) {
  if (!session.accessToken) throw httpError(401, "Not logged in");
  const res = await fetch(`${config.onshapeApiBase}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json;charset=UTF-8",
      Authorization: `Bearer ${session.accessToken}`,
    },
    body: JSON.stringify(body),
  });
  if (res.status === 401 && retry) {
    await refreshAccessToken(session);
    return onshapePost(session, path, body, false);
  }
  if (!res.ok) throw httpError(res.status, await res.text());
  const text = await res.text();
  return text ? JSON.parse(text) : {};
}

// ─── STATIC FILES ─────────────────────────────────────────────────────────────
async function serveStatic(res, pathname) {
  const requested = pathname === "/" ? "/index.html" : pathname;
  const safe = normalize(decodeURIComponent(requested)).replace(/^(\.\.[/\\])+/, "");
  const filePath = join(publicDir, safe);
  if (!filePath.startsWith(publicDir)) return json(res, 403, { error: "Forbidden" });
  try {
    const info = await stat(filePath);
    if (!info.isFile()) throw new Error("Not a file");
    const content = await readFile(filePath);
    res.writeHead(200, {
      "Content-Type": MIME[extname(filePath)] || "application/octet-stream",
      "Cache-Control": "no-store",
    });
    return res.end(content);
  } catch {
    return json(res, 404, { error: "Not found" });
  }
}

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function json(res, status, data) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  return res.end(JSON.stringify(data));
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  return res.end();
}

function httpError(status, message) {
  const err = new Error(String(message).slice(0, 500));
  err.status = status;
  return err;
}

function loadDotEnv() {
  const envPath = join(new URL(".", import.meta.url).pathname, ".env");
  if (!existsSync(envPath)) return;
  for (const line of readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const idx = trimmed.indexOf("=");
    if (idx === -1) continue;
    const key = trimmed.slice(0, idx).trim();
    const val = trimmed.slice(idx + 1).trim().replace(/^["']|["']$/g, "");
    if (!process.env[key]) process.env[key] = val;
  }
}
