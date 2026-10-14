var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker.js
var SESSION_DAYS = 7;
var PBKDF2_ITERATIONS = 1e5;
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store"
    }
  });
}
__name(json, "json");
function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}
__name(normalizeEmail, "normalizeEmail");
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
__name(isValidEmail, "isValidEmail");
function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(bytesToHex, "bytesToHex");
function bytesToBase64Url(bytes) {
  let binary = "";
  for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
__name(bytesToBase64Url, "bytesToBase64Url");
function base64UrlToBytes(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(base64);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}
__name(base64UrlToBytes, "base64UrlToBytes");
async function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}
__name(randomBytes, "randomBytes");
async function sha256Hex(text) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text)
  );
  return bytesToHex(digest);
}
__name(sha256Hex, "sha256Hex");
async function hashPassword(password) {
  const salt = await randomBytes(16);
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );
  return `pbkdf2$${PBKDF2_ITERATIONS}$${bytesToBase64Url(
    salt
  )}$${bytesToBase64Url(new Uint8Array(bits))}`;
}
__name(hashPassword, "hashPassword");
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
__name(constantTimeEqual, "constantTimeEqual");
async function verifyPassword(password, stored) {
  if (!stored) {
    return { ok: false, upgrade: false };
  }
  if (/^[0-9a-f]{64}$/i.test(stored)) {
    const candidate = await sha256Hex(password);
    return {
      ok: constantTimeEqual(
        candidate.toLowerCase(),
        stored.toLowerCase()
      ),
      upgrade: true
    };
  }
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") {
    return { ok: false, upgrade: false };
  }
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 1e4 || iterations > 1e6) {
    return { ok: false, upgrade: false };
  }
  try {
    const salt = base64UrlToBytes(parts[2]);
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256"
      },
      key,
      256
    );
    const candidate = bytesToBase64Url(
      new Uint8Array(bits)
    );
    return {
      ok: constantTimeEqual(candidate, parts[3]),
      upgrade: false
    };
  } catch {
    return { ok: false, upgrade: false };
  }
}
__name(verifyPassword, "verifyPassword");
async function newSession(env, userId) {
  const token = bytesToBase64Url(
    await randomBytes(32)
  );
  const expires = new Date(
    Date.now() + SESSION_DAYS * 864e5
  ).toISOString().slice(0, 19).replace("T", " ");
  await env.DB.prepare(
    "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
  ).bind(token, userId, expires).run();
  return {
    token,
    expires
  };
}
__name(newSession, "newSession");
function sessionCookie(token, expires) {
  return [
    `AT_SESSION=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Expires=${new Date(expires).toUTCString()}`
  ].join("; ");
}
__name(sessionCookie, "sessionCookie");
function clearSessionCookie() {
  return [
    "AT_SESSION=",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0"
  ].join("; ");
}
__name(clearSessionCookie, "clearSessionCookie");
function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) {
      return rest.join("=");
    }
  }
  return null;
}
__name(getCookie, "getCookie");
async function getSessionUser(request, env) {
  const token = getCookie(
    request,
    "AT_SESSION"
  );
  if (!token) {
    return null;
  }
  const row = await env.DB.prepare(`
    SELECT
      u.id,
      u.email,
      u.name,
      u.plan,
      u.plan_started_at,
      u.plan_expires_at,
      u.role,
      u.created_at,
      s.token,
      s.expires_at
    FROM sessions s
    JOIN users u
      ON u.id = s.user_id
    WHERE
      s.token = ?
      AND s.expires_at > datetime('now')
    LIMIT 1
  `).bind(token).first();
  if (!row) {
    return null;
  }
  return row;
}
__name(getSessionUser, "getSessionUser");
async function ensureMembershipColumns(env) {
  try {
    const columns = await env.DB.prepare("PRAGMA table_info(users)").all();
    const names = new Set((columns.results || []).map((column) => column.name));
    if (!names.has("plan_started_at")) {
      await env.DB.prepare("ALTER TABLE users ADD COLUMN plan_started_at TEXT").run();
    }
    if (!names.has("plan_expires_at")) {
      await env.DB.prepare("ALTER TABLE users ADD COLUMN plan_expires_at TEXT").run();
    }
  } catch (error) {
    console.error("membership schema check error", error);
    throw error;
  }
}
__name(ensureMembershipColumns, "ensureMembershipColumns");

async function ensureRoleColumn(env) {
  try {
    const columns = await env.DB.prepare("PRAGMA table_info(users)").all();
    const names = new Set((columns.results || []).map((column) => column.name));
    if (!names.has("role")) {
      await env.DB.prepare(
        "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'student'"
      ).run();
    }
  } catch (error) {
    console.error("role schema check error", error);
    throw error;
  }
}
__name(ensureRoleColumn, "ensureRoleColumn");

async function ensureAdminAccount(env) {
  const adminEmail = "contact@apranntech.net";
  const adminPassword = String(env.ADMIN_PASSWORD || "");

  if (!adminPassword) {
    console.warn("ADMIN_PASSWORD secret is not configured; admin account bootstrap skipped.");
    return;
  }

  if (adminPassword.length < 8) {
    console.error("ADMIN_PASSWORD must be at least 8 characters; admin bootstrap skipped.");
    return;
  }

  const existing = await env.DB.prepare(
    "SELECT id, role FROM users WHERE lower(email) = ? LIMIT 1"
  ).bind(adminEmail).first();

  if (!existing) {
    const passwordHash = await hashPassword(adminPassword);
    await env.DB.prepare(
      "INSERT INTO users (email, password_hash, name, plan, role) VALUES (?, ?, ?, 'free', 'admin')"
    ).bind(
      adminEmail,
      passwordHash,
      "Aprann Tech Administrator"
    ).run();
    console.log("Aprann Tech administrator account created.");
    return;
  }

  if (String(existing.role || "").toLowerCase() !== "admin") {
    const passwordHash = await hashPassword(adminPassword);
    await env.DB.prepare(
      "UPDATE users SET role = 'admin', password_hash = ?, name = ? WHERE id = ?"
    ).bind(
      passwordHash,
      "Aprann Tech Administrator",
      existing.id
    ).run();
    console.log("Aprann Tech administrator account promoted to role=admin.");
  }
}
__name(ensureAdminAccount, "ensureAdminAccount");

async function ensurePaymentColumns(env) {
  try {
    const columns = await env.DB.prepare("PRAGMA table_info(payments)").all();
    const names = new Set((columns.results || []).map((column) => column.name));
    if (!names.has("approved_at")) {
      await env.DB.prepare("ALTER TABLE payments ADD COLUMN approved_at TEXT").run();
    }
  } catch (error) {
    console.error("payment schema check error", error);
    throw error;
  }
}
__name(ensurePaymentColumns, "ensurePaymentColumns");

async function ensureActivityTables(env) {
  try {
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS exam_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        exam_id TEXT NOT NULL,
        exam_title TEXT NOT NULL,
        exam_type TEXT NOT NULL,
        score INTEGER NOT NULL,
        total INTEGER NOT NULL,
        percentage REAL NOT NULL,
        auto_submitted INTEGER NOT NULL DEFAULT 0,
        submitted_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS video_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        video_index INTEGER NOT NULL,
        watched_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(user_id, video_index),
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `).run();
  } catch (error) {
    console.error("activity schema check error", error);
    throw error;
  }
}
__name(ensureActivityTables, "ensureActivityTables");

async function handleSaveExamResult(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not authenticated." }, 401);

  try {
    const body = await request.json();
    const examId = String(body.exam_id || "").trim();
    const examTitle = String(body.exam_title || "").trim();
    const examType = String(body.exam_type || "").trim().toLowerCase();
    const score = Number(body.score);
    const total = Number(body.total);
    const percentage = Number(body.percentage);
    const autoSubmitted = body.auto_submitted ? 1 : 0;

    if (!examId || !examTitle || !["theory","practical"].includes(examType) ||
        !Number.isInteger(score) || !Number.isInteger(total) ||
        total < 1 || score < 0 || score > total ||
        !Number.isFinite(percentage) || percentage < 0 || percentage > 100) {
      return json({ error: "Invalid exam result." }, 400);
    }

    await env.DB.prepare(`
      INSERT INTO exam_results
        (user_id, exam_id, exam_title, exam_type, score, total, percentage, auto_submitted)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      user.id, examId, examTitle, examType,
      score, total, percentage, autoSubmitted
    ).run();

    return json({ success: true });
  } catch (error) {
    console.error("exam result save error", error);
    return json({ error: "Unable to save exam result." }, 500);
  }
}
__name(handleSaveExamResult, "handleSaveExamResult");

async function handleSaveVideoActivity(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not authenticated." }, 401);

  try {
    const body = await request.json();
    const videoIndex = Number(body.video_index);
    if (!Number.isInteger(videoIndex) || videoIndex < 0) {
      return json({ error: "Invalid video activity." }, 400);
    }

    await env.DB.prepare(`
      INSERT INTO video_activity (user_id, video_index, watched_at)
      VALUES (?, ?, datetime('now'))
      ON CONFLICT(user_id, video_index)
      DO UPDATE SET watched_at = datetime('now')
    `).bind(user.id, videoIndex).run();

    return json({ success: true });
  } catch (error) {
    console.error("video activity save error", error);
    return json({ error: "Unable to save video activity." }, 500);
  }
}
__name(handleSaveVideoActivity, "handleSaveVideoActivity");



const RESOURCE_MAX_FILE_BYTES = 25 * 1024 * 1024;
function getFileStore(env) {
  return env.FILES || null;
}
__name(getFileStore, "getFileStore");

async function ensureResourceTables(env) {
  // The production database already contains the resources table with the
  // established schema: object_key/content_type/is_published and the
  // RESOURCE_FILES R2 binding. Do not recreate or alter that table here.
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS submissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      original_name TEXT NOT NULL,
      mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
      size_bytes INTEGER NOT NULL DEFAULT 0,
      storage_key TEXT NOT NULL UNIQUE,
      marked_storage_key TEXT,
      marked_name TEXT,
      score TEXT,
      feedback TEXT,
      status TEXT NOT NULL DEFAULT 'submitted',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      marked_at TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `).run();

  await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_submissions_user ON submissions(user_id, created_at DESC)`).run();
  await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_resources_created ON resources(created_at DESC)`).run();
}
__name(ensureResourceTables, "ensureResourceTables");

function hasPremiumAccess(user) {
  if (isAdminUser(user)) return true;
  return membershipInfo(user).plan === "premium" && membershipInfo(user).active;
}
__name(hasPremiumAccess, "hasPremiumAccess");

function safeFileName(name) {
  const value = String(name || "file").trim().replace(/[^a-zA-Z0-9._-]+/g, "_");
  return value.slice(-160) || "file";
}
__name(safeFileName, "safeFileName");

function makeStorageKey(prefix, userId, originalName) {
  return `${prefix}/${userId}/${crypto.randomUUID()}-${safeFileName(originalName)}`;
}
__name(makeStorageKey, "makeStorageKey");

function fileDownloadResponse(object, fallbackName, mimeType) {
  if (!object) return new Response("File not found.", { status: 404 });
  const headers = new Headers();
  headers.set("content-type", object.httpMetadata?.contentType || mimeType || "application/octet-stream");
  headers.set("content-length", String(object.size || 0));
  headers.set("cache-control", "private, no-store");
  headers.set("content-disposition", `attachment; filename="${safeFileName(fallbackName)}"`);
  return new Response(object.body, { headers });
}
__name(fileDownloadResponse, "fileDownloadResponse");

async function handleResources(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not authenticated." }, 401);
  if (!hasPremiumAccess(user)) return json({ error: "The Resource & Marking Centre is available to Premium members." }, 403);

  const result = await env.DB.prepare(`
    SELECT id, title, category, description, original_name, content_type, size_bytes, created_at
    FROM resources
    WHERE is_published = 1
    ORDER BY created_at DESC, id DESC
  `).all();
  return json({ success: true, resources: result.results || [] });
}
__name(handleResources, "handleResources");

async function handleResourceDownload(request, env, id) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not authenticated." }, 401);
  if (!hasPremiumAccess(user)) return json({ error: "Premium membership required." }, 403);
  const store = env.RESOURCE_FILES || null;
  if (!store) return json({ error: "Resource file storage is not configured. Add the RESOURCE_FILES R2 binding to the Worker." }, 503);

  const resource = await env.DB.prepare(`SELECT original_name, content_type, object_key FROM resources WHERE id = ? AND is_published = 1 LIMIT 1`).bind(id).first();
  if (!resource) return json({ error: "Resource not found." }, 404);
  const object = await store.get(resource.object_key);
  return fileDownloadResponse(object, resource.original_name, resource.content_type);
}
__name(handleResourceDownload, "handleResourceDownload");

async function handleSubmissions(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not authenticated." }, 401);
  if (!hasPremiumAccess(user)) return json({ error: "The Resource & Marking Centre is available to Premium members." }, 403);

  const result = await env.DB.prepare(`
    SELECT id, original_name, size_bytes, score, feedback, status, created_at, marked_at, marked_name
    FROM submissions
    WHERE user_id = ?
    ORDER BY created_at DESC, id DESC
  `).bind(user.id).all();
  return json({ success: true, submissions: result.results || [] });
}
__name(handleSubmissions, "handleSubmissions");

async function handleSubmissionDownload(request, env, id, marked) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not authenticated." }, 401);
  if (!hasPremiumAccess(user)) return json({ error: "Premium membership required." }, 403);
  const store = getFileStore(env);
  if (!store) return json({ error: "File storage is not configured. Add the FILES R2 binding to the Worker." }, 503);

  const submission = await env.DB.prepare(`
    SELECT original_name, mime_type, storage_key, marked_storage_key, marked_name
    FROM submissions WHERE id = ? AND user_id = ? LIMIT 1
  `).bind(id, user.id).first();
  if (!submission) return json({ error: "Submission not found." }, 404);

  const key = marked ? submission.marked_storage_key : submission.storage_key;
  if (!key) return json({ error: "The marked paper is not available yet." }, 404);
  const name = marked ? (submission.marked_name || `marked-${submission.original_name}`) : submission.original_name;
  const object = await store.get(key);
  if (!object) {
    return json({
      error: marked ? "The marked paper file could not be found." : "The submitted paper file could not be found."
    }, 404);
  }
  return fileDownloadResponse(object, name, marked ? (object.httpMetadata?.contentType || submission.mime_type) : submission.mime_type);
}
__name(handleSubmissionDownload, "handleSubmissionDownload");

async function handleCreateSubmission(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not authenticated." }, 401);
  if (!hasPremiumAccess(user)) return json({ error: "The Resource & Marking Centre is available to Premium members." }, 403);
  const store = getFileStore(env);
  if (!store) return json({ error: "File storage is not configured. Add the FILES R2 binding to the Worker." }, 503);

  const form = await request.formData();
  const file = form.get("file");
  if (!(file instanceof File) || !file.name) return json({ error: "Please select a file." }, 400);
  if (file.size < 1) return json({ error: "The selected file is empty." }, 400);
  if (file.size > RESOURCE_MAX_FILE_BYTES) return json({ error: "File is too large. Maximum size is 25 MB." }, 413);

  const key = makeStorageKey("submissions", user.id, file.name);
  await store.put(key, file.stream(), {
    httpMetadata: { contentType: file.type || "application/octet-stream" }
  });
  try {
    await env.DB.prepare(`
      INSERT INTO submissions (user_id, original_name, mime_type, size_bytes, storage_key, status)
      VALUES (?, ?, ?, ?, ?, 'submitted')
    `).bind(user.id, file.name, file.type || "application/octet-stream", file.size, key).run();
  } catch (error) {
    await store.delete(key);
    throw error;
  }
  return json({ success: true, message: "Paper submitted successfully for marking." }, 201);
}
__name(handleCreateSubmission, "handleCreateSubmission");

async function handleAdminResources(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Admin access required." }, 403);
  const result = await env.DB.prepare(`
    SELECT id, title, category, description, original_name, content_type, size_bytes, created_at, is_published
    FROM resources ORDER BY created_at DESC, id DESC
  `).all();
  return json({ success: true, resources: result.results || [] });
}
__name(handleAdminResources, "handleAdminResources");

async function handleAdminResourceUpload(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Admin access required." }, 403);
  const store = env.RESOURCE_FILES || null;
  if (!store) return json({ error: "Resource file storage is not configured. Add the RESOURCE_FILES R2 binding to the Worker." }, 503);

  const form = await request.formData();
  const file = form.get("file");
  const title = String(form.get("title") || "").trim();
  const category = String(form.get("category") || "Resource").trim() || "Resource";
  const description = String(form.get("description") || "").trim();
  if (!title) return json({ error: "Please enter a resource title." }, 400);
  if (!(file instanceof File) || !file.name) return json({ error: "Please select a resource file." }, 400);
  if (file.size < 1) return json({ error: "The selected file is empty." }, 400);
  if (file.size > RESOURCE_MAX_FILE_BYTES) return json({ error: "File is too large. Maximum size is 25 MB." }, 413);

  const key = makeStorageKey("resources", admin.id, file.name);
  await store.put(key, file.stream(), {
    httpMetadata: { contentType: file.type || "application/octet-stream" }
  });
  try {
    await env.DB.prepare(`
      INSERT INTO resources (title, description, category, object_key, original_name, content_type, size_bytes, uploaded_by, is_published)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
    `).bind(title, description, category, key, file.name, file.type || "application/octet-stream", file.size, admin.email).run();
  } catch (error) {
    await store.delete(key);
    throw error;
  }
  return json({ success: true, message: "Resource uploaded successfully." }, 201);
}
__name(handleAdminResourceUpload, "handleAdminResourceUpload");

async function handleAdminResourceDelete(request, env, resourceId) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Admin access required." }, 403);
  const store = env.RESOURCE_FILES || null;
  if (!store) return json({ error: "Resource file storage is not configured. Add the RESOURCE_FILES R2 binding to the Worker." }, 503);
  const resource = await env.DB.prepare("SELECT object_key FROM resources WHERE id = ? LIMIT 1").bind(resourceId).first();
  if (!resource) return json({ error: "Resource not found." }, 404);
  await store.delete(resource.object_key);
  await env.DB.prepare("DELETE FROM resources WHERE id = ?").bind(resourceId).run();
  return json({ success: true, message: "Resource deleted." });
}
__name(handleAdminResourceDelete, "handleAdminResourceDelete");

async function handleAdminSubmissions(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Admin access required." }, 403);
  const result = await env.DB.prepare(`
    SELECT s.id, s.original_name, s.size_bytes, s.score, s.feedback, s.status, s.created_at, s.marked_at, s.marked_name,
           u.name AS student_name, u.email AS student_email
    FROM submissions s
    JOIN users u ON u.id = s.user_id
    ORDER BY s.created_at DESC, s.id DESC
  `).all();
  return json({ success: true, submissions: result.results || [] });
}
__name(handleAdminSubmissions, "handleAdminSubmissions");

async function handleAdminMarkSubmission(request, env, id) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Admin access required." }, 403);
  const store = getFileStore(env);
  if (!store) return json({ error: "File storage is not configured. Add the FILES R2 binding to the Worker." }, 503);

  const existing = await env.DB.prepare(`
    SELECT id, marked_storage_key, original_name FROM submissions WHERE id = ? LIMIT 1
  `).bind(id).first();
  if (!existing) return json({ error: "Submission not found." }, 404);

  const form = await request.formData();
  const score = String(form.get("score") || "").trim();
  const feedback = String(form.get("feedback") || "").trim();
  const markedFile = form.get("marked_file");
  let markedKey = existing.marked_storage_key || null;
  let markedName = null;

  // A submission may only be moved to "marked" when an actual marked
  // document exists. This prevents a paper being shown as marked while
  // the student has nothing to download.
  if (!(markedFile instanceof File && markedFile.name) && !markedKey) {
    return json({
      error: "Please upload the marked paper before saving the marking."
    }, 400);
  }

  if (markedFile instanceof File && markedFile.name) {
    if (markedFile.size > RESOURCE_MAX_FILE_BYTES) return json({ error: "Marked file is too large. Maximum size is 25 MB." }, 413);
    markedKey = makeStorageKey("marked", admin.id, markedFile.name);
    markedName = markedFile.name;
    await store.put(markedKey, markedFile.stream(), {
      httpMetadata: { contentType: markedFile.type || "application/octet-stream" }
    });
  }

  try {
    await env.DB.prepare(`
      UPDATE submissions
      SET score = ?, feedback = ?, status = 'marked',
          marked_storage_key = ?, marked_name = COALESCE(?, marked_name),
          marked_at = datetime('now')
      WHERE id = ?
    `).bind(score || null, feedback || null, markedKey, markedName, id).run();
  } catch (error) {
    if (markedFile instanceof File && markedFile.name && markedKey) await store.delete(markedKey);
    throw error;
  }

  if (existing.marked_storage_key && markedFile instanceof File && markedFile.name && existing.marked_storage_key !== markedKey) {
    await store.delete(existing.marked_storage_key).catch(() => {});
  }
  return json({ success: true, message: "Marked paper saved successfully." });
}
__name(handleAdminMarkSubmission, "handleAdminMarkSubmission");

async function handleAdminStats(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Admin access required." }, 403);

  const [students, active, exams, videos] = await Promise.all([
    env.DB.prepare(`SELECT COUNT(*) AS count FROM users`).first(),
    env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM users
      WHERE lower(plan) IN ('basic','standard','premium')
        AND plan_expires_at IS NOT NULL
        AND plan_expires_at > datetime('now')
    `).first(),
    env.DB.prepare(`SELECT COUNT(*) AS count FROM exam_results`).first(),
    env.DB.prepare(`SELECT COUNT(*) AS count FROM video_activity`).first()
  ]);

  return json({
    success: true,
    stats: {
      students: Number(students?.count || 0),
      activeMemberships: Number(active?.count || 0),
      examAttempts: Number(exams?.count || 0),
      videoActivity: Number(videos?.count || 0)
    }
  });
}
__name(handleAdminStats, "handleAdminStats");

async function handleAdminStudents(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Admin access required." }, 403);

  const result = await env.DB.prepare(`
    SELECT
      id,
      name,
      email,
      plan,
      plan_started_at,
      plan_expires_at,
      created_at
    FROM users
    ORDER BY id DESC
  `).all();

  const students = (result.results || []).map((user) => {
    const membership = membershipInfo(user);
    return {
      id: user.id,
      name: user.name || "",
      email: user.email || "",
      plan: membership.plan,
      membership_active: membership.active,
      plan_started_at: membership.started_at,
      plan_expires_at: membership.expires_at,
      created_at: user.created_at
    };
  });

  return json({ success: true, students });
}
__name(handleAdminStudents, "handleAdminStudents");

async function handleAdminResults(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Admin access required." }, 403);

  const result = await env.DB.prepare(`
    SELECT
      er.id,
      er.exam_id,
      er.exam_title,
      er.exam_type,
      er.score,
      er.total,
      er.percentage,
      er.auto_submitted,
      er.submitted_at,
      u.id AS student_id,
      u.name AS student_name,
      u.email AS student_email
    FROM exam_results er
    JOIN users u ON u.id = er.user_id
    ORDER BY er.submitted_at DESC, er.id DESC
    LIMIT 500
  `).all();

  return json({ success: true, results: result.results || [] });
}
__name(handleAdminResults, "handleAdminResults");

function membershipInfo(user) {
  const plan = String(user.plan || "free").toLowerCase();
  const paidPlans = ["basic", "standard", "premium"];
  if (!paidPlans.includes(plan) || !user.plan_expires_at) {
    return {
      plan: "free",
      active: false,
      started_at: user.plan_started_at || null,
      expires_at: user.plan_expires_at || null
    };
  }
  const expiresAt = /* @__PURE__ */ new Date(
    String(user.plan_expires_at).replace(" ", "T") + "Z"
  );
  const active = !Number.isNaN(expiresAt.getTime()) && expiresAt.getTime() > Date.now();
  return {
    plan: active ? plan : "free",
    active,
    started_at: user.plan_started_at || null,
    expires_at: user.plan_expires_at
  };
}
__name(membershipInfo, "membershipInfo");
function publicUser(user) {
  const membership = membershipInfo(user);
  return {
    id: user.id,
    email: user.email,
    name: user.name || "",
    plan: membership.plan,
    membership_active: membership.active,
    plan_started_at: membership.started_at,
    plan_expires_at: membership.expires_at,
    role: String(user.role || "student").toLowerCase(),
    created_at: user.created_at
  };
}
__name(publicUser, "publicUser");
async function handleRegister(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json(
      { error: "Invalid request." },
      400
    );
  }
  const name = String(
    body.name || ""
  ).trim();
  const email = normalizeEmail(
    body.email
  );
  const password = String(
    body.password || ""
  );
  if (name.length < 2) {
    return json(
      { error: "Please enter your name." },
      400
    );
  }
  if (!isValidEmail(email)) {
    return json(
      { error: "Please enter a valid email address." },
      400
    );
  }
  if (password.length < 8) {
    return json(
      {
        error: "Password must be at least 8 characters."
      },
      400
    );
  }
  const existing = await env.DB.prepare(
    "SELECT id FROM users WHERE lower(email) = ? LIMIT 1"
  ).bind(email).first();
  if (existing) {
    return json(
      {
        error: "An account with this email already exists."
      },
      409
    );
  }
  const passwordHash = await hashPassword(password);
  try {
    const result = await env.DB.prepare(
      "INSERT INTO users (email, password_hash, name, plan, role) VALUES (?, ?, ?, 'free', 'student')"
    ).bind(
      email,
      passwordHash,
      name
    ).run();
    const userId = result.meta?.last_row_id;
    if (!userId) {
      return json(
        {
          error: "Account created, but the session could not be started."
        },
        500
      );
    }
    const session = await newSession(
      env,
      userId
    );
    const user = await env.DB.prepare(
      "SELECT id, email, name, plan, role, created_at FROM users WHERE id = ?"
    ).bind(userId).first();
    const response = json({
      ok: true,
      user: publicUser(user)
    });
    response.headers.append(
      "Set-Cookie",
      sessionCookie(
        session.token,
        session.expires
      )
    );
    return response;
  } catch (error) {
    console.error(
      "register error",
      error
    );
    return json(
      {
        error: "Could not create the account."
      },
      500
    );
  }
}
__name(handleRegister, "handleRegister");
async function handleLogin(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json(
      { error: "Invalid request." },
      400
    );
  }
  const email = normalizeEmail(
    body.email
  );
  const password = String(
    body.password || ""
  );
  if (!isValidEmail(email) || !password) {
    return json(
      {
        error: "Please enter your email and password."
      },
      400
    );
  }
  const user = await env.DB.prepare(
    `SELECT
        id,
        email,
        password_hash,
        name,
        plan,
        plan_started_at,
        plan_expires_at,
        role,
        created_at
       FROM users
       WHERE lower(email) = ?
       LIMIT 1`
  ).bind(email).first();
  if (!user) {
    return json(
      {
        error: "Incorrect email or password."
      },
      401
    );
  }
  const check = await verifyPassword(
    password,
    user.password_hash
  );
  if (!check.ok) {
    return json(
      {
        error: "Incorrect email or password."
      },
      401
    );
  }
  if (check.upgrade) {
    const upgraded = await hashPassword(password);
    await env.DB.prepare(
      "UPDATE users SET password_hash = ? WHERE id = ?"
    ).bind(
      upgraded,
      user.id
    ).run();
  }
  const session = await newSession(
    env,
    user.id
  );
  const response = json({
    ok: true,
    user: publicUser(user)
  });
  response.headers.append(
    "Set-Cookie",
    sessionCookie(
      session.token,
      session.expires
    )
  );
  return response;
}
__name(handleLogin, "handleLogin");
async function handleMe(request, env) {
  const user = await getSessionUser(
    request,
    env
  );
  return json({
    authenticated: !!user,
    user: user ? publicUser(user) : null
  });
}
__name(handleMe, "handleMe");
async function handleLogout(request, env) {
  const token = getCookie(
    request,
    "AT_SESSION"
  );
  if (token) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE token = ?"
    ).bind(token).run();
  }
  const response = json({ ok: true });
  response.headers.append(
    "Set-Cookie",
    clearSessionCookie()
  );
  return response;
}
__name(handleLogout, "handleLogout");
async function handleCourses(request, env) {
  const user = await getSessionUser(
    request,
    env
  );
  if (!user) {
    return json(
      {
        error: "Not authenticated"
      },
      401
    );
  }
  const result = await env.DB.prepare(`
      SELECT
        id,
        title,
        slug,
        description,
        category,
        level,
        is_published,
        created_at
      FROM courses
      WHERE is_published = 1
      ORDER BY id
    `).all();
  return json({
    user: publicUser(user),
    courses: result.results || []
  });
}
__name(handleCourses, "handleCourses");
async function handleLessonProgressGet(request, env) {
  const user = await getSessionUser(
    request,
    env
  );
  if (!user) {
    return json(
      { error: "Not authenticated" },
      401
    );
  }
  try {
    const result = await env.DB.prepare(`
      SELECT
        module_slug,
        lesson_number,
        completed,
        completed_at
      FROM lesson_progress
      WHERE user_id = ?
      ORDER BY module_slug, lesson_number
    `).bind(user.id).all();
    return json({
      success: true,
      progress: result.results || []
    });
  } catch (error) {
    console.error(
      "lesson progress read error",
      error
    );
    return json(
      { error: "Unable to load lesson progress." },
      500
    );
  }
}
__name(handleLessonProgressGet, "handleLessonProgressGet");
async function handleCourse(request, env, courseId) {
  const user = await getSessionUser(
    request,
    env
  );
  if (!user) {
    return json(
      {
        error: "Not authenticated"
      },
      401
    );
  }
  const course = await env.DB.prepare(`
      SELECT
        id,
        title,
        slug,
        description,
        category,
        level,
        is_published,
        created_at
      FROM courses
      WHERE
        id = ?
        AND is_published = 1
    `).bind(courseId).first();
  if (!course) {
    return json(
      {
        error: "Course not found."
      },
      404
    );
  }
  const lessons = await env.DB.prepare(`
      SELECT
        id,
        course_id,
        title,
        slug,
        lesson_type,
        is_free,
        is_published,
        sort_order,
        video_url,
        content
      FROM lessons
      WHERE
        course_id = ?
        AND is_published = 1
      ORDER BY
        sort_order,
        id
    `).bind(courseId).all();
  const isPaid = membershipInfo(user).active;
  return json({
    user: publicUser(user),
    course,
    lessons: (lessons.results || []).map((lesson) => {
      const allowed = Number(
        lesson.is_free
      ) === 1 || isPaid;
      return {
        ...lesson,
        content: allowed ? lesson.content : "",
        video_url: allowed ? lesson.video_url : "",
        locked: !allowed
      };
    })
  });
}
__name(handleCourse, "handleCourse");
async function cleanupExpiredSessions(env) {
  try {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE expires_at <= datetime('now')"
    ).run();
  } catch (error) {
    console.error(
      "session cleanup error",
      error
    );
  }
}
__name(cleanupExpiredSessions, "cleanupExpiredSessions");
function paymentPlanDetails(plan) {
  const plans = {
    basic: { name: "Basic", amount: 150 },
    standard: { name: "Standard", amount: 250 },
    premium: { name: "Premium", amount: 600 }
  };
  return plans[String(plan || "").toLowerCase()] || null;
}
__name(paymentPlanDetails, "paymentPlanDetails");
async function createPaymentReference() {
  const bytes = await randomBytes(5);
  return "AT-" + (/* @__PURE__ */ new Date()).toISOString().slice(0, 10).replace(/-/g, "") + "-" + bytesToHex(bytes).slice(0, 8).toUpperCase();
}
__name(createPaymentReference, "createPaymentReference");
async function handleCreatePayment(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not authenticated." }, 401);
  try {
    const body = await request.json();
    const plan = String(body.plan || "").trim().toLowerCase();
    const details = paymentPlanDetails(plan);
    if (!details) return json({ error: "Invalid membership plan." }, 400);
    const reference = await createPaymentReference();
    await env.DB.prepare(`
      INSERT INTO payments
        (user_email, amount, currency, status, payment_intent_id, description, transaction_reference, plan)
      VALUES (?, ?, 'SCR', 'pending', ?, ?, ?, ?)
    `).bind(
      user.email,
      details.amount,
      reference,
      `Aprann Tech ${details.name} membership - 30 days`,
      reference,
      plan
    ).run();
    return json({
      success: true,
      payment: {
        reference,
        plan,
        plan_name: details.name,
        amount: details.amount,
        currency: "SCR",
        status: "pending",
        access_period_days: 30,
        student_name: user.name || "",
        student_email: user.email
      }
    });
  } catch (error) {
    console.error("payment creation error", error);
    return json({ error: "Unable to create payment request." }, 500);
  }
}
__name(handleCreatePayment, "handleCreatePayment");
function isAdminUser(user) {
  return !!user && String(user.role || "").toLowerCase() === "admin";
}
__name(isAdminUser, "isAdminUser");
async function requireAdmin(request, env) {
  const user = await getSessionUser(request, env);
  if (!isAdminUser(user)) return null;
  return user;
}
__name(requireAdmin, "requireAdmin");
async function handleAdminPayments(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Admin access required." }, 403);
  const result = await env.DB.prepare(`
    SELECT id, user_email, amount, currency, status, payment_intent_id,
           created_at, description, transaction_reference, plan
    FROM payments
    WHERE status = 'pending'
    ORDER BY id DESC
  `).all();
  return json({ success: true, payments: result.results || [] });
}
__name(handleAdminPayments, "handleAdminPayments");
async function handleAdminPaymentHistory(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Admin access required." }, 403);
  const result = await env.DB.prepare(`
    SELECT id, user_email, amount, currency, status, payment_intent_id,
           created_at, approved_at, description, transaction_reference, plan
    FROM payments
    WHERE status = 'paid'
    ORDER BY COALESCE(approved_at, created_at) DESC, id DESC
    LIMIT 100
  `).all();
  return json({ success: true, payments: result.results || [] });
}
__name(handleAdminPaymentHistory, "handleAdminPaymentHistory");
async function handleAdminApprovePayment(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Admin access required." }, 403);
  try {
    const body = await request.json();
    const paymentId = Number(body.payment_id);
    const transactionReference = String(body.transaction_reference || "").trim();
    if (!Number.isInteger(paymentId) || paymentId < 1) {
      return json({ error: "Invalid payment." }, 400);
    }
    const payment = await env.DB.prepare(`
      SELECT id, user_email, amount, currency, status, transaction_reference, plan
      FROM payments WHERE id = ? LIMIT 1
    `).bind(paymentId).first();
    if (!payment) return json({ error: "Payment not found." }, 404);
    if (payment.status === "paid") return json({ error: "Payment is already approved." }, 409);
    const details = paymentPlanDetails(payment.plan);
    if (!details) return json({ error: "Invalid membership plan on payment." }, 400);
    const user = await env.DB.prepare(`
      SELECT id, email, name FROM users WHERE lower(email) = ? LIMIT 1
    `).bind(normalizeEmail(payment.user_email)).first();
    if (!user) return json({ error: "Student account not found." }, 404);
    const started = /* @__PURE__ */ new Date();
    const expires = new Date(started.getTime() + 30 * 864e5);
    const startedSql = started.toISOString().slice(0, 19).replace("T", " ");
    const expiresSql = expires.toISOString().slice(0, 19).replace("T", " ");
    await env.DB.prepare(`
      UPDATE users
      SET plan = ?, plan_started_at = ?, plan_expires_at = ?
      WHERE id = ?
    `).bind(payment.plan, startedSql, expiresSql, user.id).run();
    await env.DB.prepare(`
      UPDATE payments
      SET status = 'paid',
          transaction_reference = ?,
          approved_at = datetime('now')
      WHERE id = ?
    `).bind(transactionReference || payment.transaction_reference, paymentId).run();
    return json({
      success: true,
      message: "Payment approved and 30-day membership activated.",
      membership: {
        plan: details.name,
        started_at: startedSql,
        expires_at: expiresSql,
        student_email: user.email
      }
    });
  } catch (error) {
    console.error("admin payment approval error", error);
    return json({ error: "Unable to approve payment." }, 500);
  }
}
__name(handleAdminApprovePayment, "handleAdminApprovePayment");
async function handleLessonProgress(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) {
    return json(
      { error: "Not authenticated." },
      401
    );
  }
  try {
    const body = await request.json();
    const moduleSlug = String(body.module || "").trim();
    const lessonNumber = Number(body.lesson);
    if (!moduleSlug || !Number.isInteger(lessonNumber) || lessonNumber < 1) {
      return json(
        { error: "Invalid lesson data." },
        400
      );
    }
    await env.DB.prepare(`
      INSERT INTO lesson_progress
        (user_id, module_slug, lesson_number, completed, completed_at)
      VALUES
        (?, ?, ?, 1, datetime('now'))
      ON CONFLICT(user_id, module_slug, lesson_number)
      DO UPDATE SET
        completed = 1,
        completed_at = datetime('now')
    `).bind(
      user.id,
      moduleSlug,
      lessonNumber
    ).run();
    return json({
      success: true,
      message: "Lesson progress saved."
    });
  } catch (error) {
    console.error(
      "lesson progress error",
      error
    );
    return json(
      { error: "Unable to save lesson progress." },
      500
    );
  }
}
__name(handleLessonProgress, "handleLessonProgress");

function paypalBaseUrl(env) {
  return String(env.PAYPAL_ENV || "sandbox").toLowerCase() === "live"
    ? "https://api-m.paypal.com"
    : "https://api-m.sandbox.paypal.com";
}
__name(paypalBaseUrl, "paypalBaseUrl");
async function paypalAccessToken(env) {
  if (!env.PAYPAL_CLIENT_ID || !env.PAYPAL_CLIENT_SECRET) {
    throw new Error("PayPal credentials are not configured.");
  }
  const response = await fetch(paypalBaseUrl(env) + "/v1/oauth2/token", {
    method: "POST",
    headers: {
      "Authorization": "Basic " + btoa(env.PAYPAL_CLIENT_ID + ":" + env.PAYPAL_CLIENT_SECRET),
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: "grant_type=client_credentials"
  });
  const data = await response.json();
  if (!response.ok || !data.access_token) {
    console.error("PayPal token request failed", response.status, data.error);
    throw new Error("PayPal authentication failed.");
  }
  return data.access_token;
}
__name(paypalAccessToken, "paypalAccessToken");
function paypalPlanDetails(plan) {
  const plans = {
    basic: { name: "Basic", amount: "10.99" },
    standard: { name: "Standard", amount: "17.99" },
    premium: { name: "Premium", amount: "42.99" }
  };
  return plans[String(plan || "").toLowerCase()] || null;
}
__name(paypalPlanDetails, "paypalPlanDetails");
async function handlePayPalCreateOrder(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Please log in before paying." }, 401);
  try {
    const body = await request.json();
    const plan = String(body.plan || "").trim().toLowerCase();
    const details = paypalPlanDetails(plan);
    if (!details) return json({ error: "Invalid membership plan." }, 400);
    const reference = await createPaymentReference();
    const token = await paypalAccessToken(env);
    const response = await fetch(paypalBaseUrl(env) + "/v2/checkout/orders", {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Prefer": "return=representation"
      },
      body: JSON.stringify({
        intent: "CAPTURE",
        purchase_units: [{
          reference_id: reference,
          custom_id: reference,
          invoice_id: reference,
          description: "Aprann Tech " + details.name + " membership - 30 days",
          amount: { currency_code: "USD", value: details.amount }
        }],
        application_context: {
          brand_name: "Aprann Tech",
          user_action: "PAY_NOW",
          shipping_preference: "NO_SHIPPING",
          return_url: new URL("/paypal-checkout?status=success&plan=" + plan, request.url).toString(),
          cancel_url: new URL("/paypal-checkout?status=cancelled&plan=" + plan, request.url).toString()
        }
      })
    });
    const order = await response.json();
    if (!response.ok || !order.id) {
      console.error("PayPal create order failed", response.status, order.name);
      return json({ error: "PayPal could not create the order. Please try again." }, 502);
    }
    await env.DB.prepare(`
      INSERT INTO payments
        (user_email, amount, currency, status, payment_intent_id, description, transaction_reference, plan)
      VALUES (?, ?, 'USD', 'pending', ?, ?, ?, ?)
    `).bind(
      user.email, Number(details.amount), order.id,
      "Aprann Tech " + details.name + " membership - 30 days",
      reference, plan
    ).run();
    return json({ success: true, id: order.id, amount: details.amount, currency: "USD", plan_name: details.name });
  } catch (error) {
    console.error("PayPal order creation error", error);
    return json({ error: "Unable to start PayPal checkout. Please try again." }, 500);
  }
}
__name(handlePayPalCreateOrder, "handlePayPalCreateOrder");
async function handlePayPalCaptureOrder(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Please log in before completing payment." }, 401);
  try {
    const body = await request.json();
    const orderId = String(body.orderID || "").trim();
    if (!orderId || orderId.length > 100) return json({ error: "Invalid PayPal order." }, 400);
    const payment = await env.DB.prepare(`
      SELECT id, user_email, amount, currency, status, payment_intent_id, plan
      FROM payments WHERE payment_intent_id = ? AND lower(user_email) = ? LIMIT 1
    `).bind(orderId, normalizeEmail(user.email)).first();
    if (!payment) return json({ error: "This PayPal order does not belong to your account." }, 404);
    if (payment.status === "paid") return json({ success: true, message: "Payment already confirmed; membership is active." });
    const details = paypalPlanDetails(payment.plan);
    if (!details || payment.currency !== "USD" || Number(payment.amount).toFixed(2) !== details.amount) {
      return json({ error: "Payment details did not match the membership plan." }, 409);
    }
    const token = await paypalAccessToken(env);
    const captureResponse = await fetch(paypalBaseUrl(env) + "/v2/checkout/orders/" + encodeURIComponent(orderId) + "/capture", {
      method: "POST",
      headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json", "Prefer": "return=representation" },
      body: "{}"
    });
    let captured = await captureResponse.json();
    if (!captureResponse.ok) {
      const issue = (captured.details || []).map((d) => d.issue).filter(Boolean).join(", ");
      console.error("PayPal capture failed", captureResponse.status, captured.name, issue);
      // PayPal may have completed the capture even if the capture response was lost or retried.
      // Check the order itself before telling the student that payment failed.
      const orderResponse = await fetch(paypalBaseUrl(env) + "/v2/checkout/orders/" + encodeURIComponent(orderId), {
        method: "GET",
        headers: { "Authorization": "Bearer " + token, "Prefer": "return=representation" }
      });
      const orderDetails = await orderResponse.json();
      if (orderResponse.ok && orderDetails.status === "COMPLETED") {
        captured = orderDetails;
      } else {
        const safeIssue = issue || captured.name || "UNKNOWN";
        return json({
          error: "PayPal could not confirm the payment (" + safeIssue + "). No membership change was confirmed. Please try again or contact support."
        }, 502);
      }
    }
    const purchase = captured.purchase_units?.[0];
    const capture = purchase?.payments?.captures?.[0];
    const paidAmount = capture?.amount;
    if (captured.status !== "COMPLETED" || capture?.status !== "COMPLETED" ||
        paidAmount?.currency_code !== "USD" || paidAmount?.value !== details.amount ||
        (purchase?.custom_id && purchase.custom_id !== payment.transaction_reference)) {
      return json({ error: "PayPal did not confirm the expected completed payment." }, 409);
    }
    const started = new Date();
    const expires = new Date(started.getTime() + 30 * 864e5);
    const startedSql = started.toISOString().slice(0, 19).replace("T", " ");
    const expiresSql = expires.toISOString().slice(0, 19).replace("T", " ");
    const result = await env.DB.prepare(`
      UPDATE payments SET status = 'paid', approved_at = datetime('now')
      WHERE id = ? AND status = 'pending'
    `).bind(payment.id).run();
    if (!result.success || Number(result.meta?.changes || 0) !== 1) {
      return json({ error: "Payment was already processed. Refresh your membership page." }, 409);
    }
    await env.DB.prepare(`
      UPDATE users SET plan = ?, plan_started_at = ?, plan_expires_at = ?
      WHERE lower(email) = ?
    `).bind(payment.plan, startedSql, expiresSql, normalizeEmail(user.email)).run();
    return json({
      success: true,
      message: "Payment confirmed. Your 30-day membership is active.",
      membership: { plan: details.name, started_at: startedSql, expires_at: expiresSql }
    });
  } catch (error) {
    console.error("PayPal capture error", error);
    return json({ error: "Unable to confirm PayPal payment. Please contact support." }, 500);
  }
}
__name(handlePayPalCaptureOrder, "handlePayPalCaptureOrder");
function paypalCheckoutPage(env) {
  const clientId = String(env.PAYPAL_CLIENT_ID || "");
  if (!clientId) return new Response("PayPal checkout is not configured.", { status: 503 });
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Aprann Tech PayPal Checkout</title><style>body{font-family:Arial,sans-serif;background:#f4f7fb;color:#17243a;margin:0;padding:24px}.card{max-width:520px;margin:32px auto;background:#fff;padding:28px;border-radius:16px;box-shadow:0 8px 30px #12213b18}h1{margin-top:0;color:#163d70}.muted{color:#526174;line-height:1.5}.plans{display:grid;gap:10px;margin:22px 0}.plan{padding:14px;border:1px solid #ccd6e3;border-radius:10px;cursor:pointer}.plan.active{border:2px solid #1769aa;background:#f0f7ff}.plan input{margin-right:8px}#paypal-button-container{margin-top:20px}#message{margin-top:16px;font-weight:600}.notice{font-size:13px;color:#667085;margin-top:18px}</style><script src="https://www.paypal.com/sdk/js?client-id=${encodeURIComponent(clientId)}&currency=USD&intent=capture"></script></head><body><main class="card"><h1>Aprann Tech Membership</h1><p class="muted">Choose a plan for 30 days of access. Payments are one-time; there is no automatic monthly charge.</p><div class="plans"><label class="plan active"><input type="radio" name="plan" value="basic" checked>Basic — $10.99 USD</label><label class="plan"><input type="radio" name="plan" value="standard">Standard — $17.99 USD</label><label class="plan"><input type="radio" name="plan" value="premium">Premium — $42.99 USD</label></div><div id="paypal-button-container"></div><p id="message" role="status"></p><p class="notice">Sandbox test page. Do not use real money. You must be logged in to your Aprann Tech student account.</p></main><script>
const message=document.getElementById('message');
const requestedPlan=new URLSearchParams(location.search).get('plan');
if(['basic','standard','premium'].includes(requestedPlan)){const selected=document.querySelector('input[name="plan"][value="'+requestedPlan+'"]');if(selected)selected.checked=true;}
document.querySelectorAll('input[name="plan"]').forEach(input=>input.addEventListener('change',()=>{document.querySelectorAll('.plan').forEach(label=>label.classList.toggle('active',label.querySelector('input').checked));}));
document.querySelectorAll('.plan').forEach(label=>label.classList.toggle('active',label.querySelector('input').checked));
if(new URLSearchParams(location.search).get('status')==='cancelled') message.textContent='Payment cancelled. No membership payment was taken.';
if(new URLSearchParams(location.search).get('status')==='success') message.textContent='Return received. Complete the payment below if it is not already confirmed.';
paypal.Buttons({
  createOrder: async () => {
    message.textContent='Preparing secure PayPal checkout…';
    const plan=document.querySelector('input[name="plan"]:checked').value;
    const response=await fetch('/api/paypal/create-order',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({plan})});
    const data=await response.json();
    if(!response.ok||!data.id) throw new Error(data.error||'Could not create PayPal order. Please log in first.');
    return data.id;
  },
  onApprove: async (data) => {
    message.textContent='Confirming payment securely…';
    const response=await fetch('/api/paypal/capture-order',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({orderID:data.orderID})});
    const result=await response.json();
    if(!response.ok||!result.success) throw new Error(result.error||'Payment confirmation failed.');
    message.textContent=result.message+' Please return to your course page.';
  },
  onCancel: () => { message.textContent='Payment cancelled. No membership payment was taken.'; },
  onError: (err) => { message.textContent=(err&&err.message)||'PayPal checkout could not be completed. Please try again.'; }
}).render('#paypal-button-container').catch(err=>{message.textContent=err.message||'PayPal checkout could not load.';});
</script></body></html>`;
  return new Response(html, { headers: { "content-type": "text/html; charset=UTF-8", "cache-control": "no-store" } });
}
__name(paypalCheckoutPage, "paypalCheckoutPage");

var worker_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      await ensureMembershipColumns(env);
      await ensureRoleColumn(env);
      await ensureAdminAccount(env);
      await ensurePaymentColumns(env);
      await ensureActivityTables(env);
      await ensureResourceTables(env);
    } catch (error) {
      console.error("membership initialization error", error);
    }
    if (url.pathname === "/paypal-checkout" && request.method === "GET") {
      return paypalCheckoutPage(env);
    }
    if (url.pathname.startsWith(
      "/api/"
    )) {
      const method = request.method.toUpperCase();
      try {
        if (url.pathname === "/api/register" && method === "POST") {
          return await handleRegister(
            request,
            env
          );
        }
        if (url.pathname === "/api/login" && method === "POST") {
          return await handleLogin(
            request,
            env
          );
        }
        if (url.pathname === "/api/me" && method === "GET") {
          return await handleMe(
            request,
            env
          );
        }
        if (url.pathname === "/api/resources" && method === "GET") {
          return await handleResources(request, env);
        }
        if (url.pathname === "/api/submissions" && method === "GET") {
          return await handleSubmissions(request, env);
        }
        if (url.pathname === "/api/submissions" && method === "POST") {
          return await handleCreateSubmission(request, env);
        }
        if (url.pathname === "/api/admin/resources" && method === "GET") {
          return await handleAdminResources(request, env);
        }
        if (url.pathname === "/api/admin/resources/upload" && method === "POST") {
          return await handleAdminResourceUpload(request, env);
        }
        const adminResourceDeleteMatch = url.pathname.match(/^\/api\/admin\/resources\/(\d+)$/);
        if (adminResourceDeleteMatch && method === "DELETE") {
          return await handleAdminResourceDelete(request, env, Number(adminResourceDeleteMatch[1]));
        }
        if (url.pathname === "/api/admin/submissions" && method === "GET") {
          return await handleAdminSubmissions(request, env);
        }
        if (url.pathname === "/api/admin/payments" && method === "GET") {
          return await handleAdminPayments(request, env);
        }
        if (url.pathname === "/api/admin/payments/history" && method === "GET") {
          return await handleAdminPaymentHistory(request, env);
        }
        if (url.pathname === "/api/admin/approve-payment" && method === "POST") {
          return await handleAdminApprovePayment(request, env);
        }
        if (url.pathname === "/api/admin/stats" && method === "GET") {
          return await handleAdminStats(request, env);
        }
        if (url.pathname === "/api/admin/students" && method === "GET") {
          return await handleAdminStudents(request, env);
        }
        if (url.pathname === "/api/admin/results" && method === "GET") {
          return await handleAdminResults(request, env);
        }
        if (url.pathname === "/api/exam-results" && method === "POST") {
          return await handleSaveExamResult(request, env);
        }
        if (url.pathname === "/api/video-activity" && method === "POST") {
          return await handleSaveVideoActivity(request, env);
        }
        if (url.pathname === "/api/paypal/create-order" && method === "POST") {
          return await handlePayPalCreateOrder(request, env);
        }
        if (url.pathname === "/api/paypal/capture-order" && method === "POST") {
          return await handlePayPalCaptureOrder(request, env);
        }
        if (url.pathname === "/api/create-payment" && method === "POST") {
          return await handleCreatePayment(
            request,
            env
          );
        }
        if (url.pathname === "/api/lesson-progress" && method === "GET") {
          return await handleLessonProgressGet(
            request,
            env
          );
        }
        if (url.pathname === "/api/logout" && method === "POST") {
          return await handleLogout(
            request,
            env
          );
        }
        if (url.pathname === "/api/lesson-progress" && method === "POST") {
          return await handleLessonProgress(
            request,
            env
          );
        }
        if (url.pathname === "/api/courses" && method === "GET") {
          return await handleCourses(
            request,
            env
          );
        }
        const resourceDownloadMatch = url.pathname.match(/^\/api\/resources\/(\d+)\/download$/);
        if (resourceDownloadMatch && method === "GET") {
          return await handleResourceDownload(request, env, Number(resourceDownloadMatch[1]));
        }
        const markedSubmissionDownloadMatch = url.pathname.match(/^\/api\/submissions\/(\d+)\/marked\/download$/);
        if (markedSubmissionDownloadMatch && method === "GET") {
          return await handleSubmissionDownload(request, env, Number(markedSubmissionDownloadMatch[1]), true);
        }
        const submissionDownloadMatch = url.pathname.match(/^\/api\/submissions\/(\d+)\/download$/);
        if (submissionDownloadMatch && method === "GET") {
          return await handleSubmissionDownload(request, env, Number(submissionDownloadMatch[1]), false);
        }
        const adminMarkSubmissionMatch = url.pathname.match(/^\/api\/admin\/submissions\/(\d+)\/mark$/);
        if (adminMarkSubmissionMatch && method === "POST") {
          return await handleAdminMarkSubmission(request, env, Number(adminMarkSubmissionMatch[1]));
        }
        const courseMatch = url.pathname.match(
          /^\/api\/courses\/(\d+)$/
        );
        if (courseMatch && method === "GET") {
          return await handleCourse(
            request,
            env,
            Number(
              courseMatch[1]
            )
          );
        }
        return json(
          {
            error: "API endpoint not found."
          },
          404
        );
      } catch (error) {
        console.error(
          "API error",
          error
        );
        return json(
          {
            error: "Server error."
          },
          500
        );
      }
    }
    ctx.waitUntil(
      cleanupExpiredSessions(env)
    );
    const assetResponse = await env.ASSETS.fetch(request);
    if (request.method === "GET" && (url.pathname === "/" || url.pathname.endsWith(".html") || url.pathname === "/index.html")) {
      const contentType = assetResponse.headers.get("content-type") || "";
      if (contentType.includes("text/html") && assetResponse.ok) {
        let html = await assetResponse.text();
        const membershipBridge = `<script>
(function(){
  function updateMembershipPrices(){
    const replacements = [[/\\bSCR\\s*150\\b/g, '$10.99 USD'], [/\\bSCR\\s*250\\b/g, '$17.99 USD'], [/\\bSCR\\s*600\\b/g, '$42.99 USD']];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      const parent = node.parentElement;
      if (parent && !['SCRIPT','STYLE','NOSCRIPT'].includes(parent.tagName)) {
        let value = node.nodeValue || '';
        for (const [pattern, replacement] of replacements) value = value.replace(pattern, replacement);
        if (value !== node.nodeValue) node.nodeValue = value;
      }
    }
  }
  function interceptPlanButtons(event){
    const button = event.target && event.target.closest ? event.target.closest('button,a,[role="button"]') : null;
    if (!button) return;
    const label = (button.innerText || button.textContent || '').replace(/\\s+/g,' ').trim().toLowerCase();
    const match = label.match(/choose\\s+(basic|standard|premium)/);
    if (!match) return;
    event.preventDefault();
    event.stopPropagation();
    if (event.stopImmediatePropagation) event.stopImmediatePropagation();
    window.location.href = '/paypal-checkout?plan=' + encodeURIComponent(match[1]);
  }
  document.addEventListener('click', interceptPlanButtons, true);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', updateMembershipPrices, {once:true}); else updateMembershipPrices();
  const observer = new MutationObserver(updateMembershipPrices);
  const startObserver = function(){ if(document.body) observer.observe(document.body,{childList:true,subtree:true,characterData:true}); };
  if(document.body) startObserver(); else document.addEventListener('DOMContentLoaded',startObserver,{once:true});
})();
</script>`;
        if (!html.includes("AprannTechMembershipBridge")) {
          const markedBridge = membershipBridge.replace("<script>", '<script id="AprannTechMembershipBridge">');
          if (html.includes("</body>")) html = html.replace("</body>", markedBridge + "</body>");
          else html += markedBridge;
        }
        const headers = new Headers(assetResponse.headers);
        headers.delete("content-length");
        headers.delete("content-encoding");
        headers.delete("etag");
        return new Response(html, { status: assetResponse.status, statusText: assetResponse.statusText, headers });
      }
    }
    return assetResponse;
  }
};
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map