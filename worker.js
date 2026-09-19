/**
 * Aprann Tech - Cloudflare Worker backend
 * Version 1: authentication, sessions and membership
 */

const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 100000;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store"
    }
  });
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const base64 =
    value.replace(/-/g, "+").replace(/_/g, "/") +
    "===".slice((value.length + 3) % 4);

  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text)
  );
  return bytesToHex(digest);
}

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

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

async function verifyPassword(password, stored) {
  if (!stored) {
    return { ok: false, upgrade: false };
  }

  // Support existing SHA-256 password hashes.
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

  if (
    parts.length !== 4 ||
    parts[0] !== "pbkdf2"
  ) {
    return { ok: false, upgrade: false };
  }

  const iterations = Number(parts[1]);

  if (
    !Number.isInteger(iterations) ||
    iterations < 10000 ||
    iterations > 1000000
  ) {
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

async function newSession(env, userId) {
  const token = bytesToBase64Url(
    await randomBytes(32)
  );

  const expires = new Date(
    Date.now() + SESSION_DAYS * 86400000
  )
    .toISOString()
    .slice(0, 19)
    .replace("T"," ");

  await env.DB.prepare(
    "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
  )
    .bind(token, userId, expires)
    .run();

  return {
    token,
    expires
  };
}

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
  `)
    .bind(token)
    .first();

  if (!row) {
    return null;
  }

  return row;
}

async function ensureMembershipColumns(env) {
  try {
    const columns = await env.DB.prepare("PRAGMA table_info(users)").all();
    const names = new Set((columns.results || []).map(column => column.name));

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

  const expiresAt = new Date(
    String(user.plan_expires_at).replace(" ", "T") + "Z"
  );

  const active =
    !Number.isNaN(expiresAt.getTime()) &&
    expiresAt.getTime() > Date.now();

  return {
    plan: active ? plan : "free",
    active,
    started_at: user.plan_started_at || null,
    expires_at: user.plan_expires_at
  };
}

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
    created_at: user.created_at
  };
}

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
        error:
          "Password must be at least 8 characters."
      },
      400
    );
  }

  const existing = await env.DB.prepare(
    "SELECT id FROM users WHERE lower(email) = ? LIMIT 1"
  )
    .bind(email)
    .first();

  if (existing) {
    return json(
      {
        error:
          "An account with this email already exists."
      },
      409
    );
  }

  const passwordHash =
    await hashPassword(password);

  try {
    const result = await env.DB.prepare(
      "INSERT INTO users (email, password_hash, name, plan) VALUES (?, ?, ?, 'free')"
    )
      .bind(
        email,
        passwordHash,
        name
      )
      .run();

    const userId =
      result.meta?.last_row_id;

    if (!userId) {
      return json(
        {
          error:
            "Account created, but the session could not be started."
        },
        500
      );
    }

    const session =
      await newSession(
        env,
        userId
      );

    const user =
      await env.DB.prepare(
        "SELECT id, email, name, plan, created_at FROM users WHERE id = ?"
      )
        .bind(userId)
        .first();

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
        error:
          "Could not create the account."
      },
      500
    );
  }
}

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

  if (
    !isValidEmail(email) ||
    !password
  ) {
    return json(
      {
        error:
          "Please enter your email and password."
      },
      400
    );
  }

  const user =
    await env.DB.prepare(
      `SELECT
        id,
        email,
        password_hash,
        name,
        plan,
        plan_started_at,
        plan_expires_at,
        created_at
       FROM users
       WHERE lower(email) = ?
       LIMIT 1`
    )
      .bind(email)
      .first();

  if (!user) {
    return json(
      {
        error:
          "Incorrect email or password."
      },
      401
    );
  }

  const check =
    await verifyPassword(
      password,
      user.password_hash
    );

  if (!check.ok) {
    return json(
      {
        error:
          "Incorrect email or password."
      },
      401
    );
  }

  // Upgrade old SHA-256 passwords
  // after a successful login.
  if (check.upgrade) {
    const upgraded =
      await hashPassword(password);

    await env.DB.prepare(
      "UPDATE users SET password_hash = ? WHERE id = ?"
    )
      .bind(
        upgraded,
        user.id
      )
      .run();
  }

  const session =
    await newSession(
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

async function handleMe(request, env) {
  const user =
    await getSessionUser(
      request,
      env
    );

  return json({
    authenticated: !!user,
    user: user
      ? publicUser(user)
      : null
  });
}

async function handleLogout(request, env) {
  const token =
    getCookie(
      request,
      "AT_SESSION"
    );

  if (token) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE token = ?"
    )
      .bind(token)
      .run();
  }

  const response =
    json({ ok: true });

  response.headers.append(
    "Set-Cookie",
    clearSessionCookie()
  );

  return response;
}

async function handleCourses(
  request,
  env
) {
  const user =
    await getSessionUser(
      request,
      env
    );

  if (!user) {
    return json(
      {
        error:
          "Not authenticated"
      },
      401
    );
  }

  const result =
    await env.DB.prepare(`
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
    `)
      .all();

  return json({
    user: publicUser(user),
    courses:
      result.results || []
  });
}

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
    `)
      .bind(user.id)
      .all();

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
async function handleCourse(
  request,
  env,
  courseId
) {
  const user =
    await getSessionUser(
      request,
      env
    );

  if (!user) {
    return json(
      {
        error:
          "Not authenticated"
      },
      401
    );
  }

  const course =
    await env.DB.prepare(`
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
    `)
      .bind(courseId)
      .first();

  if (!course) {
    return json(
      {
        error:
          "Course not found."
      },
      404
    );
  }

  const lessons =
    await env.DB.prepare(`
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
    `)
      .bind(courseId)
      .all();

  const isPaid = membershipInfo(user).active;

  return json({
    user: publicUser(user),
    course,
    lessons:
      (lessons.results || [])
        .map(lesson => {
          const allowed =
            Number(
              lesson.is_free
            ) === 1 ||
            isPaid;

          return {
            ...lesson,
            content:
              allowed
                ? lesson.content
                : "",
            video_url:
              allowed
                ? lesson.video_url
                : "",
            locked:
              !allowed
          };
        })
  });
}

async function cleanupExpiredSessions(
  env
) {
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

    if (
      !moduleSlug ||
      !Number.isInteger(lessonNumber) ||
      lessonNumber < 1
    ) {
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
    `)
      .bind(
        user.id,
        moduleSlug,
        lessonNumber
      )
      .run();

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
export default {
  async fetch(
    request,
    env,
    ctx
  ) {
    const url =
      new URL(request.url);

    if (
      url.pathname.startsWith(
        "/api/"
      )
    ) {
      const method =
        request.method.toUpperCase();

      try {
        if (
          url.pathname ===
            "/api/register" &&
          method === "POST"
        ) {
          return await handleRegister(
            request,
            env
          );
        }

        if (
          url.pathname ===
            "/api/login" &&
          method === "POST"
        ) {
          return await handleLogin(
            request,
            env
          );
        }

        if (
          url.pathname ===
            "/api/me" &&
          method === "GET"
        ) {
          return await handleMe(
            request,
            env
          );
        }

       if (
  url.pathname ===
  "/api/lesson-progress" &&
  method === "GET"
) {
  return await handleLessonProgressGet(
    request,
    env
  );
}
        if (
          url.pathname ===
            "/api/logout" &&
          method === "POST"
        ) {
          return await handleLogout(
            request,
            env
          );
        }

       if (
  url.pathname ===
  "/api/lesson-progress" &&
  method === "POST"
) {
  return await handleLessonProgress(
    request,
    env
  );
}
        if (
          url.pathname ===
            "/api/courses" &&
          method === "GET"
        ) {
          return await handleCourses(
            request,
            env
          );
        }

        const courseMatch =
          url.pathname.match(
            /^\/api\/courses\/(\d+)$/
          );

        if (
          courseMatch &&
          method === "GET"
        ) {
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
            error:
              "API endpoint not found."
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
            error:
           "Server error."
          },
          500
        );
      }
    }

    ctx.waitUntil(
      cleanupExpiredSessions(env)
    );

    try {
      await ensureMembershipColumns(env);
    } catch (error) {
      console.error("membership initialization error", error);
    }

    return env.ASSETS.fetch(
      request
    );
  }
};
