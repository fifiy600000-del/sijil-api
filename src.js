import bcrypt from "bcryptjs";

// ============ إعدادات عامة ============

const CODE_TTL_MINUTES = 10;        // مدة صلاحية رمز تفعيل البريد
const RESEND_COOLDOWN_SECONDS = 60; // مهلة بين كل إعادة إرسال
const MAX_CODE_ATTEMPTS = 5;        // محاولات خاطئة قبل رفض الرمز

const WORKER_CODE_TTL_MINUTES = 15; // مدة صلاحية كود دعوة العامل

const FROM_NAME = "سجل";

// ============================================================
// Worker
// ============================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ========================================================
    // REGISTER
    // ========================================================

    if (url.pathname === "/api/register") {
      if (request.method !== "POST") {
        return json(
          { success: false, message: "استخدم POST" },
          405
        );
      }

      const data = await request.json();
      const { full_name, email, password } = data;

      if (!email || !password) {
        return json(
          {
            success: false,
            message: "email و password مطلوبان"
          },
          400
        );
      }

      if (!isValidEmail(email)) {
        return json(
          {
            success: false,
            message: "صيغة البريد الإلكتروني غير صحيحة"
          },
          400
        );
      }

      const existing = await env.DB
        .prepare(
          "SELECT id, verified FROM users WHERE email = ?"
        )
        .bind(email)
        .first();

      if (existing && existing.verified) {
        return json(
          {
            success: false,
            message: "البريد الإلكتروني مستخدم مسبقًا"
          },
          409
        );
      }

      const password_hash = await bcrypt.hash(password, 10);

      const code = generateCode();

      const expiresAt = new Date(
        Date.now() + CODE_TTL_MINUTES * 60 * 1000
      ).toISOString();

      const now = new Date().toISOString();

      if (existing) {
        await env.DB
          .prepare(
            `UPDATE users
             SET full_name = ?,
                 password_hash = ?,
                 verification_code = ?,
                 code_expires_at = ?,
                 code_attempts = 0,
                 last_code_sent_at = ?
             WHERE email = ?`
          )
          .bind(
            full_name || "",
            password_hash,
            code,
            expiresAt,
            now,
            email
          )
          .run();
      } else {
        const id = crypto.randomUUID();

        await env.DB
          .prepare(
            `INSERT INTO users
             (
               id,
               full_name,
               email,
               password_hash,
               verified,
               verification_code,
               code_expires_at,
               last_code_sent_at
             )
             VALUES (?, ?, ?, ?, 0, ?, ?, ?)`
          )
          .bind(
            id,
            full_name || "",
            email,
            password_hash,
            code,
            expiresAt,
            now
          )
          .run();
      }

      // إرسال كود التحقق بواسطة Resend
      const emailSent = await sendVerificationEmail(
        env,
        email,
        full_name,
        code
      );

      // لا نرجع نجاح إذا فشل إرسال البريد
      if (!emailSent) {
        return json(
          {
            success: false,
            message: "تم إنشاء الحساب لكن فشل إرسال رمز التحقق إلى البريد"
          },
          502
        );
      }

      return json({
        success: true,
        message: "تم إنشاء الحساب، تحقق من بريدك الإلكتروني",
        email
      });
    }

    // ========================================================
    // VERIFY EMAIL
    // ========================================================

    if (url.pathname === "/api/verify-email") {
      if (request.method !== "POST") {
        return json(
          {
            success: false,
            message: "استخدم POST"
          },
          405
        );
      }

      const data = await request.json();
      const { email, code } = data;

      if (!email || !code) {
        return json(
          {
            success: false,
            message: "email و code مطلوبان"
          },
          400
        );
      }

      const user = await env.DB
        .prepare(
          `SELECT
             id,
             verified,
             verification_code,
             code_expires_at,
             code_attempts
           FROM users
           WHERE email = ?`
        )
        .bind(email)
        .first();

      if (!user) {
        return json(
          {
            success: false,
            message: "الحساب غير موجود"
          },
          404
        );
      }

      if (user.verified) {
        return json(
          {
            success: false,
            message: "الحساب مفعّل مسبقًا"
          },
          409
        );
      }

      if (user.code_attempts >= MAX_CODE_ATTEMPTS) {
        return json(
          {
            success: false,
            message: "محاولات كثيرة، اطلب رمزًا جديدًا"
          },
          429
        );
      }

      if (
        !user.verification_code ||
        !user.code_expires_at ||
        new Date(user.code_expires_at) < new Date()
      ) {
        return json(
          {
            success: false,
            message: "الرمز منتهي الصلاحية، اطلب رمزًا جديدًا"
          },
          410
        );
      }

      if (user.verification_code !== code) {
        await env.DB
          .prepare(
            `UPDATE users
             SET code_attempts = code_attempts + 1
             WHERE id = ?`
          )
          .bind(user.id)
          .run();

        return json(
          {
            success: false,
            message: "الرمز غير صحيح"
          },
          401
        );
      }

      await env.DB
        .prepare(
          `UPDATE users
           SET verified = 1,
               verification_code = NULL,
               code_expires_at = NULL,
               code_attempts = 0
           WHERE id = ?`
        )
        .bind(user.id)
        .run();

      const token = crypto.randomUUID();

      const sessionExpiresAt = new Date(
        Date.now() + 30 * 24 * 60 * 60 * 1000
      ).toISOString();

      await env.DB
        .prepare(
          `INSERT INTO sessions
           (token, user_id, expires_at)
           VALUES (?, ?, ?)`
        )
        .bind(
          token,
          user.id,
          sessionExpiresAt
        )
        .run();

      return json({
        success: true,
        message: "تم تفعيل الحساب",
        token
      });
    }

    // ========================================================
    // RESEND CODE
    // ========================================================

    if (url.pathname === "/api/resend-code") {
      if (request.method !== "POST") {
        return json(
          {
            success: false,
            message: "استخدم POST"
          },
          405
        );
      }

      const data = await request.json();
      const { email } = data;

      if (!email) {
        return json(
          {
            success: false,
            message: "email مطلوب"
          },
          400
        );
      }

      const user = await env.DB
        .prepare(
          `SELECT
             id,
             full_name,
             verified,
             last_code_sent_at
           FROM users
           WHERE email = ?`
        )
        .bind(email)
        .first();

      if (!user) {
        return json(
          {
            success: false,
            message: "الحساب غير موجود"
          },
          404
        );
      }

      if (user.verified) {
        return json(
          {
            success: false,
            message: "الحساب مفعّل مسبقًا"
          },
          409
        );
      }

      if (user.last_code_sent_at) {
        const elapsed =
          (Date.now() -
            new Date(user.last_code_sent_at).getTime()) /
          1000;

        if (elapsed < RESEND_COOLDOWN_SECONDS) {
          const wait = Math.ceil(
            RESEND_COOLDOWN_SECONDS - elapsed
          );

          return json(
            {
              success: false,
              message: `الرجاء الانتظار ${wait} ثانية قبل إعادة الإرسال`
            },
            429
          );
        }
      }

      const code = generateCode();

      const expiresAt = new Date(
        Date.now() + CODE_TTL_MINUTES * 60 * 1000
      ).toISOString();

      const now = new Date().toISOString();

      await env.DB
        .prepare(
          `UPDATE users
           SET verification_code = ?,
               code_expires_at = ?,
               code_attempts = 0,
               last_code_sent_at = ?
           WHERE id = ?`
        )
        .bind(
          code,
          expiresAt,
          now,
          user.id
        )
        .run();

      // إرسال الرمز الجديد
      const emailSent = await sendVerificationEmail(
        env,
        email,
        user.full_name,
        code
      );

      if (!emailSent) {
        return json(
          {
            success: false,
            message: "فشل إرسال رمز التحقق، حاول مرة أخرى"
          },
          502
        );
      }

      return json({
        success: true,
        message: "تم إرسال رمز جديد إلى بريدك الإلكتروني"
      });
    }

    // ========================================================
    // LOGIN
    // ========================================================

    if (url.pathname === "/api/login") {
      if (request.method !== "POST") {
        return json(
          {
            success: false,
            message: "استخدم POST"
          },
          405
        );
      }

      const data = await request.json();
      const { email, password } = data;

      if (!email || !password) {
        return json(
          {
            success: false,
            message: "email و password مطلوبان"
          },
          400
        );
      }

      const user = await env.DB
        .prepare(
          `SELECT
             id,
             email,
             password_hash,
             verified
           FROM users
           WHERE email = ?`
        )
        .bind(email)
        .first();

      if (!user) {
        return json(
          {
            success: false,
            message: "البريد الإلكتروني أو كلمة المرور غير صحيحة"
          },
          401
        );
      }

      const valid = await bcrypt.compare(
        password,
        user.password_hash
      );

      if (!valid) {
        return json(
          {
            success: false,
            message: "البريد الإلكتروني أو كلمة المرور غير صحيحة"
          },
          401
        );
      }

      if (!user.verified) {
        return json(
          {
            success: false,
            message: "الحساب غير مفعّل، تحقق من بريدك الإلكتروني"
          },
          403
        );
      }

      const token = crypto.randomUUID();

      const expiresAt = new Date(
        Date.now() + 30 * 24 * 60 * 60 * 1000
      ).toISOString();

      await env.DB
        .prepare(
          `INSERT INTO sessions
           (token, user_id, expires_at)
           VALUES (?, ?, ?)`
        )
        .bind(
          token,
          user.id,
          expiresAt
        )
        .run();

      return json({
        success: true,
        message: "تم تسجيل الدخول",
        token,
        user: {
          id: user.id,
          email: user.email
        }
      });
    }

    // ========================================================
    // LOGOUT
    // ========================================================

    if (
      url.pathname === "/api/logout" &&
      request.method === "POST"
    ) {
      const token = getToken(request);

      if (!token) {
        return json(
          {
            success: false,
            message: "غير مسجل الدخول"
          },
          401
        );
      }

      const ownerDel = await env.DB
        .prepare(
          "DELETE FROM sessions WHERE token = ?"
        )
        .bind(token)
        .run();

      if (
        !ownerDel.meta ||
        ownerDel.meta.changes === 0
      ) {
        await env.DB
          .prepare(
            "DELETE FROM worker_sessions WHERE token = ?"
          )
          .bind(token)
          .run();
      }

      return json({
        success: true,
        message: "تم تسجيل الخروج"
      });
    }

    // ========================================================
    // إنشاء كود دعوة عامل
    // المالك فقط
    // ========================================================

    if (
      url.pathname === "/api/workers/generate" &&
      request.method === "POST"
    ) {
      const token = getToken(request);

      if (!token) {
        return json(
          {
            success: false,
            message: "غير مسجل الدخول"
          },
          401
        );
      }

      const access = await getAccess(env, token);

      if (!access) {
        return json(
          {
            success: false,
            message: "الجلسة غير صالحة أو منتهية"
          },
          401
        );
      }

      if (access.type !== "owner") {
        return json(
          {
            success: false,
            message: "العامل ما يقدر يضيف عمال جدد"
          },
          403
        );
      }

      const code = generateCode();

      const expiresAt = new Date(
        Date.now() +
          WORKER_CODE_TTL_MINUTES * 60 * 1000
      ).toISOString();

      const id = crypto.randomUUID();

      await env.DB
        .prepare(
          `INSERT INTO workers
           (
             id,
             owner_user_id,
             code,
             code_expires_at,
             status
           )
           VALUES (?, ?, ?, ?, 'pending')`
        )
        .bind(
          id,
          access.owner_user_id,
          code,
          expiresAt
        )
        .run();

      return json({
        success: true,
        message:
          "شارك هذا الكود مع العامل، صالح لمدة 15 دقيقة",
        code,
        expires_at: expiresAt
      });
    }

    // ========================================================
    // انضمام العامل بالكود
    // بدون تسجيل دخول
    // ========================================================

    if (
      url.pathname === "/api/workers/join" &&
      request.method === "POST"
    ) {
      const data = await request.json();
      const { code, name } = data;

      if (!code) {
        return json(
          {
            success: false,
            message: "الكود مطلوب"
          },
          400
        );
      }

      const pending = await env.DB
        .prepare(
          `SELECT
             id,
             owner_user_id,
             code_expires_at,
             status
           FROM workers
           WHERE code = ?
             AND status = 'pending'`
        )
        .bind(code)
        .first();

      if (!pending) {
        return json(
          {
            success: false,
            message: "الكود غير صحيح"
          },
          404
        );
      }

      if (
        new Date(pending.code_expires_at) <
        new Date()
      ) {
        return json(
          {
            success: false,
            message:
              "الكود منتهي الصلاحية، اطلب كودًا جديدًا"
          },
          410
        );
      }

      const now = new Date().toISOString();

      await env.DB
        .prepare(
          `UPDATE workers
           SET status = 'active',
               name = ?,
               joined_at = ?,
               code = NULL,
               code_expires_at = NULL
           WHERE id = ?`
        )
        .bind(
          name || "عامل",
          now,
          pending.id
        )
        .run();

      const token = crypto.randomUUID();

      const expiresAt = new Date(
        Date.now() + 30 * 24 * 60 * 60 * 1000
      ).toISOString();

      await env.DB
        .prepare(
          `INSERT INTO worker_sessions
           (
             token,
             worker_id,
             owner_user_id,
             expires_at
           )
           VALUES (?, ?, ?, ?)`
        )
        .bind(
          token,
          pending.id,
          pending.owner_user_id,
          expiresAt
        )
        .run();

      return json({
        success: true,
        message: "تم الانضمام بنجاح",
        token
      });
    }

    // ========================================================
    // قائمة العمال
    // المالك فقط
    // ========================================================

    if (
      url.pathname === "/api/workers" &&
      request.method === "GET"
    ) {
      const token = getToken(request);

      if (!token) {
        return json(
          {
            success: false,
            message: "غير مسجل الدخول"
          },
          401
        );
      }

      const access = await getAccess(env, token);

      if (!access) {
        return json(
          {
            success: false,
            message: "الجلسة غير صالحة أو منتهية"
          },
          401
        );
      }

      if (access.type !== "owner") {
        return json(
          {
            success: false,
            message: "غير مصرح"
          },
          403
        );
      }

      const result = await env.DB
        .prepare(
          `SELECT
             id,
             name,
             status,
             joined_at,
             created_at
           FROM workers
           WHERE owner_user_id = ?
             AND status = 'active'
           ORDER BY joined_at DESC`
        )
        .bind(access.owner_user_id)
        .all();

      return json({
        success: true,
        workers: result.results
      });
    }

    // ========================================================
    // حذف عامل
    // المالك فقط
    // ========================================================

    if (
      url.pathname.startsWith("/api/workers/") &&
      request.method === "DELETE"
    ) {
      const token = getToken(request);

      if (!token) {
        return json(
          {
            success: false,
            message: "غير مسجل الدخول"
          },
          401
        );
      }

      const access = await getAccess(env, token);

      if (!access) {
        return json(
          {
            success: false,
            message: "الجلسة غير صالحة أو منتهية"
          },
          401
        );
      }

      if (access.type !== "owner") {
        return json(
          {
            success: false,
            message: "غير مصرح"
          },
          403
        );
      }

      const workerId =
        url.pathname.replace(
          "/api/workers/",
          ""
        );

      const worker = await env.DB
        .prepare(
          `SELECT id
           FROM workers
           WHERE id = ?
             AND owner_user_id = ?`
        )
        .bind(
          workerId,
          access.owner_user_id
        )
        .first();

      if (!worker) {
        return json(
          {
            success: false,
            message: "العامل غير موجود"
          },
          404
        );
      }

      // نحذف كل جلساته أولًا
      await env.DB
        .prepare(
          "DELETE FROM worker_sessions WHERE worker_id = ?"
        )
        .bind(workerId)
        .run();

      // ثم نحذف العامل
      await env.DB
        .prepare(
          "DELETE FROM workers WHERE id = ?"
        )
        .bind(workerId)
        .run();

      return json({
        success: true,
        message: "تم حذف العامل، فقد الوصول للحساب"
      });
    }

    // ========================================================
    // CREATE NOTEBOOK
    // ========================================================

    if (
      url.pathname === "/api/notebooks" &&
      request.method === "POST"
    ) {
      const token = getToken(request);

      if (!token) {
        return json(
          {
            success: false,
            message: "غير مسجل الدخول"
          },
          401
        );
      }

      const access = await getAccess(env, token);

      if (!access) {
        return json(
          {
            success: false,
            message: "الجلسة غير صالحة أو منتهية"
          },
          401
        );
      }

      const data = await request.json();

      const title =
        data.title || "سجل جديد";

      const id = crypto.randomUUID();

      await env.DB
        .prepare(
          `INSERT INTO notebooks
           (id, user_id, title)
           VALUES (?, ?, ?)`
        )
        .bind(
          id,
          access.owner_user_id,
          title
        )
        .run();

      return json({
        success: true,
        message: "تم إنشاء السجل",
        notebook: {
          id,
          title
        }
      });
    }

    // ========================================================
    // ADD ROW
    // ========================================================

    if (
      url.pathname === "/api/rows" &&
      request.method === "POST"
    ) {
      const token = getToken(request);

      if (!token) {
        return json(
          {
            success: false,
            message: "غير مسجل الدخول"
          },
          401
        );
      }

      const access = await getAccess(env, token);

      if (!access) {
        return json(
          {
            success: false,
            message: "الجلسة غير صالحة أو منتهية"
          },
          401
        );
      }

      const data = await request.json();

      const {
        notebook_id,
        name,
        amount = 0,
        quantity = 0,
        notes = ""
      } = data;

      if (!notebook_id) {
        return json(
          {
            success: false,
            message: "notebook_id مطلوب"
          },
          400
        );
      }

      const notebook = await env.DB
        .prepare(
          `SELECT id
           FROM notebooks
           WHERE id = ?
             AND user_id = ?`
        )
        .bind(
          notebook_id,
          access.owner_user_id
        )
        .first();

      if (!notebook) {
        return json(
          {
            success: false,
            message: "السجل غير موجود"
          },
          404
        );
      }

      const positionResult = await env.DB
        .prepare(
          `SELECT
             COALESCE(MAX(position), -1) + 1 AS position
           FROM rows
           WHERE notebook_id = ?`
        )
        .bind(notebook_id)
        .first();

      const position =
        positionResult.position;

      const id = crypto.randomUUID();

      await env.DB
        .prepare(
          `INSERT INTO rows
           (
             id,
             notebook_id,
             position,
             name,
             amount,
             quantity,
             notes
           )
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          id,
          notebook_id,
          position,
          name || "",
          Number(amount) || 0,
          Number(quantity) || 0,
          notes || ""
        )
        .run();

      return json({
        success: true,
        message: "تمت إضافة الصف",
        row: {
          id,
          notebook_id,
          position,
          name: name || "",
          amount: Number(amount) || 0,
          quantity: Number(quantity) || 0,
          notes: notes || ""
        }
      });
    }

    // ========================================================
    // GET ROWS
    // ========================================================

    if (
      url.pathname === "/api/rows" &&
      request.method === "GET"
    ) {
      const token = getToken(request);

      const notebookId =
        url.searchParams.get("notebook_id");

      if (!token) {
        return json(
          {
            success: false,
            message: "غير مسجل الدخول"
          },
          401
        );
      }

      const access = await getAccess(env, token);

      if (!access) {
        return json(
          {
            success: false,
            message: "الجلسة غير صالحة أو منتهية"
          },
          401
        );
      }

      if (!notebookId) {
        return json(
          {
            success: false,
            message: "notebook_id مطلوب"
          },
          400
        );
      }

      const notebook = await env.DB
        .prepare(
          `SELECT
             id,
             title
           FROM notebooks
           WHERE id = ?
             AND user_id = ?`
        )
        .bind(
          notebookId,
          access.owner_user_id
        )
        .first();

      if (!notebook) {
        return json(
          {
            success: false,
            message: "السجل غير موجود"
          },
          404
        );
      }

      const result = await env.DB
        .prepare(
          `SELECT
             id,
             notebook_id,
             position,
             name,
             amount,
             quantity,
             notes
           FROM rows
           WHERE notebook_id = ?
           ORDER BY position ASC`
        )
        .bind(notebookId)
        .all();

      return json({
        success: true,
        notebook,
        rows: result.results
      });
    }

    // ========================================================
    // Default
    // ========================================================

    return json({
      success: true,
      message: "Sijil API يعمل"
    });
  }
};

// ============================================================
// أدوات مساعدة
// ============================================================

function generateCode() {
  const buf = new Uint32Array(1);

  crypto.getRandomValues(buf);

  const n = buf[0] % 1000000;

  return String(n).padStart(6, "0");
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getToken(request) {
  const auth =
    request.headers.get("Authorization");

  if (
    auth &&
    auth.startsWith("Bearer ")
  ) {
    return auth.slice(7).trim();
  }

  return null;
}

// ============================================================
// التحقق من التوكن
// ============================================================

async function getAccess(env, token) {
  // ----------------------------------------------------------
  // Owner
  // ----------------------------------------------------------

  const owner = await env.DB
    .prepare(
      `SELECT
         users.id as user_id,
         users.email
       FROM sessions
       JOIN users
         ON users.id = sessions.user_id
       WHERE sessions.token = ?
         AND sessions.expires_at > CURRENT_TIMESTAMP`
    )
    .bind(token)
    .first();

  if (owner) {
    return {
      type: "owner",
      owner_user_id: owner.user_id,
      email: owner.email
    };
  }

  // ----------------------------------------------------------
  // Worker
  // ----------------------------------------------------------

  const worker = await env.DB
    .prepare(
      `SELECT
         worker_sessions.worker_id,
         worker_sessions.owner_user_id,
         workers.name
       FROM worker_sessions
       JOIN workers
         ON workers.id = worker_sessions.worker_id
       WHERE worker_sessions.token = ?
         AND worker_sessions.expires_at > CURRENT_TIMESTAMP
         AND workers.status = 'active'`
    )
    .bind(token)
    .first();

  if (worker) {
    return {
      type: "worker",
      owner_user_id: worker.owner_user_id,
      worker_id: worker.worker_id,
      worker_name: worker.name
    };
  }

  return null;
}

// ============================================================
// JSON Response
// ============================================================

function json(data, status = 200) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type": "application/json"
      }
    }
  );
}

// ============================================================
// إرسال رمز التحقق بواسطة Resend
// ============================================================

async function sendVerificationEmail(
  env,
  toEmail,
  fullName,
  code
) {
  if (!env.RESEND_API_KEY) {
    console.error(
      "RESEND_API_KEY غير موجود في Secrets"
    );

    return false;
  }

  try {
    const response = await fetch(
      "https://api.resend.com/emails",
      {
        method: "POST",

        headers: {
          "Authorization":
            `Bearer ${env.RESEND_API_KEY}`,

          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          from:
            `${FROM_NAME} <onboarding@resend.dev>`,

          to: [toEmail],

          subject:
            "رمز تفعيل حسابك في سجل",

          html: `
            <!DOCTYPE html>
            <html lang="ar" dir="rtl">

            <head>
              <meta charset="UTF-8">
              <meta name="viewport"
                content="width=device-width, initial-scale=1.0">
              <title>رمز تفعيل حسابك</title>
            </head>

            <body style="
              margin: 0;
              padding: 0;
              background: #f5f5f5;
              font-family: Arial, sans-serif;
              direction: rtl;
            ">

              <div style="
                max-width: 600px;
                margin: 40px auto;
                background: #ffffff;
                border-radius: 16px;
                padding: 30px;
                box-sizing: border-box;
              ">

                <h2 style="
                  margin-top: 0;
                  color: #222222;
                ">
                  مرحبًا ${escapeHtml(fullName || "")}
                </h2>

                <p style="
                  font-size: 16px;
                  color: #444444;
                  line-height: 1.8;
                ">
                  رمز تفعيل حسابك في تطبيق
                  <strong>سجل</strong> هو:
                </p>

                <div style="
                  margin: 25px 0;
                  padding: 20px;
                  background: #f1f1f1;
                  border-radius: 12px;
                  text-align: center;
                ">

                  <div style="
                    font-size: 32px;
                    font-weight: bold;
                    letter-spacing: 8px;
                    color: #111111;
                  ">
                    ${code}
                  </div>

                </div>

                <p style="
                  font-size: 15px;
                  color: #555555;
                  line-height: 1.8;
                ">
                  هذا الرمز صالح لمدة
                  <strong>${CODE_TTL_MINUTES} دقائق</strong>.
                </p>

                <p style="
                  font-size: 14px;
                  color: #888888;
                  line-height: 1.8;
                ">
                  إذا لم تطلب هذا الرمز،
                  يمكنك تجاهل هذه الرسالة.
                </p>

                <hr style="
                  border: 0;
                  border-top: 1px solid #eeeeee;
                  margin: 25px 0;
                ">

                <p style="
                  text-align: center;
                  font-size: 13px;
                  color: #999999;
                  margin-bottom: 0;
                ">
                  تطبيق سجل
                </p>

              </div>

            </body>

            </html>
          `,

          text:
            `مرحبًا ${fullName || ""}\n\n` +
            `رمز تفعيل حسابك في سجل هو: ${code}\n\n` +
            `الرمز صالح لمدة ${CODE_TTL_MINUTES} دقائق.\n\n` +
            `إذا لم تطلب هذا الرمز، تجاهل هذه الرسالة.`
        })
      }
    );

    const result =
      await response.json();

    if (!response.ok) {
      console.error(
        "RESEND ERROR:",
        response.status,
        result
      );

      return false;
    }

    console.log(
      "Verification email sent:",
      result
    );

    return true;

  } catch (err) {
    console.error(
      "RESEND REQUEST FAILED:",
      err
    );

    return false;
  }
}

// ============================================================
// حماية النص داخل HTML
// ============================================================

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
} 
