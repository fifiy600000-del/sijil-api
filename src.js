import bcrypt from "bcryptjs";
import { WorkerMailer } from "worker-mailer";

// ============ إعدادات عامة ============
const CODE_TTL_MINUTES = 10;      // مدة صلاحية الرمز
const RESEND_COOLDOWN_SECONDS = 60; // مهلة بين كل إعادة إرسال
const MAX_CODE_ATTEMPTS = 5;      // محاولات خاطئة قبل رفض الرمز

const FROM_NAME = "سجل";
// عنوان Gmail المرسل وكلمة المرور يُقرآن من env (أسرار Cloudflare)
// بدل كتابتهما هنا مباشرة - راجع تعليمات wrangler secret أسفل الملف

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ============ REGISTER ============
    if (url.pathname === "/api/register") {
      if (request.method !== "POST")
        return json({ success: false, message: "استخدم POST" }, 405);

      const data = await request.json();
      const { full_name, email, password } = data;

      if (!email || !password)
        return json({ success: false, message: "email و password مطلوبان" }, 400);

      if (!isValidEmail(email))
        return json({ success: false, message: "صيغة البريد الإلكتروني غير صحيحة" }, 400);

      const existing = await env.DB
        .prepare("SELECT id, verified FROM users WHERE email = ?")
        .bind(email)
        .first();

      if (existing && existing.verified)
        return json({ success: false, message: "البريد الإلكتروني مستخدم مسبقًا" }, 409);

      const password_hash = await bcrypt.hash(password, 10);
      const code = generateCode();
      const expiresAt = new Date(Date.now() + CODE_TTL_MINUTES * 60 * 1000).toISOString();
      const now = new Date().toISOString();

      if (existing) {
        // حساب موجود لكن غير مفعّل: نحدّثه برمز جديد بدل تكرار السجل
        await env.DB
          .prepare(
            `UPDATE users SET full_name = ?, password_hash = ?, verification_code = ?,
             code_expires_at = ?, code_attempts = 0, last_code_sent_at = ? WHERE email = ?`
          )
          .bind(full_name || "", password_hash, code, expiresAt, now, email)
          .run();
      } else {
        const id = crypto.randomUUID();
        await env.DB
          .prepare(
            `INSERT INTO users
             (id, full_name, email, password_hash, verified, verification_code, code_expires_at, last_code_sent_at)
             VALUES (?, ?, ?, ?, 0, ?, ?, ?)`
          )
          .bind(id, full_name || "", email, password_hash, code, expiresAt, now)
          .run();
      }

      await sendVerificationEmail(env, email, full_name, code);

      return json({
        success: true,
        message: "تم إنشاء الحساب، تحقق من بريدك الإلكتروني",
        email
      });
    }

    // ============ VERIFY EMAIL ============
    if (url.pathname === "/api/verify-email") {
      if (request.method !== "POST")
        return json({ success: false, message: "استخدم POST" }, 405);

      const data = await request.json();
      const { email, code } = data;

      if (!email || !code)
        return json({ success: false, message: "email و code مطلوبان" }, 400);

      const user = await env.DB
        .prepare(
          `SELECT id, verified, verification_code, code_expires_at, code_attempts
           FROM users WHERE email = ?`
        )
        .bind(email)
        .first();

      if (!user)
        return json({ success: false, message: "الحساب غير موجود" }, 404);

      if (user.verified)
        return json({ success: false, message: "الحساب مفعّل مسبقًا" }, 409);

      if (user.code_attempts >= MAX_CODE_ATTEMPTS)
        return json({ success: false, message: "محاولات كثيرة، اطلب رمزًا جديدًا" }, 429);

      if (!user.verification_code || new Date(user.code_expires_at) < new Date()) {
        return json({ success: false, message: "الرمز منتهي الصلاحية، اطلب رمزًا جديدًا" }, 410);
      }

      if (user.verification_code !== code) {
        await env.DB
          .prepare("UPDATE users SET code_attempts = code_attempts + 1 WHERE id = ?")
          .bind(user.id)
          .run();

        return json({ success: false, message: "الرمز غير صحيح" }, 401);
      }

      await env.DB
        .prepare(
          `UPDATE users SET verified = 1, verification_code = NULL,
           code_expires_at = NULL, code_attempts = 0 WHERE id = ?`
        )
        .bind(user.id)
        .run();

      const token = crypto.randomUUID();
      const sessionExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

      await env.DB
        .prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(token, user.id, sessionExpiresAt)
        .run();

      return json({
        success: true,
        message: "تم تفعيل الحساب",
        token
      });
    }

    // ============ RESEND CODE ============
    if (url.pathname === "/api/resend-code") {
      if (request.method !== "POST")
        return json({ success: false, message: "استخدم POST" }, 405);

      const data = await request.json();
      const { email } = data;

      if (!email)
        return json({ success: false, message: "email مطلوب" }, 400);

      const user = await env.DB
        .prepare("SELECT id, full_name, verified, last_code_sent_at FROM users WHERE email = ?")
        .bind(email)
        .first();

      if (!user)
        return json({ success: false, message: "الحساب غير موجود" }, 404);

      if (user.verified)
        return json({ success: false, message: "الحساب مفعّل مسبقًا" }, 409);

      if (user.last_code_sent_at) {
        const elapsed = (Date.now() - new Date(user.last_code_sent_at).getTime()) / 1000;
        if (elapsed < RESEND_COOLDOWN_SECONDS) {
          const wait = Math.ceil(RESEND_COOLDOWN_SECONDS - elapsed);
          return json({ success: false, message: `الرجاء الانتظار ${wait} ثانية قبل إعادة الإرسال` }, 429);
        }
      }

      const code = generateCode();
      const expiresAt = new Date(Date.now() + CODE_TTL_MINUTES * 60 * 1000).toISOString();
      const now = new Date().toISOString();

      await env.DB
        .prepare(
          `UPDATE users SET verification_code = ?, code_expires_at = ?,
           code_attempts = 0, last_code_sent_at = ? WHERE id = ?`
        )
        .bind(code, expiresAt, now, user.id)
        .run();

      await sendVerificationEmail(env, email, user.full_name, code);

      return json({ success: true, message: "تم إرسال رمز جديد إلى بريدك الإلكتروني" });
    }

    // ============ LOGIN ============
    if (url.pathname === "/api/login") {
      if (request.method !== "POST")
        return json({ success: false, message: "استخدم POST" }, 405);

      const data = await request.json();
      const { email, password } = data;

      if (!email || !password)
        return json({ success: false, message: "email و password مطلوبان" }, 400);

      const user = await env.DB
        .prepare("SELECT id, email, password_hash, verified FROM users WHERE email = ?")
        .bind(email)
        .first();

      if (!user)
        return json({ success: false, message: "البريد الإلكتروني أو كلمة المرور غير صحيحة" }, 401);

      const valid = await bcrypt.compare(password, user.password_hash);

      if (!valid)
        return json({ success: false, message: "البريد الإلكتروني أو كلمة المرور غير صحيحة" }, 401);

      if (!user.verified)
        return json({ success: false, message: "الحساب غير مفعّل، تحقق من بريدك الإلكتروني" }, 403);

      const token = crypto.randomUUID();
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

      await env.DB
        .prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(token, user.id, expiresAt)
        .run();

      return json({
        success: true,
        message: "تم تسجيل الدخول",
        token,
        user: { id: user.id, email: user.email }
      });
    }

    // ============ CREATE NOTEBOOK ============
    if (url.pathname === "/api/notebooks" && request.method === "POST") {
      const token = getToken(request);
      if (!token) return json({ success: false, message: "غير مسجل الدخول" }, 401);

      const user = await getUser(env, token);
      if (!user) return json({ success: false, message: "الجلسة غير صالحة أو منتهية" }, 401);

      const data = await request.json();
      const title = data.title || "سجل جديد";
      const id = crypto.randomUUID();

      await env.DB
        .prepare("INSERT INTO notebooks (id, user_id, title) VALUES (?, ?, ?)")
        .bind(id, user.id, title)
        .run();

      return json({ success: true, message: "تم إنشاء السجل", notebook: { id, title } });
    }

    // ============ ADD ROW ============
    if (url.pathname === "/api/rows" && request.method === "POST") {
      const token = getToken(request);
      if (!token) return json({ success: false, message: "غير مسجل الدخول" }, 401);

      const user = await getUser(env, token);
      if (!user) return json({ success: false, message: "الجلسة غير صالحة أو منتهية" }, 401);

      const data = await request.json();
      const { notebook_id, name, amount = 0, quantity = 0, notes = "" } = data;

      if (!notebook_id)
        return json({ success: false, message: "notebook_id مطلوب" }, 400);

      const notebook = await env.DB
        .prepare("SELECT id FROM notebooks WHERE id = ? AND user_id = ?")
        .bind(notebook_id, user.id)
        .first();

      if (!notebook)
        return json({ success: false, message: "السجل غير موجود" }, 404);

      const positionResult = await env.DB
        .prepare("SELECT COALESCE(MAX(position), -1) + 1 AS position FROM rows WHERE notebook_id = ?")
        .bind(notebook_id)
        .first();

      const position = positionResult.position;
      const id = crypto.randomUUID();

      await env.DB
        .prepare(
          `INSERT INTO rows (id, notebook_id, position, name, amount, quantity, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(id, notebook_id, position, name || "", Number(amount) || 0, Number(quantity) || 0, notes || "")
        .run();

      return json({
        success: true,
        message: "تمت إضافة الصف",
        row: { id, notebook_id, position, name: name || "", amount: Number(amount) || 0, quantity: Number(quantity) || 0, notes: notes || "" }
      });
    }

    // ============ GET ROWS ============
    if (url.pathname === "/api/rows" && request.method === "GET") {
      const token = getToken(request);
      const notebookId = url.searchParams.get("notebook_id");

      if (!token) return json({ success: false, message: "غير مسجل الدخول" }, 401);

      const user = await getUser(env, token);
      if (!user) return json({ success: false, message: "الجلسة غير صالحة أو منتهية" }, 401);

      if (!notebookId)
        return json({ success: false, message: "notebook_id مطلوب" }, 400);

      const notebook = await env.DB
        .prepare("SELECT id, title FROM notebooks WHERE id = ? AND user_id = ?")
        .bind(notebookId, user.id)
        .first();

      if (!notebook)
        return json({ success: false, message: "السجل غير موجود" }, 404);

      const result = await env.DB
        .prepare(
          `SELECT id, notebook_id, position, name, amount, quantity, notes
           FROM rows WHERE notebook_id = ? ORDER BY position ASC`
        )
        .bind(notebookId)
        .all();

      return json({ success: true, notebook, rows: result.results });
    }

    return json({ success: true, message: "Sijil API يعمل" });
  }
};

// ============ أدوات مساعدة ============

function generateCode() {
  // رقم عشوائي آمن من 6 أرقام (يشمل الأصفار في البداية)
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  const n = buf[0] % 1000000;
  return String(n).padStart(6, "0");
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getToken(request) {
  const auth = request.headers.get("Authorization");
  if (auth && auth.startsWith("Bearer ")) return auth.slice(7).trim();
  return null;
}

async function getUser(env, token) {
  return await env.DB
    .prepare(
      `SELECT users.id, users.email
       FROM sessions JOIN users ON users.id = sessions.user_id
       WHERE sessions.token = ? AND sessions.expires_at > CURRENT_TIMESTAMP`
    )
    .bind(token)
    .first();
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

// إرسال البريد عبر Gmail SMTP مباشرة من الـ Worker (worker-mailer يفتح
// اتصال TCP مباشرة لسيرفر Gmail — بدون أي خدمة إرسال بريد خارجية،
// فقط حساب Gmail عادي + كلمة مرور تطبيق App Password مجانية دائمًا)
async function sendVerificationEmail(env, toEmail, fullName, code) {
  if (!env.GMAIL_USER || !env.GMAIL_PASS) {
    console.error("GMAIL_USER / GMAIL_PASS غير مضبوطة في أسرار الـ Worker");
    return;
  }

  try {
    const mailer = await WorkerMailer.connect({
      host: "smtp.gmail.com",
      port: 465,
      secure: true, // implicit TLS، مطلوب مع بورت 465
      credentials: {
        username: env.GMAIL_USER,
        password: env.GMAIL_PASS
      },
      authType: "plain"
    });

    await mailer.send({
      from: { name: FROM_NAME, email: env.GMAIL_USER },
      to: toEmail,
      subject: "رمز تفعيل حسابك في سجل",
      text:
        `مرحبًا ${fullName || ""},\n\n` +
        `رمز تفعيل حسابك هو: ${code}\n` +
        `صالح لمدة ${CODE_TTL_MINUTES} دقائق.\n\n` +
        `إذا لم تطلب هذا الرمز، تجاهل هذه الرسالة.`
    });
  } catch (err) {
    // لا نُفشل عملية التسجيل بسبب خطأ إرسال، لكن يُسجَّل للمراجعة
    console.error("email send failed:", err);
  }
}
