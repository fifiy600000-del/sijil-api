import bcrypt from "bcryptjs";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // REGISTER
    if (url.pathname === "/api/register") {
      if (request.method !== "POST")
        return json({ success: false, message: "استخدم POST" }, 405);

      const data = await request.json();
      const { username, password } = data;

      if (!username || !password)
        return json({ success: false, message: "username و password مطلوبان" }, 400);

      const exists = await env.DB
        .prepare("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .first();

      if (exists)
        return json({ success: false, message: "اسم المستخدم موجود مسبقًا" }, 409);

      const id = crypto.randomUUID();
      const password_hash = await bcrypt.hash(password, 10);

      await env.DB
        .prepare("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)")
        .bind(id, username, password_hash)
        .run();

      return json({
        success: true,
        message: "تم إنشاء الحساب",
        id,
        username
      });
    }

    // LOGIN
    if (url.pathname === "/api/login") {
      if (request.method !== "POST")
        return json({ success: false, message: "استخدم POST" }, 405);

      const data = await request.json();
      const { username, password } = data;

      if (!username || !password)
        return json({ success: false, message: "username و password مطلوبان" }, 400);

      const user = await env.DB
        .prepare("SELECT id, username, password_hash FROM users WHERE username = ?")
        .bind(username)
        .first();

      if (!user)
        return json({ success: false, message: "اسم المستخدم أو كلمة المرور غير صحيحة" }, 401);

      const valid = await bcrypt.compare(password, user.password_hash);

      if (!valid)
        return json({ success: false, message: "اسم المستخدم أو كلمة المرور غير صحيحة" }, 401);

      const token = crypto.randomUUID();

      const expiresAt = new Date(
        Date.now() + 30 * 24 * 60 * 60 * 1000
      ).toISOString();

      await env.DB
        .prepare(
          "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
        )
        .bind(token, user.id, expiresAt)
        .run();

      return json({
        success: true,
        message: "تم تسجيل الدخول",
        token,
        user: {
          id: user.id,
          username: user.username
        }
      });
    }

    // CREATE NOTEBOOK
    if (url.pathname === "/api/notebooks" && request.method === "POST") {
      const token = getToken(request);

      if (!token)
        return json({ success: false, message: "غير مسجل الدخول" }, 401);

      const user = await getUser(env, token);

      if (!user)
        return json({ success: false, message: "الجلسة غير صالحة أو منتهية" }, 401);

      const data = await request.json();
      const title = data.title || "سجل جديد";
      const id = crypto.randomUUID();

      await env.DB
        .prepare(
          "INSERT INTO notebooks (id, user_id, title) VALUES (?, ?, ?)"
        )
        .bind(id, user.id, title)
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

    // ADD ROW
    if (url.pathname === "/api/rows" && request.method === "POST") {
      const token = getToken(request);

      if (!token)
        return json({ success: false, message: "غير مسجل الدخول" }, 401);

      const user = await getUser(env, token);

      if (!user)
        return json({ success: false, message: "الجلسة غير صالحة أو منتهية" }, 401);

      const data = await request.json();
      const {
        notebook_id,
        name,
        amount = 0,
        quantity = 0,
        notes = ""
      } = data;

      if (!notebook_id)
        return json({ success: false, message: "notebook_id مطلوب" }, 400);

      const notebook = await env.DB
        .prepare(
          "SELECT id FROM notebooks WHERE id = ? AND user_id = ?"
        )
        .bind(notebook_id, user.id)
        .first();

      if (!notebook)
        return json({ success: false, message: "السجل غير موجود" }, 404);

      const positionResult = await env.DB
        .prepare(
          "SELECT COALESCE(MAX(position), -1) + 1 AS position FROM rows WHERE notebook_id = ?"
        )
        .bind(notebook_id)
        .first();

      const position = positionResult.position;
      const id = crypto.randomUUID();

      await env.DB
        .prepare(
          `INSERT INTO rows
          (id, notebook_id, position, name, amount, quantity, notes)
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

    // GET ROWS
    if (url.pathname === "/api/rows" && request.method === "GET") {
      const token = getToken(request);
      const notebookId = url.searchParams.get("notebook_id");

      if (!token)
        return json({ success: false, message: "غير مسجل الدخول" }, 401);

      const user = await getUser(env, token);

      if (!user)
        return json({ success: false, message: "الجلسة غير صالحة أو منتهية" }, 401);

      if (!notebookId)
        return json({ success: false, message: "notebook_id مطلوب" }, 400);

      const notebook = await env.DB
        .prepare(
          "SELECT id, title FROM notebooks WHERE id = ? AND user_id = ?"
        )
        .bind(notebookId, user.id)
        .first();

      if (!notebook)
        return json({ success: false, message: "السجل غير موجود" }, 404);

      const result = await env.DB
        .prepare(
          `SELECT id, notebook_id, position, name, amount, quantity, notes
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

    return json({
      success: true,
      message: "Sijil API يعمل"
    });
  }
};

function getToken(request) {
  const auth = request.headers.get("Authorization");

  if (auth && auth.startsWith("Bearer "))
    return auth.slice(7).trim();

  return null;
}

async function getUser(env, token) {
  return await env.DB
    .prepare(
      `SELECT users.id, users.username
       FROM sessions
       JOIN users ON users.id = sessions.user_id
       WHERE sessions.token = ?
       AND sessions.expires_at > CURRENT_TIMESTAMP`
    )
    .bind(token)
    .first();
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json"
    }
  });
}
