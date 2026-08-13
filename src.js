import bcrypt from "bcryptjs";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // REGISTER
    if (url.pathname === "/api/register") {
      if (request.method !== "POST") {
        return json({ success: false, message: "استخدم POST" }, 405);
      }

      const data = await request.json();
      const username = data.username;
      const password = data.password;

      if (!username || !password) {
        return json({
          success: false,
          message: "username و password مطلوبان"
        }, 400);
      }

      const exists = await env.DB
        .prepare("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .first();

      if (exists) {
        return json({
          success: false,
          message: "اسم المستخدم موجود مسبقًا"
        }, 409);
      }

      const id = crypto.randomUUID();
      const password_hash = await bcrypt.hash(password, 10);

      await env.DB
        .prepare(
          "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)"
        )
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
      if (request.method !== "POST") {
        return json({ success: false, message: "استخدم POST" }, 405);
      }

      const data = await request.json();
      const username = data.username;
      const password = data.password;

      if (!username || !password) {
        return json({
          success: false,
          message: "username و password مطلوبان"
        }, 400);
      }

      const user = await env.DB
        .prepare(
          "SELECT id, username, password_hash FROM users WHERE username = ?"
        )
        .bind(username)
        .first();

      if (!user) {
        return json({
          success: false,
          message: "اسم المستخدم أو كلمة المرور غير صحيحة"
        }, 401);
      }

      const valid = await bcrypt.compare(password, user.password_hash);

      if (!valid) {
        return json({
          success: false,
          message: "اسم المستخدم أو كلمة المرور غير صحيحة"
        }, 401);
      }

      const token = crypto.randomUUID();

      await env.DB
        .prepare(
          "INSERT INTO sessions (id, user_id) VALUES (?, ?)"
        )
        .bind(token, user.id)
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

    return json({
      success: true,
      message: "Sijil API يعمل"
    });
  }
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json"
    }
  });
}
