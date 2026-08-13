import bcrypt from "bcryptjs";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/register") {
      if (request.method !== "POST") {
        return new Response(
          JSON.stringify({
            success: false,
            message: "استخدم POST"
          }),
          {
            status: 405,
            headers: {
              "Content-Type": "application/json"
            }
          }
        );
      }

      const data = await request.json();

      const username = data.username;
      const password = data.password;

      if (!username || !password) {
        return new Response(
          JSON.stringify({
            success: false,
            message: "username و password مطلوبان"
          }),
          {
            status: 400,
            headers: {
              "Content-Type": "application/json"
            }
          }
        );
      }

      const exists = await env.DB
        .prepare("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .first();

      if (exists) {
        return new Response(
          JSON.stringify({
            success: false,
            message: "اسم المستخدم موجود مسبقًا"
          }),
          {
            status: 409,
            headers: {
              "Content-Type": "application/json"
            }
          }
        );
      }

      const id = crypto.randomUUID();

      const password_hash = await bcrypt.hash(password, 10);

      await env.DB
        .prepare(
          "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)"
        )
        .bind(id, username, password_hash)
        .run();

      return new Response(
        JSON.stringify({
          success: true,
          message: "تم إنشاء الحساب",
          id: id,
          username: username
        }),
        {
          headers: {
            "Content-Type": "application/json"
          }
        }
      );
    }

    return new Response(
      JSON.stringify({
        success: true,
        message: "Sijil API يعمل"
      }),
      {
        headers: {
          "Content-Type": "application/json"
        }
      }
    );
  }
};
