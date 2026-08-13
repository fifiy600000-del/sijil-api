export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/register") {
      if (request.method !== "POST") {
        return new Response("POST only", { status: 405 });
      }

      const data = await request.json();

      const username = data.username;

      if (!username) {
        return new Response(
          JSON.stringify({ success: false, message: "username مطلوب" }),
          { headers: { "Content-Type": "application/json" } }
        );
      }

      const id = crypto.randomUUID();

      await env.DB.prepare(
        "INSERT INTO users (id, username) VALUES (?, ?)"
      ).bind(id, username).run();

      return new Response(
        JSON.stringify({
          success: true,
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
