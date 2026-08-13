export default {
  async fetch(request, env) {
    const result = await env.DB
      .prepare("SELECT COUNT(*) AS count FROM users")
      .first();

    return new Response(
      JSON.stringify({
        success: true,
        users: result.count
      }),
      {
        headers: {
          "Content-Type": "application/json"
        }
      }
    );
  }
};
