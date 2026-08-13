export default {
  async fetch(request, env) {
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
