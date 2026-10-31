const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_PATTERN = /^\+?[0-9 ()-]{7,20}$/;
const MAX_NAME_LENGTH = 128;
const USER_KEY_PREFIX = "user:";

function corsHeaders(env) {
  return {
    "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    Vary: "Origin"
  };
}

function json(body, status, env) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(env) }
  });
}

function parseSignup(body) {
  const field = name => (typeof body?.[name] === "string" ? body[name].trim() : "");
  const firstName = field("first_name");
  const lastName = field("last_name");
  const email = field("email");
  const phone = field("phone");

  if (!firstName || !lastName) return { error: "First and last name are required." };
  if (firstName.length > MAX_NAME_LENGTH || lastName.length > MAX_NAME_LENGTH) {
    return { error: "Name is too long." };
  }
  if (!email || !phone) return { error: "Email and phone number are required." };
  if (!EMAIL_PATTERN.test(email)) return { error: "Email looks invalid." };
  if (!PHONE_PATTERN.test(phone)) return { error: "Phone number looks invalid." };

  return { signup: { firstName, lastName, email, phone } };
}

async function createUser(env, { firstName, lastName, email, phone }) {
  const user = {
    id: crypto.randomUUID(),
    first_name: firstName,
    last_name: lastName,
    email,
    phone,
    fora_client_id: null
  };
  await env.USERS.put(`${USER_KEY_PREFIX}${user.id}`, JSON.stringify(user), {
    metadata: { first_name: firstName, last_name: lastName }
  });
  return user;
}

async function listUsers(env) {
  const { keys } = await env.USERS.list({ prefix: USER_KEY_PREFIX });
  return keys.map(({ name, metadata }) => ({
    id: name.slice(USER_KEY_PREFIX.length),
    first_name: metadata?.first_name ?? "",
    last_name: metadata?.last_name ?? ""
  }));
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }
    if (request.headers.get("Origin") !== env.ALLOWED_ORIGIN) {
      return json({ error: "Forbidden." }, 403, env);
    }

    if (request.method === "GET" && pathname === "/users") {
      return json({ users: await listUsers(env) }, 200, env);
    }

    if (request.method === "POST" && pathname === "/signup") {
      const { signup, error } = parseSignup(await request.json().catch(() => null));
      if (error) return json({ error }, 400, env);
      return json(await createUser(env, signup), 201, env);
    }

    return json({ error: "Not found." }, 404, env);
  }
};
