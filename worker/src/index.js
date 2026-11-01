import { SignJWT, importPKCS8 } from "jose";

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_PATTERN = /^\+?[0-9 ()-]{7,20}$/;
const MAX_NAME_LENGTH = 128;
const USER_KEY_PREFIX = "user:";

const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const ASSERTION_AUDIENCE = "fora:app-token";
const TOKEN_KEY = "fora:app_token";
const TOKEN_REFRESH_MARGIN_MS = 60_000;
const KV_MIN_TTL_SECONDS = 60;
const HOTEL_SEARCH_LIMIT = 24;
const MAX_SEARCH_LENGTH = 128;

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

async function requestForaToken(env) {
  const privateKey = await importPKCS8(env.FORA_PRIVATE_KEY, "ES256");
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: env.FORA_KID })
    .setIssuer(env.FORA_CLIENT_ID)
    .setSubject(env.FORA_CLIENT_ID)
    .setAudience(ASSERTION_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("60s")
    .setJti(crypto.randomUUID())
    .sign(privateKey);

  const response = await fetch(`${env.FORA_API_BASE}/v1/auth/app-token/`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: assertion
    })
  });
  if (!response.ok) {
    throw new Error(`Fora token request failed (${response.status}): ${await response.text()}`);
  }

  const data = await response.json();
  return { access_token: data.access_token, expires_at: Date.now() + data.expires_in * 1000 };
}

async function getForaToken(env) {
  const cached = await env.USERS.get(TOKEN_KEY, "json");
  if (cached && cached.expires_at - TOKEN_REFRESH_MARGIN_MS > Date.now()) {
    return { ...cached, from_cache: true };
  }

  const token = await requestForaToken(env);
  const secondsLeft = Math.floor((token.expires_at - Date.now()) / 1000);
  await env.USERS.put(TOKEN_KEY, JSON.stringify(token), {
    expirationTtl: Math.max(secondsLeft, KV_MIN_TTL_SECONDS)
  });
  return { ...token, from_cache: false };
}

async function createForaClient(env, { firstName, lastName, email, phone }) {
  const { access_token } = await getForaToken(env);
  const response = await fetch(`${env.FORA_API_BASE}/published/clients/`, {
    method: "POST",
    headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      first_name: firstName,
      last_name: lastName,
      emails: [{ email, email_type: "personal" }],
      phone_numbers: [{ phone_number: phone, number_type: "mobile" }]
    })
  });
  if (!response.ok) {
    throw new Error(`Fora client create failed (${response.status}): ${await response.text()}`);
  }

  const client = await response.json();
  return client.id;
}

async function searchForaHotels(env, query) {
  const { access_token } = await getForaToken(env);
  const params = new URLSearchParams({ supplier_types: "hotel", search: query, limit: String(HOTEL_SEARCH_LIMIT) });
  const response = await fetch(`${env.FORA_API_BASE}/published/suppliers/?${params}`, {
    headers: { Authorization: `Bearer ${access_token}` }
  });
  if (!response.ok) {
    throw new Error(`Fora hotel search failed (${response.status}): ${await response.text()}`);
  }

  const { count, results } = await response.json();
  return { count, results };
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

async function createUser(env, { firstName, lastName, email, phone }, foraClientId) {
  const user = {
    id: crypto.randomUUID(),
    first_name: firstName,
    last_name: lastName,
    email,
    phone,
    fora_client_id: foraClientId
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
    const { pathname, searchParams } = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }
    if (request.headers.get("Origin") !== env.ALLOWED_ORIGIN) {
      return json({ error: "Forbidden." }, 403, env);
    }

    if (request.method === "GET" && pathname === "/users") {
      return json({ users: await listUsers(env) }, 200, env);
    }

    if (request.method === "GET" && pathname === "/hotels") {
      const query = (searchParams.get("search") ?? "").trim();
      if (!query) return json({ error: "Enter a destination." }, 400, env);
      if (query.length > MAX_SEARCH_LENGTH) return json({ error: "Search is too long." }, 400, env);

      try {
        return json(await searchForaHotels(env, query), 200, env);
      } catch (err) {
        console.error(err);
        return json({ error: "Hotel search is unavailable right now." }, 502, env);
      }
    }

    if (request.method === "GET" && pathname === "/fora/token-status") {
      try {
        const token = await getForaToken(env);
        return json(
          { from_cache: token.from_cache, expires_at: new Date(token.expires_at).toISOString() },
          200,
          env
        );
      } catch (err) {
        console.error(err);
        return json({ error: "Could not get a Fora token." }, 502, env);
      }
    }

    if (request.method === "POST" && pathname === "/signup") {
      const { signup, error } = parseSignup(await request.json().catch(() => null));
      if (error) return json({ error }, 400, env);

      let foraClientId;
      try {
        foraClientId = await createForaClient(env, signup);
      } catch (err) {
        console.error(err);
        return json({ error: "Could not create your Fora profile." }, 502, env);
      }
      return json(await createUser(env, signup, foraClientId), 201, env);
    }

    return json({ error: "Not found." }, 404, env);
  }
};
