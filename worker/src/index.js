import { SignJWT, importPKCS8 } from "jose";

const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_PATTERN = /^\+?[0-9 ()-]{7,20}$/;
const MAX_NAME_LENGTH = 128;

let cachedToken = null;

function corsHeaders(env) {
  return {
    "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
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

async function getForaToken(env) {
  if (cachedToken && cachedToken.expiresAt - 60_000 > Date.now()) {
    return cachedToken.value;
  }

  const tokenUrl = `${env.FORA_API_BASE}/oauth/token/`;
  const privateKey = await importPKCS8(env.FORA_PRIVATE_KEY, "ES256");
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: env.FORA_KID })
    .setIssuer(env.FORA_CLIENT_ID)
    .setSubject(env.FORA_CLIENT_ID)
    .setAudience(tokenUrl)
    .setIssuedAt()
    .setExpirationTime("60s")
    .setJti(crypto.randomUUID())
    .sign(privateKey);

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      scope: "clients:write",
      client_id: env.FORA_CLIENT_ID,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: assertion
    })
  });
  if (!response.ok) {
    throw new Error(`Fora token request failed (${response.status}): ${await response.text()}`);
  }

  const data = await response.json();
  cachedToken = { value: data.access_token, expiresAt: Date.now() + data.expires_in * 1000 };
  return cachedToken.value;
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
  if (!email && !phone) return { error: "An email or phone number is required to sign in." };
  if (email && !EMAIL_PATTERN.test(email)) return { error: "Email looks invalid." };
  if (phone && !PHONE_PATTERN.test(phone)) return { error: "Phone number looks invalid." };

  return { signup: { firstName, lastName, email, phone } };
}

async function createClient(env, { firstName, lastName, email, phone }) {
  const token = await getForaToken(env);
  const response = await fetch(`${env.FORA_API_BASE}/v2/clients/`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      first_name: firstName,
      last_name: lastName,
      type: "client",
      skip_dup_check: true,
      emails: email ? [{ email, email_type: "personal" }] : [],
      phone_numbers: phone ? [{ phone_number: phone, number_type: "mobile" }] : []
    })
  });
  if (!response.ok) {
    throw new Error(`Fora create client failed (${response.status}): ${await response.text()}`);
  }
  const created = await response.json();
  return { id: created.id, first_name: created.first_name };
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }
    if (request.method !== "POST" || pathname !== "/signup") {
      return json({ error: "Not found." }, 404, env);
    }
    if (request.headers.get("Origin") !== env.ALLOWED_ORIGIN) {
      return json({ error: "Forbidden." }, 403, env);
    }

    const { signup, error } = parseSignup(await request.json().catch(() => null));
    if (error) return json({ error }, 400, env);

    try {
      return json(await createClient(env, signup), 201, env);
    } catch (err) {
      console.error(err);
      return json({ error: "Could not submit right now. Please try again." }, 502, env);
    }
  }
};
