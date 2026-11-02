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
const UUID_PATTERN = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const HOTEL_ROOMS_PATH = new RegExp(`^/hotels/(${UUID_PATTERN})/rooms$`);
const RATE_CHECK_PATH = new RegExp(`^/carts/(${UUID_PATTERN})/rate-checks$`);
const BOOKING_PATH = new RegExp(`^/carts/(${UUID_PATTERN})/bookings$`);
const USER_CARDS_PATH = new RegExp(`^/users/(${UUID_PATTERN})/cards$`);
const CARD_ID_PATTERN = new RegExp(`^${UUID_PATTERN}$`);
const MAX_RATE_ID_LENGTH = 256;
const ISO_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
const MAX_ADULTS = 9;
const ROOMS_CURRENCY = "USD";

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

function nextOffset(nextUrl) {
  if (!nextUrl) return null;
  const offset = Number(new URL(nextUrl).searchParams.get("offset"));
  return Number.isInteger(offset) ? offset : null;
}

async function searchForaHotels(env, query, offset) {
  const { access_token } = await getForaToken(env);
  const params = new URLSearchParams({
    supplier_types: "hotel",
    search: query,
    limit: String(HOTEL_SEARCH_LIMIT),
    offset: String(offset)
  });
  const response = await fetch(`${env.FORA_API_BASE}/published/suppliers/?${params}`, {
    headers: { Authorization: `Bearer ${access_token}` }
  });
  if (!response.ok) {
    throw new Error(`Fora hotel search failed (${response.status}): ${await response.text()}`);
  }

  const { count, next, results } = await response.json();
  return { count, results, next_offset: nextOffset(next) };
}

async function fetchForaRooms(env, supplierId, { start, end, adults }) {
  const { access_token } = await getForaToken(env);
  const response = await fetch(`${env.FORA_API_BASE}/published/suppliers/${supplierId}/rates/`, {
    method: "POST",
    headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      start_date: start,
      end_date: end,
      number_of_adults: adults,
      currency: ROOMS_CURRENCY
    })
  });
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`Fora rooms request failed (${response.status}): ${await response.text()}`);
  }

  const { cart_id, rates } = await response.json();
  return { cart_id, rates };
}

async function checkForaRate(env, cartId, rateId) {
  const { access_token } = await getForaToken(env);
  const response = await fetch(`${env.FORA_API_BASE}/published/carts/${cartId}/rate-checks/`, {
    method: "POST",
    headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ rate_id: rateId })
  });
  if (response.status === 400 || response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`Fora rate check failed (${response.status}): ${await response.text()}`);
  }

  return response.json();
}

async function fetchForaCards(env, clientId) {
  const { access_token } = await getForaToken(env);
  const response = await fetch(`${env.FORA_API_BASE}/published/clients/${clientId}/cards/`, {
    headers: { Authorization: `Bearer ${access_token}` }
  });
  if (!response.ok) {
    throw new Error(`Fora cards request failed (${response.status}): ${await response.text()}`);
  }

  const { cards } = await response.json();
  return cards;
}

async function bookForaRoom(env, cartId, rateId, cardId, user) {
  const { access_token } = await getForaToken(env);
  const response = await fetch(`${env.FORA_API_BASE}/published/carts/${cartId}/bookings/`, {
    method: "POST",
    headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      rate_id: rateId,
      client_id: user.fora_client_id,
      client_card_id: cardId,
      confirmation_email: user.email
    })
  });
  if (!response.ok) {
    throw new Error(`Fora booking failed (${response.status}): ${await response.text()}`);
  }

  return response.json();
}

function parseStay(body) {
  const start = typeof body?.start === "string" ? body.start : "";
  const end = typeof body?.end === "string" ? body.end : "";
  const adults = Number(body?.adults);

  if (!ISO_DATE_PATTERN.test(start) || !ISO_DATE_PATTERN.test(end)) {
    return { error: "Choose your check-in and check-out dates." };
  }
  if (end <= start) return { error: "Check-out must be after check-in." };
  if (!Number.isInteger(adults) || adults < 1 || adults > MAX_ADULTS) {
    return { error: `Choose between 1 and ${MAX_ADULTS} guests.` };
  }

  return { stay: { start, end, adults } };
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
      const offset = Number(searchParams.get("offset") ?? 0);
      if (!Number.isInteger(offset) || offset < 0) return json({ error: "Invalid page." }, 400, env);

      try {
        return json(await searchForaHotels(env, query, offset), 200, env);
      } catch (err) {
        console.error(err);
        return json({ error: "Hotel search is unavailable right now." }, 502, env);
      }
    }

    const roomsMatch = pathname.match(HOTEL_ROOMS_PATH);
    if (request.method === "POST" && roomsMatch) {
      const { stay, error } = parseStay(await request.json().catch(() => null));
      if (error) return json({ error }, 400, env);

      try {
        const rooms = await fetchForaRooms(env, roomsMatch[1], stay);
        if (!rooms) return json({ error: "This hotel can't be booked online." }, 404, env);
        return json(rooms, 200, env);
      } catch (err) {
        console.error(err);
        return json({ error: "Rooms are unavailable right now." }, 502, env);
      }
    }

    const rateCheckMatch = pathname.match(RATE_CHECK_PATH);
    if (request.method === "POST" && rateCheckMatch) {
      const body = await request.json().catch(() => null);
      const rateId = typeof body?.rate_id === "string" ? body.rate_id : "";
      if (!rateId || rateId.length > MAX_RATE_ID_LENGTH) {
        return json({ error: "Choose a room." }, 400, env);
      }

      try {
        const rate = await checkForaRate(env, rateCheckMatch[1], rateId);
        if (!rate) return json({ error: "This room is no longer available." }, 404, env);
        return json(rate, 200, env);
      } catch (err) {
        console.error(err);
        return json({ error: "We couldn't confirm this room right now." }, 502, env);
      }
    }

    const userCardsMatch = pathname.match(USER_CARDS_PATH);
    if (request.method === "GET" && userCardsMatch) {
      const user = await env.USERS.get(`${USER_KEY_PREFIX}${userCardsMatch[1]}`, "json");
      if (!user?.fora_client_id) return json({ error: "Log in again to see your cards." }, 404, env);

      try {
        return json({ cards: await fetchForaCards(env, user.fora_client_id) }, 200, env);
      } catch (err) {
        console.error(err);
        return json({ error: "We couldn't load your saved cards." }, 502, env);
      }
    }

    const bookingMatch = pathname.match(BOOKING_PATH);
    if (request.method === "POST" && bookingMatch) {
      const body = await request.json().catch(() => null);
      const rateId = typeof body?.rate_id === "string" ? body.rate_id : "";
      const userId = typeof body?.user_id === "string" ? body.user_id : "";
      const cardId = typeof body?.card_id === "string" ? body.card_id : "";
      if (!rateId || rateId.length > MAX_RATE_ID_LENGTH || !userId) {
        return json({ error: "Choose a room and log in first." }, 400, env);
      }
      if (!CARD_ID_PATTERN.test(cardId)) return json({ error: "Choose a card." }, 400, env);
      const user = await env.USERS.get(`${USER_KEY_PREFIX}${userId}`, "json");
      if (!user?.fora_client_id) return json({ error: "Log in again to book." }, 400, env);

      try {
        return json(await bookForaRoom(env, bookingMatch[1], rateId, cardId, user), 201, env);
      } catch (err) {
        console.error(err);
        return json({ error: "We couldn't book this room. Please try again." }, 502, env);
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
