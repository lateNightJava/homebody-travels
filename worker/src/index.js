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
const CART_PATH = new RegExp(`^/carts/(${UUID_PATTERN})$`);
const RATE_CHECK_PATH = new RegExp(`^/carts/(${UUID_PATTERN})/rate-checks$`);
const BOOKING_PATH = new RegExp(`^/carts/(${UUID_PATTERN})/bookings$`);
const CHECKOUT_PATH = new RegExp(`^/carts/(${UUID_PATTERN})/checkout$`);
const USER_CARDS_PATH = new RegExp(`^/users/(${UUID_PATTERN})/cards$`);
const USER_CARD_PATH = new RegExp(`^/users/(${UUID_PATTERN})/cards/(${UUID_PATTERN})$`);
const USER_BOOKINGS_PATH = new RegExp(`^/users/(${UUID_PATTERN})/bookings$`);
const BOOKING_STATUS_PATH = new RegExp(`^/bookings/(${UUID_PATTERN})/status$`);
const MAX_LISTED_BOOKINGS = 20;
const FORA_API_VERSION = "1";
const CARD_ID_PATTERN = new RegExp(`^${UUID_PATTERN}$`);
const MAX_RATE_ID_LENGTH = 256;
const MAX_LOYALTY_NUMBER_LENGTH = 50;
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

  const response = await fetch(`${env.FORA_API_BASE}/auth/app-token/`, {
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
  const response = await fetch(`${env.FORA_API_BASE}/contacts/`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${access_token}`,
      "Content-Type": "application/json",
      "Fora-Api-Version": "1"
    },
    body: JSON.stringify({
      first_name: firstName,
      last_name: lastName,
      emails: [{ address: email, type: "personal" }],
      phone_numbers: [{ number: phone, type: "mobile" }]
    })
  });
  if (!response.ok) {
    throw new Error(`Fora client create failed (${response.status}): ${await response.text()}`);
  }

  const client = await response.json();
  return client.id;
}

async function searchForaHotels(env, query, offset) {
  const { access_token } = await getForaToken(env);
  const params = new URLSearchParams({
    supplier_types: "hotel",
    search: query,
    limit: String(HOTEL_SEARCH_LIMIT),
    offset: String(offset)
  });
  const response = await fetch(`${env.FORA_API_BASE}/suppliers/?${params}`, {
    headers: { Authorization: `Bearer ${access_token}`, "Fora-Api-Version": FORA_API_VERSION }
  });
  if (!response.ok) {
    throw new Error(`Fora hotel search failed (${response.status}): ${await response.text()}`);
  }

  const { count, results } = await response.json();
  const seen = offset + results.length;
  return { count, results, next_offset: seen < count ? seen : null };
}

async function startForaCart(env, supplierId, { start, end, adults }) {
  const result = await sendForaJson(env, "POST", "/carts/", {
    supplier_id: supplierId,
    start_date: start,
    end_date: end,
    number_of_adults: adults,
    currency: ROOMS_CURRENCY
  });
  if (result.status === 403 || result.status === 404) return null;
  if (!result.ok) {
    throw new Error(`Fora cart start failed (${result.status}): ${JSON.stringify(result.data)}`);
  }

  return { cart_id: result.data.id, status: result.data.status, version: result.data.version };
}

async function fetchForaCart(env, cartId) {
  const result = await getForaJson(env, `/carts/${cartId}/`);
  if (result.status === 404) return null;
  if (!result.ok) {
    throw new Error(`Fora cart request failed (${result.status}): ${JSON.stringify(result.data)}`);
  }

  const { status, version, providers, programs } = result.data;
  const rates = programs.flatMap(program =>
    program.rates
      .filter(rate => rate.price)
      .map(rate => ({
        id: rate.id,
        program_id: program.id,
        program_name: program.name,
        member_rate_required: program.member_rate_required,
        room_description: rate.room,
        is_refundable: rate.cancellations.some(cancellation => cancellation.refundable),
        price: { total: rate.price.total ?? rate.price.nightly, currency: rate.price.currency }
      }))
  );
  return { status, version, providers, rates };
}

async function checkForaRate(env, cartId, rateId) {
  const result = await sendForaJson(env, "POST", `/carts/${cartId}/rate-checks/`, { rate_id: rateId });
  if ([400, 403, 404, 409].includes(result.status)) return null;
  if (!result.ok) {
    throw new Error(`Fora rate check failed (${result.status}): ${JSON.stringify(result.data)}`);
  }

  const rate = result.data;
  return {
    id: rate.id,
    room_description: rate.room,
    price: rate.price ? { total: rate.price.total ?? rate.price.nightly, currency: rate.price.currency } : null,
    is_refundable: rate.cancellations.some(cancellation => cancellation.refundable),
    cancellations: rate.cancellations,
    deposits: [],
    cart_version: rate.cart_version
  };
}

async function fetchForaCards(env, clientId) {
  const { access_token } = await getForaToken(env);
  const response = await fetch(`${env.FORA_API_BASE}/contacts/${clientId}/cards/`, {
    headers: { Authorization: `Bearer ${access_token}`, "Fora-Api-Version": FORA_API_VERSION }
  });
  if (!response.ok) {
    throw new Error(`Fora cards request failed (${response.status}): ${await response.text()}`);
  }

  const { cards } = await response.json();
  return cards;
}

async function getForaJson(env, path) {
  const { access_token } = await getForaToken(env);
  const response = await fetch(`${env.FORA_API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${access_token}`, "Fora-Api-Version": FORA_API_VERSION }
  });
  const data = await response.json().catch(() => ({}));
  return { status: response.status, ok: response.ok, data };
}

function postForaJson(env, path, body) {
  return sendForaJson(env, "POST", path, body);
}

async function sendForaJson(env, method, path, body) {
  const { access_token } = await getForaToken(env);
  const response = await fetch(`${env.FORA_API_BASE}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${access_token}`,
      "Content-Type": "application/json",
      "Fora-Api-Version": FORA_API_VERSION
    },
    body: JSON.stringify(body)
  });
  const data = await response.json().catch(() => ({}));
  return { status: response.status, ok: response.ok, data };
}

function startForaCard(env, clientId) {
  return postForaJson(env, `/contacts/${clientId}/cards/`, {
    origin: env.CARD_ORIGIN_OVERRIDE || env.ALLOWED_ORIGIN
  });
}

function saveForaCard(env, clientId, cardId, card) {
  const address = card?.billing_address ?? {};
  return postForaJson(env, `/contacts/${clientId}/cards/${cardId}/`, {
    number_token: card?.number_token,
    cvv_token: card?.cvv_token,
    first_six: card?.first_six,
    last_four: card?.last_four,
    card_type: card?.card_type,
    holder_name: card?.holder_name,
    expiry_month: card?.expiry_month,
    expiry_year: card?.expiry_year,
    billing_address: {
      line_1: address.line_1,
      ...(address.line_2 ? { line_2: address.line_2 } : {}),
      city: address.city,
      ...(address.state ? { state: address.state } : {}),
      postal_code: address.postal_code,
      country: address.country
    }
  });
}

function foraResult(result, env, failure) {
  if (result.ok) return json(result.data, result.status, env);
  console.error(`${failure} (${result.status}): ${JSON.stringify(result.data)}`);
  if (result.status >= 500) return json({ error: failure }, 502, env);
  return json({ error: failure, fora: result.data }, result.status, env);
}

function saveForaCheckout(env, cartId, { cardId, loyaltyNumber }, user) {
  return sendForaJson(env, "PATCH", `/carts/${cartId}/`, {
    contact_id: user.fora_client_id,
    card_id: cardId,
    email: user.email,
    ...(loyaltyNumber ? { loyalty_number: loyaltyNumber } : {})
  });
}

async function fetchForaBookingStatus(env, bookingId) {
  const result = await getForaJson(env, `/bookings/${bookingId}/status/`);
  if (!result.ok) {
    throw new Error(`Fora booking status failed (${result.status}): ${JSON.stringify(result.data)}`);
  }

  return result.data;
}

function bookingSummary(booking) {
  return {
    id: booking.id,
    hotel: booking.supplier?.name ?? "",
    arrival: booking.arrival,
    departure: booking.departure,
    status: booking.status ?? "Pending",
    confirmation_number: booking.confirmation_number ?? null
  };
}

async function rememberBooking(env, user, booking) {
  const bookings = [bookingSummary(booking), ...(user.bookings ?? [])];
  await env.USERS.put(`${USER_KEY_PREFIX}${user.id}`, JSON.stringify({ ...user, bookings }), {
    metadata: { first_name: user.first_name, last_name: user.last_name }
  });
}

async function refreshBooking(env, stored) {
  const { status, confirmation_number } = await fetchForaBookingStatus(env, stored.id);
  if (status === "Pending" || status === "Failed") return { ...stored, status, confirmation_number };

  const details = await getForaJson(env, `/bookings/${stored.id}/`);
  return details.ok ? bookingSummary(details.data) : { ...stored, status, confirmation_number };
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
        const cart = await startForaCart(env, roomsMatch[1], stay);
        if (!cart) return json({ error: "This hotel can't be booked online." }, 404, env);
        return json(cart, 202, env);
      } catch (err) {
        console.error(err);
        return json({ error: "Rooms are unavailable right now." }, 502, env);
      }
    }

    const cartMatch = pathname.match(CART_PATH);
    if (request.method === "GET" && cartMatch) {
      try {
        const cart = await fetchForaCart(env, cartMatch[1]);
        if (!cart) return json({ error: "This search has expired. Search again." }, 404, env);
        return json(cart, 200, env);
      } catch (err) {
        console.error(err);
        return json({ error: "Rooms are unavailable right now." }, 502, env);
      }
    }

    const rateCheckMatch = pathname.match(RATE_CHECK_PATH);
    if (request.method === "POST" && rateCheckMatch) {
      const body = await request.json().catch(() => null);
      const rateId = typeof body?.rate_id === "string" ? body.rate_id : "";
      if (!rateId || rateId.length > MAX_RATE_ID_LENGTH) return json({ error: "Choose a room." }, 400, env);

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

    if (request.method === "POST" && userCardsMatch) {
      const user = await env.USERS.get(`${USER_KEY_PREFIX}${userCardsMatch[1]}`, "json");
      if (!user?.fora_client_id) return json({ error: "Log in again to add a card." }, 404, env);

      try {
        return foraResult(await startForaCard(env, user.fora_client_id), env, "We couldn't start adding your card.");
      } catch (err) {
        console.error(err);
        return json({ error: "We couldn't start adding your card." }, 502, env);
      }
    }

    const userCardMatch = pathname.match(USER_CARD_PATH);
    if (request.method === "POST" && userCardMatch) {
      const user = await env.USERS.get(`${USER_KEY_PREFIX}${userCardMatch[1]}`, "json");
      if (!user?.fora_client_id) return json({ error: "Log in again to add a card." }, 404, env);
      const card = await request.json().catch(() => null);

      try {
        return foraResult(
          await saveForaCard(env, user.fora_client_id, userCardMatch[2], card),
          env,
          "We couldn't save your card."
        );
      } catch (err) {
        console.error(err);
        return json({ error: "We couldn't save your card." }, 502, env);
      }
    }

    const checkoutMatch = pathname.match(CHECKOUT_PATH);
    if (request.method === "POST" && checkoutMatch) {
      const body = await request.json().catch(() => null);
      const userId = typeof body?.user_id === "string" ? body.user_id : "";
      const cardId = typeof body?.card_id === "string" ? body.card_id : "";
      const loyaltyNumber = typeof body?.loyalty_number === "string" ? body.loyalty_number.trim() : "";
      if (!userId) return json({ error: "Log in first." }, 400, env);
      if (!CARD_ID_PATTERN.test(cardId)) return json({ error: "Choose a card." }, 400, env);
      if (loyaltyNumber.length > MAX_LOYALTY_NUMBER_LENGTH) {
        return json({ error: "Loyalty number is too long." }, 400, env);
      }
      const user = await env.USERS.get(`${USER_KEY_PREFIX}${userId}`, "json");
      if (!user?.fora_client_id) return json({ error: "Log in again to book." }, 400, env);

      try {
        return foraResult(
          await saveForaCheckout(env, checkoutMatch[1], { cardId, loyaltyNumber }, user),
          env,
          "We couldn't save your checkout details."
        );
      } catch (err) {
        console.error(err);
        return json({ error: "We couldn't save your checkout details." }, 502, env);
      }
    }

    const bookingMatch = pathname.match(BOOKING_PATH);
    if (request.method === "POST" && bookingMatch) {
      const body = await request.json().catch(() => null);
      const userId = typeof body?.user_id === "string" ? body.user_id : "";
      const version = Number(body?.version);
      if (!userId || !Number.isInteger(version) || version < 1) {
        return json({ error: "Choose a room and log in first." }, 400, env);
      }
      const user = await env.USERS.get(`${USER_KEY_PREFIX}${userId}`, "json");
      if (!user) return json({ error: "Log in again to book." }, 400, env);

      try {
        const result = await postForaJson(env, `/carts/${bookingMatch[1]}/bookings/`, { version });
        if (result.ok) await rememberBooking(env, user, result.data);
        return foraResult(result, env, "We couldn't book this room.");
      } catch (err) {
        console.error(err);
        return json({ error: "We couldn't book this room. Please try again." }, 502, env);
      }
    }

    const bookingStatusMatch = pathname.match(BOOKING_STATUS_PATH);
    if (request.method === "GET" && bookingStatusMatch) {
      try {
        return json(await fetchForaBookingStatus(env, bookingStatusMatch[1]), 200, env);
      } catch (err) {
        console.error(err);
        return json({ error: "We couldn't check this booking right now." }, 502, env);
      }
    }

    const userBookingsMatch = pathname.match(USER_BOOKINGS_PATH);
    if (request.method === "GET" && userBookingsMatch) {
      const user = await env.USERS.get(`${USER_KEY_PREFIX}${userBookingsMatch[1]}`, "json");
      if (!user) return json({ error: "Log in again to see your bookings." }, 404, env);
      const stored = (user.bookings ?? []).slice(0, MAX_LISTED_BOOKINGS);
      const bookings = await Promise.all(stored.map(booking => refreshBooking(env, booking).catch(() => booking)));
      return json({ bookings }, 200, env);
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
