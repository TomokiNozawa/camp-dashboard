// Camp Dashboard Auth Worker
// Slack OAuth v2 -> JWT + Firebase Custom Token
// Uses standard OAuth v2 flow (no OpenID Connect required)

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    try {
      if (url.pathname === "/auth/start") return handleAuthStart(url, env);
      if (url.pathname === "/auth/callback") return handleAuthCallback(url, request, env);
      if (url.pathname === "/slack/events" && request.method === "POST") return handleSlackEvent(request, env);
      if (url.pathname === "/health") return json({ status: "ok" });
      return new Response("Not Found", { status: 404 });
    } catch (e) {
      return json({ error: e.message }, 500);
    }
  },
};

function corsHeaders(env) {
  return {
    "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// Step 1: Redirect to Slack OAuth v2
// No user_scope needed - authed_user.id is always returned
function handleAuthStart(url, env) {
  const state = crypto.randomUUID();
  const params = new URLSearchParams({
    client_id: env.SLACK_CLIENT_ID,
    scope: "channels:read,groups:read,users:read",
    redirect_uri: `${url.origin}/auth/callback`,
    state,
  });

  return new Response(null, {
    status: 302,
    headers: {
      Location: `https://slack.com/oauth/v2/authorize?${params}`,
      "Set-Cookie": `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/`,
    },
  });
}

// Step 2: Exchange code, verify channel membership, issue JWT + Firebase token
async function handleAuthCallback(url, request, env) {
  const code = url.searchParams.get("code");
  const error = url.searchParams.get("error");

  if (error) {
    return redirectWithError(env, `Slack denied: ${error}`);
  }

  // Exchange code for token via oauth.v2.access
  const tokenRes = await fetch("https://slack.com/api/oauth.v2.access", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.SLACK_CLIENT_ID,
      client_secret: env.SLACK_CLIENT_SECRET,
      code,
      redirect_uri: `${url.origin}/auth/callback`,
    }),
  });
  const tokenData = await tokenRes.json();

  if (!tokenData.ok) {
    return redirectWithError(env, `Token exchange failed: ${tokenData.error}`);
  }

  // Get user ID from the authed_user
  const userId = tokenData.authed_user?.id;
  if (!userId) {
    return redirectWithError(env, "Failed to get user ID from Slack");
  }

  // Check channel membership using Bot Token
  const memberCheck = await isChannelMember(userId, env);
  if (!memberCheck.ok) {
    return redirectWithError(env, `Access denied (${memberCheck.error}). channel=${env.ALLOWED_CHANNEL_ID}, user=${userId}`);
  }

  try {
    // Get user profile via Bot Token
    const profileRes = await fetch(`https://slack.com/api/users.info?user=${userId}`, {
      headers: { Authorization: `Bearer ${env.SLACK_BOT_TOKEN}` },
    });
    const profileData = await profileRes.json();
    const profile = profileData.ok ? profileData.user : null;
    const displayName = profile?.real_name || profile?.name || "Unknown";
    const avatar = profile?.profile?.image_72 || "";

    // Create JWT (8 hour expiry)
    const jwt = await createJWT(
      { sub: userId, name: displayName, avatar, exp: Math.floor(Date.now() / 1000) + 2592000 },  // 30 days
      env.JWT_SECRET
    );

    // Create Firebase Custom Token
    const firebaseToken = await createFirebaseCustomToken(userId, env);

    // Redirect back to frontend with tokens in hash fragment
    const frontendUrl = env.FRONTEND_URL || "https://tomokinozawa.github.io/camp-dashboard";
    return new Response(null, {
      status: 302,
      headers: {
        Location: `${frontendUrl}#jwt=${jwt}&ft=${firebaseToken}&name=${encodeURIComponent(displayName)}&avatar=${encodeURIComponent(avatar)}`,
      },
    });
  } catch (e) {
    return redirectWithError(env, `Internal error: ${e.message}`);
  }
}

async function isChannelMember(userId, env) {
  let cursor = "";
  do {
    const params = new URLSearchParams({
      channel: env.ALLOWED_CHANNEL_ID,
      limit: "200",
    });
    if (cursor) params.set("cursor", cursor);

    const res = await fetch(`https://slack.com/api/conversations.members?${params}`, {
      headers: { Authorization: `Bearer ${env.SLACK_BOT_TOKEN}` },
    });
    const data = await res.json();
    if (!data.ok) return { ok: false, error: data.error };
    if (data.members.includes(userId)) return { ok: true };
    cursor = data.response_metadata?.next_cursor || "";
  } while (cursor);
  return { ok: false, error: "user_not_in_channel" };
}

// JWT creation using Web Crypto API (HS256)
async function createJWT(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const enc = new TextEncoder();
  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(signingInput));
  return `${signingInput}.${base64url(sig)}`;
}

// Firebase Custom Token (RS256, signed with service account key)
async function createFirebaseCustomToken(uid, env) {
  const serviceAccount = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT || "{}");
  if (!serviceAccount.private_key) return "";

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: serviceAccount.client_email,
    sub: serviceAccount.client_email,
    aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
    iat: now,
    exp: now + 3600,
    uid,
  };

  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  const pemContents = serviceAccount.private_key
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\n/g, "");
  const binaryKey = Uint8Array.from(atob(pemContents), (c) => c.charCodeAt(0));

  const key = await crypto.subtle.importKey(
    "pkcs8", binaryKey, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64url(sig)}`;
}

function base64url(input) {
  if (typeof input === "string") {
    // Handle UTF-8 strings (e.g. Japanese names)
    const bytes = new TextEncoder().encode(input);
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  const bytes = new Uint8Array(input);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ============ SLACK EVENT API ============
const REACTION_MAP = {
  clipboard: { target: 'tasks', label: 'task' },
  thinking_face: { target: 'planning_topics', label: 'topic' },
  warning: { target: 'risks_issues', label: 'risk' },
  white_check_mark: { target: 'decisions', label: 'decision' },
};

async function handleSlackEvent(request, env) {
  const body = await request.json();

  // Slack URL verification challenge
  if (body.type === 'url_verification') {
    return json({ challenge: body.challenge });
  }

  // Only process reaction_added events
  if (body.event?.type !== 'reaction_added') return json({ ok: true });

  const { reaction, user: reactUser, item } = body.event;
  const mapping = REACTION_MAP[reaction];
  if (!mapping) return json({ ok: true }); // Not a mapped reaction

  // Only process messages in the allowed channel
  if (item.type !== 'message') return json({ ok: true });
  const channel = item.channel;

  try {
    // Get the original message text
    const msgRes = await fetch(`https://slack.com/api/conversations.history?channel=${channel}&latest=${item.ts}&limit=1&inclusive=true`, {
      headers: { Authorization: `Bearer ${env.SLACK_BOT_TOKEN}` },
    });
    const msgData = await msgRes.json();
    const message = msgData.ok ? msgData.messages?.[0] : null;
    if (!message) return json({ ok: true });

    const msgText = message.text || '';
    const title = msgText.substring(0, 80).replace(/\n/g, ' ');

    // Get message author name
    const authorRes = await fetch(`https://slack.com/api/users.info?user=${message.user}`, {
      headers: { Authorization: `Bearer ${env.SLACK_BOT_TOKEN}` },
    });
    const authorData = await authorRes.json();
    const authorName = authorData.ok ? (authorData.user?.real_name || authorData.user?.name || 'Unknown') : 'Unknown';

    // Build the Slack message permalink
    const slackLink = `https://slack.com/archives/${channel}/p${item.ts.replace('.', '')}`;
    const now = new Date().toISOString().split('T')[0];

    // Write to Firebase
    const dbUrl = env.FIREBASE_DB_URL || 'https://camp-dashborad-default-rtdb.asia-southeast1.firebasedatabase.app';
    let fbPath, fbData;

    if (mapping.target === 'tasks') {
      fbPath = 'tasks';
      fbData = {
        title,
        description: `Slack: ${authorName} (${now})\n${msgText.substring(0, 500)}`,
        status: 'todo',
        priority: 'medium',
        assignee_id: null,
        due_date: null,
        source: 'slack',
        slack_link: slackLink,
        created_by: reactUser,
        created_at: { '.sv': 'timestamp' },
        updated_at: { '.sv': 'timestamp' },
        order: Date.now(),
      };
    } else if (mapping.target === 'planning_topics') {
      fbPath = 'planning_topics';
      fbData = {
        title,
        context: `Slack: ${authorName} (${now})\n${msgText.substring(0, 500)}`,
        category: '未分類',
        status: '未着手',
        priority: 'medium',
        assignee_id: null,
        due_date: null,
        decision_id: null,
        source: 'slack',
        slack_link: slackLink,
        created_by: reactUser,
        created_at: { '.sv': 'timestamp' },
        updated_at: { '.sv': 'timestamp' },
      };
    } else if (mapping.target === 'risks_issues') {
      fbPath = 'risks_issues';
      fbData = {
        title,
        type: 'issue',
        impact: 'medium',
        likelihood: null,
        status: '未対応',
        mitigation: '',
        assignee_id: null,
        due_date: null,
        related_area: '',
        source: 'slack',
        slack_link: slackLink,
        created_by: reactUser,
        created_at: { '.sv': 'timestamp' },
      };
    } else if (mapping.target === 'decisions') {
      fbPath = 'decisions';
      fbData = {
        title,
        content: msgText.substring(0, 1000),
        rationale: `Slack: ${authorName} (${now})`,
        decided_at: now,
        decided_by: reactUser,
        topic_id: null,
        impact_areas: '',
        status: '有効',
        source: 'slack',
        slack_link: slackLink,
        created_at: { '.sv': 'timestamp' },
      };
    }

    // Firebase REST API - push new entry
    const fbRes = await fetch(`${dbUrl}/${fbPath}.json`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(fbData),
    });
    const fbResult = await fbRes.json();

    // Reply in Slack thread
    const labels = { tasks: 'タスク', planning_topics: '検討事項', risks_issues: 'リスク/課題', decisions: '意思決定' };
    const replyText = `${labels[mapping.target]}に登録しました\nタイトル: ${title}\n→ <https://tomokinozawa.github.io/camp-dashboard/|Dashboard で確認>`;

    await fetch('https://slack.com/api/chat.postMessage', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.SLACK_BOT_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        channel,
        thread_ts: item.ts,
        text: replyText,
      }),
    });

    return json({ ok: true });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

function redirectWithError(env, message) {
  const frontendUrl = env.FRONTEND_URL || "https://tomokinozawa.github.io/camp-dashboard";
  return new Response(null, {
    status: 302,
    headers: {
      Location: `${frontendUrl}#error=${encodeURIComponent(message)}`,
    },
  });
}
