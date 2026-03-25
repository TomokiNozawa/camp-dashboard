// Camp Dashboard Auth Worker
// Slack OAuth v2 -> JWT + Firebase Custom Token
// Uses standard OAuth v2 flow (no OpenID Connect required)

// Dedup: track processed event IDs to prevent Slack retry duplicates
const processedEvents = new Set();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    try {
      if (url.pathname === "/auth/start") return handleAuthStart(url, env);
      if (url.pathname === "/auth/callback") return handleAuthCallback(url, request, env);
      if (url.pathname === "/slack/events" && request.method === "POST") {
        // Parse body once, return 200 immediately, process in background
        const body = await request.json();
        if (body.type === 'url_verification') return json({ challenge: body.challenge });

        // Dedup using event_id (Slack sends same event_id on retries)
        const eventId = body.event_id || '';
        if (processedEvents.has(eventId)) return json({ ok: true });
        processedEvents.add(eventId);
        // Clean old entries to prevent memory growth
        if (processedEvents.size > 100) {
          const first = processedEvents.values().next().value;
          processedEvents.delete(first);
        }

        // Return 200 immediately, process in background via waitUntil
        ctx.waitUntil(processSlackEvent(body, env));
        return json({ ok: true });
      }
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

async function processSlackEvent(body, env) {
  // Only process reaction_added events
  if (body.event?.type !== 'reaction_added') return;

  const { reaction, user: reactUser, item } = body.event;

  // Ignore reactions from bots (prevents infinite loop)
  // Check 1: authorizations-based check
  if (reactUser === body.authorizations?.[0]?.user_id) return;
  // Check 2: call auth.test to get our own bot user ID
  try {
    const authTest = await fetch('https://slack.com/api/auth.test', {
      headers: { Authorization: `Bearer ${env.SLACK_BOT_TOKEN}` },
    });
    const authData = await authTest.json();
    if (authData.ok && reactUser === authData.user_id) return;
  } catch (e) { /* continue */ }

  const mapping = REACTION_MAP[reaction];
  if (!mapping) return; // Not a mapped reaction

  // Only process messages in the allowed channel
  if (item.type !== 'message') return;
  const channel = item.channel;

  try {
    // Get the original message text
    const msgRes = await fetch(`https://slack.com/api/conversations.history?channel=${channel}&latest=${item.ts}&limit=1&inclusive=true`, {
      headers: { Authorization: `Bearer ${env.SLACK_BOT_TOKEN}` },
    });
    const msgData = await msgRes.json();
    const message = msgData.ok ? msgData.messages?.[0] : null;
    if (!message) return;

    const msgText = message.text || '';

    // Resolve @mentions to user names and IDs
    const mentionMap = {};
    const mentionRegex = /<@(U[A-Z0-9]+)>/g;
    let match;
    while ((match = mentionRegex.exec(msgText)) !== null) {
      const uid = match[1];
      if (!mentionMap[uid]) {
        const uRes = await fetch(`https://slack.com/api/users.info?user=${uid}`, {
          headers: { Authorization: `Bearer ${env.SLACK_BOT_TOKEN}` },
        });
        const uData = await uRes.json();
        mentionMap[uid] = uData.ok ? (uData.user?.real_name || uData.user?.name || uid) : uid;
      }
    }
    // Replace <@UXXXX> with real names for AI input
    let readableText = msgText;
    for (const [uid, name] of Object.entries(mentionMap)) {
      readableText = readableText.replace(new RegExp(`<@${uid}>`, 'g'), name);
    }

    // Get message author name
    const authorRes = await fetch(`https://slack.com/api/users.info?user=${message.user}`, {
      headers: { Authorization: `Bearer ${env.SLACK_BOT_TOKEN}` },
    });
    const authorData = await authorRes.json();
    const authorName = authorData.ok ? (authorData.user?.real_name || authorData.user?.name || 'Unknown') : 'Unknown';

    // Get all workspace members for assignee matching
    const membersRes = await fetch(`https://slack.com/api/conversations.members?channel=${env.ALLOWED_CHANNEL_ID}&limit=200`, {
      headers: { Authorization: `Bearer ${env.SLACK_BOT_TOKEN}` },
    });
    const membersData = await membersRes.json();
    const memberIds = membersData.ok ? membersData.members : [];
    const memberNames = {};
    for (const uid of memberIds) {
      if (mentionMap[uid]) { memberNames[uid] = mentionMap[uid]; continue; }
      const r = await fetch(`https://slack.com/api/users.info?user=${uid}`, {
        headers: { Authorization: `Bearer ${env.SLACK_BOT_TOKEN}` },
      });
      const d = await r.json();
      if (d.ok && !d.user?.is_bot) memberNames[uid] = d.user?.real_name || d.user?.name || uid;
    }
    const memberList = Object.entries(memberNames).map(([uid, name]) => `${name} (${uid})`).join(', ');

    // AI analysis via OpenAI
    const today = new Date().toISOString().split('T')[0];
    const typeLabel = { tasks: 'task', planning_topics: 'planning topic', risks_issues: 'risk/issue', decisions: 'decision' }[mapping.target];
    const aiPrompt = `You are analyzing a Slack message to register it as a ${typeLabel} in a project dashboard for "Claude Cowork Camp" (a training program).

Message author: ${authorName}
Message: ${readableText}
Today: ${today}
Channel members: ${memberList}

Respond in JSON only (no markdown, no explanation):
{
  "title": "concise title in Japanese (max 60 chars)",
  "summary": "brief summary of the request/content in Japanese (2-3 sentences)",
  "assignee_id": "Slack user ID of the most appropriate assignee from the member list, or null if unclear",
  "due_date": "YYYY-MM-DD if mentioned or reasonably inferred (within 1-2 weeks for urgent, 1 month for normal), or null",
  "priority": "high/medium/low based on urgency",
  "category": "for planning topics only: one of 対象者定義/ゴール設計/差別化/業務適用/形式・構成/カリキュラム/運営, otherwise null"
}`;

    let aiResult = { title: readableText.substring(0, 60).replace(/\n/g, ' '), summary: readableText.substring(0, 300), assignee_id: null, due_date: null, priority: 'medium', category: null };

    if (env.OPENAI_API_KEY) {
      try {
        const aiRes = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${env.OPENAI_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'gpt-4o-mini',
            messages: [{ role: 'user', content: aiPrompt }],
            temperature: 0.3,
            max_tokens: 300,
          }),
        });
        const aiData = await aiRes.json();
        const content = aiData.choices?.[0]?.message?.content || '';
        const parsed = JSON.parse(content.replace(/```json?\n?/g, '').replace(/```/g, '').trim());
        aiResult = { ...aiResult, ...parsed };
      } catch (e) { /* fallback to defaults */ }
    }

    // Get proper Slack permalink via API
    let slackLink = '';
    try {
      const plRes = await fetch(`https://slack.com/api/chat.getPermalink?channel=${channel}&message_ts=${item.ts}`, {
        headers: { Authorization: `Bearer ${env.SLACK_BOT_TOKEN}` },
      });
      const plData = await plRes.json();
      slackLink = plData.ok ? plData.permalink : '';
    } catch (e) { /* fallback to empty */ }
    const now = new Date().toISOString().split('T')[0];

    // Write to Firebase
    const dbUrl = env.FIREBASE_DB_URL || 'https://camp-dashborad-default-rtdb.asia-southeast1.firebasedatabase.app';
    let fbPath, fbData;

    if (mapping.target === 'tasks') {
      fbPath = 'tasks';
      fbData = {
        title: aiResult.title,
        description: aiResult.summary + '\n\n---\nSlack: ' + authorName + ' (' + now + ')',
        status: 'todo',
        priority: aiResult.priority || 'medium',
        assignee_id: aiResult.assignee_id,
        due_date: aiResult.due_date,
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
        title: aiResult.title,
        context: aiResult.summary + '\n\n---\nSlack: ' + authorName + ' (' + now + ')',
        category: aiResult.category || '\u672a\u5206\u985e',
        status: '\u672a\u7740\u624b',
        priority: aiResult.priority || 'medium',
        assignee_id: aiResult.assignee_id,
        due_date: aiResult.due_date,
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
        title: aiResult.title,
        type: 'issue',
        impact: aiResult.priority === 'high' ? 'high' : aiResult.priority === 'low' ? 'low' : 'medium',
        likelihood: null,
        status: '\u672a\u5bfe\u5fdc',
        mitigation: '',
        assignee_id: aiResult.assignee_id,
        due_date: aiResult.due_date,
        related_area: aiResult.category || '',
        source: 'slack',
        slack_link: slackLink,
        created_by: reactUser,
        created_at: { '.sv': 'timestamp' },
      };
    } else if (mapping.target === 'decisions') {
      fbPath = 'decisions';
      fbData = {
        title: aiResult.title,
        content: aiResult.summary,
        rationale: 'Slack: ' + authorName + ' (' + now + ')\n' + readableText.substring(0, 500),
        decided_at: now,
        decided_by: message.user,
        topic_id: null,
        impact_areas: aiResult.category || '',
        status: '\u6709\u52b9',
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

    // Add confirmation reaction
    await fetch('https://slack.com/api/reactions.add', {
      method: 'POST',
      headers: { Authorization: `Bearer ${env.SLACK_BOT_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ channel, timestamp: item.ts, name: 'ballot_box_with_check' }),
    });

    // Reply in Slack thread
    const labels = { tasks: '\u30bf\u30b9\u30af', planning_topics: '\u691c\u8a0e\u4e8b\u9805', risks_issues: '\u30ea\u30b9\u30af/\u8ab2\u984c', decisions: '\u610f\u601d\u6c7a\u5b9a' };
    const assigneeName = aiResult.assignee_id && memberNames[aiResult.assignee_id] ? memberNames[aiResult.assignee_id] : '\u672a\u5272\u308a\u5f53\u3066';
    const dueDateText = aiResult.due_date || '\u672a\u8a2d\u5b9a';
    const replyText = labels[mapping.target] + '\u306b\u767b\u9332\u3057\u307e\u3057\u305f\n\u30bf\u30a4\u30c8\u30eb: ' + aiResult.title + '\n\u62c5\u5f53: ' + assigneeName + '\n\u671f\u65e5: ' + dueDateText + '\n\u2192 <https://tomokinozawa.github.io/camp-dashboard/|Dashboard>';

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

    return;
  } catch (e) {
    // Background task, no response needed
    return;
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
