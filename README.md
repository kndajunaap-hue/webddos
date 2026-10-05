# Leo Security Workspace

## Supabase setup

1. Create a Supabase project.
2. Run [`supabase/schema.sql`](supabase/schema.sql) in the Supabase SQL Editor.
3. Add these environment variables to the deployment:
   - `SUPABASE_URL`
   - `SUPABASE_ANON_KEY`
   - `SUPABASE_SERVICE_ROLE_KEY` — server-only; never expose this value in browser code.
4. Set the Supabase Auth site URL and allowed redirect URLs to the deployed app URL. Enable GitHub as an Auth provider if GitHub sign-in is needed, and set GitHub's OAuth callback to the callback URL shown in Supabase Auth settings.
5. Set at least one AI provider secret (`CHUTES_KEY`, `OPENROUTER_KEY`, `GROQ_KEY_1`, or `LLM7_KEY`) on the server.
6. Set `OWNER_EMAIL` to the email address of the workspace administrator.

Registration and login use Supabase Auth. API keys and Script Hub records are stored in Postgres; API key values are shown only at creation and only their SHA-256 hashes are stored.

## LeoAI API

Create a key in **API Access** and keep it on your server. Requests to `/api/oracle` accept the OpenAI chat-completions message format:

```javascript
const response = await fetch('https://YOUR-DEPLOYMENT/api/oracle', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer YOUR_LEO_API_KEY'
  },
  body: JSON.stringify({
    model: 'leoai-free',
    messages: [{ role: 'user', content: 'Hello' }]
  })
});

const result = await response.json();
```

The `model` field is a compatibility label. The service chooses an available provider model and does not expose its internal model name in this response.
