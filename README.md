# DeskPilot — Your AI Workplace Sidekick

I built DeskPilot because jumping between five different apps just to stay on top of a workday gets exhausting fast. It's an AI-powered assistant that handles the repetitive stuff — reminders, emails, quick summaries — so you can focus on work that actually matters. The backend runs on Django REST Framework, the frontend on React.js, and everything connects through a clean REST API.

---

## What It Can Do

### Talk to It Like a Person
The chat interface understands plain English. No commands to memorize — just say what you need, and DeskPilot figures out the intent and acts on it. Set a reminder, draft an email, summarize a thread — it handles it conversationally.

### Reminders That Actually Work
Say something like "Remind me to follow up with the client at 3 PM tomorrow" and DeskPilot takes care of it, including syncing to Google Calendar automatically. Getting the time parsing bulletproof took some effort, but it now reliably handles tricky cases like accidental past-date scheduling.

### Gmail Without Switching Tabs
Pull in recent emails, get a quick summary of what's waiting in your inbox, or send a reply — all from inside the assistant. Authentication uses Google OAuth2, so your credentials stay secure.

### Instant Summaries
Paste a long document, email thread, or meeting note and DeskPilot turns it into something actually readable. Powered by OpenAI's models — genuinely useful for staying on top of heavy inboxes.

### Secure by Design
Sessions use JWT tokens. Google integrations go through OAuth2. Nothing gets stored unnecessarily.

---

## Tech Stack

- Frontend: React.js
- Backend: Django REST Framework
- Database: PostgreSQL (production) / SQLite (local dev)
- Integrations: Google Calendar API, Gmail API, OpenAI GPT
- Auth: JWT + Google OAuth2

---

## Real Problems I Hit (and Fixed)

**Google OAuth kept rejecting connections** — Google flags OAuth over plain HTTP as insecure. Switched to HTTPS and that resolved it immediately.

**Reminders landing in the past** — the natural language parser was misreading certain relative time expressions. Built a custom parse_datetime_safely() function that validates the result before saving, ensuring reminders always land in the future.

**Permissions not sticking after login** — API calls were failing even after a successful OAuth handshake. Fixed by forcing re-verification with the correct permission scopes declared explicitly from the start.

---

## What's Next

- Smarter task automation workflows
- Multi-language support
- Better NLP for intent detection
- Integrations with tools like Slack and Notion
