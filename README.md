# 🚀 DeskPilot - AI Powered Workplace Assistant

**DeskPilot** is an AI-powered workplace assistant designed to streamline daily professional tasks and enhance productivity. Built using **Django REST Framework (backend)** and **React.js (frontend)**, it combines intelligent chat, task automation, and third-party integrations into a unified platform.

---

## ✨ Key Features

### 🤖 AI Chat Assistant

* Interacts with users using natural language
* Detects intent and converts it into structured actions (reminders, emails, summaries)
* Provides a seamless conversational experience

---

### ⏰ Smart Reminders with Google Calendar Integration

* Create reminders using natural language (e.g., *“Remind me to call John at 6 PM”*)
* Automatically syncs events with Google Calendar via API
* Prevents scheduling in the past using robust time parsing logic

---

### 📧 Email Integration

* Summarizes recent Gmail messages
* Allows sending emails directly through the assistant
* Secure authentication using Google OAuth2

---

### 📝 AI-Powered Summarization

* Generates concise summaries for long texts and emails
* Helps users quickly understand complex information
* Powered by advanced OpenAI models

---

### 🔐 Authentication & User Management

* JWT-based authentication for secure sessions
* Google OAuth2 integration for Gmail & Calendar access

---

### 🖥️ Frontend Dashboard

* Built with React.js for a modern and responsive UI
* Includes:

  * Chat interface
  * Reminders page
  * Calendar connection module
  * Navigation dashboard

---

## 🛠️ Tech Stack

### Frontend

* React.js

### Backend

* Django REST Framework

### Database

* PostgreSQL / SQLite

### APIs & Integrations

* Google Calendar API
* Gmail API
* OpenAI GPT API

### Authentication

* JWT + Google OAuth2

---

## 🚀 Impact

DeskPilot acts as a **personal AI-powered workplace assistant**, helping users:

* Automate reminders and scheduling
* Manage emails efficiently
* Summarize lengthy content instantly
* Interact with systems using natural language

It significantly reduces manual effort and improves productivity by centralizing essential workplace tools into one platform.

---

## ⚡ Challenges Faced

* **Google OAuth2 Integration**

  * Faced rejection due to insecure HTTP
  * Resolved by enabling HTTPS for secure authentication

* **Date & Time Parsing for Reminders**

  * Incorrect past date scheduling issues
  * Implemented a custom `parse_datetime_safely()` function to ensure accurate future scheduling

* **API Permission Issues**

  * Encountered insufficient permissions even after authentication
  * Solved using user re-verification and proper scope handling

---

## 📌 Future Enhancements

* Advanced task automation workflows
* Multi-language support
* Improved NLP intent detection
* Integration with additional workplace tools (Slack, Notion, etc.)

---
