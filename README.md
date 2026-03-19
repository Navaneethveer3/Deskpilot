Deskpilot is an AI-powered workplace assistant built with Django (backend) and React (frontend) to streamline professional tasks and improve productivity. It integrates natural language understanding, calendar management, reminders, email processing, and intelligent chat into a single unified platform.



#### **Key Features**



**AI Chat Assistant**



* Interacts with users via natural language.
* Understands intent and outputs structured JSON for actions like reminders, emails, and summarizations.



**Reminders with Google Calendar Integration**



* Users can set reminders in natural language (e.g., “Remind me to call John at 6 PM today”).
* Reminders are stored in the database and automatically synced to the user’s Google Calendar via Google API.
* Time parsing logic ensures events are never scheduled in the past.



**Email Integration**



* Summarizes recent Gmail messages.
* Allows sending emails directly through the assistant.
* Uses secure OAuth2 authentication with stored Google credentials.



**Summarization**



* Summarizes long texts or emails concisely using OpenAI models.
* Provides quick overviews of complex information.
* Authentication \& User Management



**JWT-based authentication for secure user sessions.**



* Google OAuth2 integration for connecting Gmail and Calendar services.



**Frontend Dashboard**



* Built in React with professional UI.
* Features navigation bar, chat interface, reminders page, and calendar connection button.









#### Tech Stack



* **Frontend:** React.js
* **Backend:** Django REST Framework
* **Database:** PostgreSQL / SQLite
* **APIs \& Integrations:** Google Calendar API, Gmail API, OpenAI GPT API
* **Authentication:** JWT + Google OAuth2









##### Impact



Deskpilot reduces the overhead of managing workplace tasks by acting as a personal AI-powered secretary. It automates reminders, schedules meetings, summarizes long content, manages email, and responds to queries — all through a simple conversational interface.







###### What are the problems faced while building this project?



* **Integrating Google OAuth2 :** Google rejected due to insecure HTTP, fixed with adding HTTPS support.
* **Date and Time Parsing for Reminders :** sometimes system used wrong past dates, written a separate function named parse\_datetime\_safely() to handle the date and time for reminders safely.
* **Insufficient API Permissions :** there is shortage of permissions API even after login, to handle this I used re-verification method for the user.
