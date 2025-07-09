import os
import openai
import json
import re
import base64
from datetime import datetime, timedelta, time
from django.utils import timezone
from django.conf import settings
from django.utils.timezone import make_aware, is_aware, get_current_timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from dateutil.parser import parse as dateutil_parse
from email.mime.text import MIMEText
from django.contrib.auth import get_user_model
from deskpilot.models import Reminder, GoogleCredentials
import jwt
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.authentication import JWTAuthentication
# Google API imports
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required
from google_auth_oauthlib.flow import Flow
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


CLIENT_SECRETS_FILE = os.path.join(settings.BASE_DIR, 'credentials', 'credentials.json')
SCOPES = [
            'https://www.googleapis.com/auth/calendar',
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.send',
            'openid',
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email',
]
REDIRECT_URI = 'http://localhost:8000/app/google/callback/'



@login_required
def google_login(request):
    token = request.GET.get('token')  # frontend sends `?token=<JWT>` in URL
    if not token:
        return HttpResponse("Missing JWT token", status=400)
    
    request.session['jwt_token'] = token  # save for callback use

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    request.session['oauth_state'] = state
    return redirect(authorization_url)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def google_status(request):
    from deskpilot.models import GoogleCredentials

    connected = GoogleCredentials.objects.filter(user=request.user).exists()
    return Response({"connected": connected})


@login_required
def google_callback(request):
    print("🔁 Callback triggered!")
    state = request.session.get('oauth_state')
    jwt_token = request.session.get('jwt_token')

    if not jwt_token:
        return HttpResponse("JWT token missing from session", status=400)

    try:
        # Decode JWT token manually to get user
        UntypedToken(jwt_token)  # validate
        decoded = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = decoded.get("user_id")
        User = get_user_model()
        user = User.objects.get(id=user_id)

        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=state,
            redirect_uri=REDIRECT_URI
        )
        flow.fetch_token(authorization_response=request.build_absolute_uri())
        credentials = flow.credentials

        obj, created = GoogleCredentials.objects.update_or_create(
            user=user,
            defaults={
                'token': credentials.token,
                'refresh_token': credentials.refresh_token,
                'token_uri': credentials.token_uri,
                'client_id': credentials.client_id,
                'client_secret': credentials.client_secret,
                'scopes': ' '.join(credentials.scopes)
            }
        )

        print(f"✅ GoogleCredentials saved for (id={user.id}), created={created}")
        return redirect('http://localhost:3000/dashboard')

    except User.DoesNotExist:
        return HttpResponse("User not found", status=404)
    except Exception as e:
        print(f"❌ Error in google_callback: {e}")
        return HttpResponse(f"Google OAuth error: {e}", status=500)





openai.api_key = settings.OPENAI_API_KEY


class MissingGoogleCredentials(Exception):
    pass


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def chat_with_assistant(request):
    print(f"API called by user: (id={request.user.id})")
    user_message = request.data.get("message")
    if not user_message:
        return Response({"error": "No message provided"}, status=400)

    user = request.user

    try:
        system_prompt = (
            "You are a helpful workplace assistant.\n"
            "Detect what the user wants and respond ONLY with structured JSON.\n\n"
            "If it's a reminder:\n"
    '{"action": "reminder", "title": "...", "description": "...", '
    '"time": "ISO 8601 format like 2025-06-01T15:30"}\n'
            "If it's a text summarization:\n"
            '{"action": "summarize", "text": "..."}\n'
            "If the user wants to summarize emails:\n"
            '{"action": "summarize_emails"}\n'
            "If the user wants to send an email:\n"
            '{"action": "send_email", "to": "...", "subject": "...", "body": "..."}\n'
            "Otherwise:\n"
            '{"action": "chat"}'
        )

        response = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
        )

        gpt_reply = response.choices[0].message.content
        try:
            parsed = json.loads(gpt_reply)
        except json.JSONDecodeError:
            parsed = {"action": "chat"}

        # === Reminder Handling ===
        if parsed.get("action") == "reminder":
            title = parsed.get("title", "Reminder")
            description = parsed.get("description", "")
            time_str = parsed.get("time")

            try:
                reminder_time = parse_datetime_safely(time_str)
            except ValueError:
                return Response({"error": "Invalid datetime format"}, status=400)

            Reminder.objects.create(
                user=user,
                title=title,
                description=description,
                remind_at=reminder_time,
            )

            try:
                user_obj = get_exact_user(user)
                user_creds = GoogleCredentials.objects.get(user=user_obj)

                creds = Credentials(
                    token=user_creds.token,
                    refresh_token=user_creds.refresh_token,
                    token_uri=user_creds.token_uri,
                    client_id=user_creds.client_id,
                    client_secret=user_creds.client_secret,
                    scopes=user_creds.scopes.split()
                )

                if creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                    user_creds.token = creds.token
                    user_creds.save()

                service = build('calendar', 'v3', credentials=creds)

                event = {
                    'summary': title,
                    'description': description,
                    'start': {
                        'dateTime': reminder_time.isoformat(),
                        'timeZone': 'Asia/Kolkata',
                    },
                    'end': {
                        'dateTime': (reminder_time + timedelta(minutes=30)).isoformat(),
                        'timeZone': 'Asia/Kolkata',
                    },
                }

                service.events().insert(calendarId='primary', body=event).execute()

            except GoogleCredentials.DoesNotExist:
                print("Google Calendar not connected for this user.")
            except Exception as e:
                print(f"Google Calendar error: {e}")

            return Response({
                "reply": f"✅ Reminder set for {reminder_time.strftime('%Y-%m-%d %I:%M %p')}: {title}"
            })

        # === Summarization ===
        elif parsed.get("action") == "summarize":
            text = parsed.get("text")
            if not text:
                return Response({"error": "No text provided for summarization."}, status=400)

            summary_response = openai.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "Summarize the following text clearly and concisely."},
                    {"role": "user", "content": text}
                ],
            )
            summary = summary_response.choices[0].message.content
            return Response({"reply": summary})

        # === Summarize Gmail Emails ===
        elif parsed.get("action") == "summarize_emails":
            try:
                emails_text = fetch_recent_emails_summary(user)
            except MissingGoogleCredentials as e:
                return Response({"reply": str(e)})
            
            summary_response = openai.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "Summarize the following emails clearly and concisely."},
                    {"role": "user", "content": emails_text}
                ],
            )
            summary = summary_response.choices[0].message.content
            return Response({"reply": summary})

        # === Send Email ===
        elif parsed.get("action") == "send_email":
            to = parsed.get("to")
            subject = parsed.get("subject", "No Subject")
            body = parsed.get("body", "")
            if not (to and body):
                return Response({"error": "Missing email or body."}, status=400)
            result = send_email(user, to, subject, body)
            return Response({"reply": result})

        # === Fallback Chat ===
        else:
            fallback_response = openai.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a helpful workplace assistant."},
                    {"role": "user", "content": user_message}
                ],
            )
            reply = fallback_response.choices[0].message.content
            return Response({"reply": reply})

    except Exception as e:
        return Response({"error": str(e)}, status=500)


def parse_datetime_safely(input_str):
    

    now = datetime.now()
    tz = get_current_timezone()

    input_str = input_str.lower().strip()

    # Handle 'today' and 'tomorrow'
    if "today" in input_str:
        base_date = now.date()
        # remove 'today' from string to parse time only
        time_str = input_str.replace("today", "").strip()
        if time_str == "":
            # If only 'today' provided, return now
            dt = datetime.combine(base_date, now.time())
        else:
            dt = dateutil_parse(time_str, default=datetime.combine(base_date, time(0, 0)))
    elif "tomorrow" in input_str:
        base_date = now.date() + timedelta(days=1)
        time_str = input_str.replace("tomorrow", "").strip()
        if time_str == "":
            dt = datetime.combine(base_date, time(9, 0))  # default 9AM tomorrow
        else:
            dt = dateutil_parse(time_str, default=datetime.combine(base_date, time(0, 0)))
    else:
        # If input has no explicit date, check if it has a date pattern
        date_match = re.search(r"\d{4}-\d{2}-\d{2}", input_str)
        if date_match:
            dt = dateutil_parse(input_str)
        else:
            # No date found, assume today
            dt = dateutil_parse(input_str, default=datetime.combine(now.date(), time(0, 0)))

            # If parsed datetime is earlier than now, and only time was provided, assume next day
            if dt < now:
                dt += timedelta(days=1)

    # Make datetime aware if naive
    if not is_aware(dt):
        dt = make_aware(dt, timezone=tz)

    return dt





def fetch_recent_emails_summary(user, max_emails=5):
    try:
        user_obj = get_exact_user(user)
        user_creds = GoogleCredentials.objects.get(user=user_obj)

        creds = Credentials(
            token=user_creds.token,
            refresh_token=user_creds.refresh_token,
            token_uri=user_creds.token_uri,
            client_id=user_creds.client_id,
            client_secret=user_creds.client_secret,
            scopes=user_creds.scopes.split()
        )

        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            user_creds.token = creds.token
            user_creds.save()

        service = build('gmail', 'v1', credentials=creds)

        messages = service.users().messages().list(userId='me', maxResults=max_emails).execute().get('messages', [])
        email_bodies = []

        for msg in messages:
            msg_detail = service.users().messages().get(userId='me', id=msg['id']).execute()
            snippet = msg_detail.get('snippet', '')
            headers = msg_detail.get('payload', {}).get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            email_bodies.append(f"Subject: {subject}\nSnippet: {snippet}")

        return "\n\n".join(email_bodies)
        
    except GoogleCredentials.DoesNotExist:
        print(f"No Google credentials found for user {user.username}")
        # Instead of returning a Response, return a string that your view can respond with
        return "Google account is not connected. Please connect your Google account first."


def send_email(user, to, subject, body):
    try:
        user_obj = get_exact_user(user)
        user_creds = GoogleCredentials.objects.get(user=user_obj)

    except GoogleCredentials.DoesNotExist:
        return "Google account is not connected. Please connect your Google account first."

    creds = Credentials(
        token=user_creds.token,
        refresh_token=user_creds.refresh_token,
        token_uri=user_creds.token_uri,
        client_id=user_creds.client_id,
        client_secret=user_creds.client_secret,
        scopes=user_creds.scopes.split()
    )

    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        user_creds.token = creds.token
        user_creds.save()

    service = build('gmail', 'v1', credentials=creds)

    message = MIMEText(body)
    message['to'] = to
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

    message_body = {'raw': raw}
    service.users().messages().send(userId='me', body=message_body).execute()

    return "📤 Email sent successfully!"


def get_exact_user(user):
    User = get_user_model()
    try:
        return User.objects.get(username__iexact=user.username)
    except User.DoesNotExist:
        return user


