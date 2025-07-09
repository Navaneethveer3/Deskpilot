from django.urls import path
from .views import chat_with_assistant

urlpatterns = [
    path("ai-chat/", chat_with_assistant),
]