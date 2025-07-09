from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import register_user, protected_view, verify_email, CustomTokenObtainPairView, logout_user
from .views import ReminderListCreateAPIView, ReminderRetrieveUpdateDestroyAPIView
from ai_assistant.views import google_login, google_callback, google_status

urlpatterns = [
    path('register/', register_user),
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path("token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path('token.refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('protected/', protected_view),
    path('verify-email/<uidb64>/<token>/', verify_email),
    path('logout/', logout_user),
    path('reminders/', ReminderListCreateAPIView.as_view(), name='reminder-list-create'),
    path('reminders/<int:pk>/', ReminderRetrieveUpdateDestroyAPIView.as_view(), name='reminder-detail'),
    path('google/login/', google_login, name='google_login'),
    path('google/callback/', google_callback, name='google_callback'),
    path("google/status/", google_status),
    
]