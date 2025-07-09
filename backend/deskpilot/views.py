from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status, viewsets, permissions, generics
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed
from .models import Reminder
from .serializers import ReminderSerializer
from dateutil.parser import parse




def send_verification_email(user, frontend_url):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    verification_link = f"{frontend_url}/verify-email/{uid}/{token}/"

    subject = "Verify your DeskPilot account"
    message = f"Hi {user.username},\n\nPlease verify your account by clicking the link:\n{verification_link}"

    send_mail(subject, message, 'hello@deskpilot.com', [user.email])

@api_view(['POST'])
def register_user(request):
    username = request.data.get('username')
    password = request.data.get('password')
    email = request.data.get('email')
    frontend_url = request.data.get('frontend_url')

    if User.objects.filter(username=username).exists():
        return Response({'error':'User already exists'}, status=400)

    if User.objects.filter(email=email).exists():
        return Response({'error':'Email already exists'}, status=400)

    user = User.objects.create_user(username=username, password=password, email=email, is_active=False)
    send_verification_email(user, frontend_url)

    return Response({'message':'User registered succesfully! Please verify your account to login'}, status=201)


@api_view(['GET'])
def verify_email(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        
        if user.is_active:
            return Response({'message':'User already verified.'}, status=200)

        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({'message':'User verified successfully!'}, status=200)
        else:
            return Response({'error':'Token expired. Please retry again'}, status=400)

    except Exception as e:
        return Response({'error':'Invalid verification link.'}, status=400)


@api_view(['GET'])
def protected_view(request):
    return Response({'message':f'Welcome {request.user.username}! You are authenticated.'})



class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        if not self.user.is_active:
            raise AuthenticationFailed('Email not verified. Please check your email.')

        return data

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer



@api_view(['POST'])
def logout_user(request):
    try:
        refresh_token = request.data["refresh"]
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response({"message": "Logout successful"}, status=205)
    except Exception as e:
        return Response({"error": "Invalid token"}, status=400)



class ReminderListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = ReminderSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Reminder.objects.filter(user=self.request.user).order_by('-remind_at')

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class ReminderRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = ReminderSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Reminder.objects.filter(user=self.request.user)





def parse_reminder_time(text):
    
    dt = parse(text, fuzzy=True)  
    return dt

