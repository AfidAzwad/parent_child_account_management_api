from django.urls import path
from .parent_account_views import ParentRegisterView, VerifyOTPAndCreateUserView


urlpatterns = [
    path('parent/register/', ParentRegisterView.as_view(), name='register_with_otp'),
    path('parent/verify-otp/', VerifyOTPAndCreateUserView.as_view(), name='verify_otp_and_create_user'),
]