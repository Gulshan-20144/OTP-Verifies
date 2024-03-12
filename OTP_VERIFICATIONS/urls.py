from rest_framework.urls import path
from OTP_VERIFICATIONS.views import Userragistration,Userlogin,Userdetails,VerifyOTP,ResendOtp
urlpatterns = [
    path("api/register-api/",Userragistration.as_view()),
    path("api/login-api/",Userlogin.as_view()),
    path("api/details-api/",Userdetails.as_view()),
    path("api/otp-api/",VerifyOTP.as_view()),
    path("api/resentotp-api/",ResendOtp.as_view())
]
