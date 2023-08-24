from django.urls import path
from .views import *

urlpatterns = [
    path("",Signup,name='signup'),
    path("login/",Login,name='login'),
    path("homepage/",Homepage,name='homepage'),
    path("contact/",Contact,name='contact'),
    path("logout/",Logout,name='logout'),
    path('forget_password/',ForgetPassword,name='forgetpassword'),
    path('forget_password_email_send/',ForgetPasswordEmailSend, name='forgetpasswordemailsend'),

    path('forget_password_done/<uidb64>/<token>/', ForgetPasswordDone, name='forgetpassworddone'),
    path('changepassword/', ChangePassword, name='changepassword')


]
