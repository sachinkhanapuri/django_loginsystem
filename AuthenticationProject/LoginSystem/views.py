from django.contrib.auth import authenticate,login, logout
from django.shortcuts import render,redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
#from .tokens import generate_token
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator


# Create your views here.
def Signup(request):
    if request.method == "POST":
        username=request.POST.get('username')
        email=request.POST.get('email')
        password=request.POST.get("password")
        confirm_password=request.POST.get("confirm_password")
        user = User.objects.filter(username=username)
        print(user)
        if username=="" or email=="" or password=="" or confirm_password=="":
            messages.info(request,"All the filed should be complousory!!")
            return redirect('signup')
        if user.exists():
            messages.error(request, "Username is already exist! PLease try some another one username")
            return render(request, 'signup.html')
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email is already exist! PLease try with another one")
            return render(request, 'signup.html')
        else:
            if password == confirm_password:
                user = User.objects.create_user(username=username, email=email, password=password)
                # print(user)
                user.save()
                messages.success(request, "User created successfully!!")
                return redirect('login')
            elif len(password) < 10:
                messages.error(request, "Password should be less then 10")
                return render(request, 'signup.html')
            else:
                messages.error(request, "Password didn't matched")
                return render(request,'signup.html')
    return render(request,'signup.html')

def Login(request):
    if request.method=="POST":
        username=request.POST.get('username')
        password=request.POST.get('pass')
        user=User.objects.filter(username=username)
        #print(user)
        if username == '':
            messages.error(request, "Please enter Username,It should not be empty")
            return render(request, 'login.html')
        if password == '':
            messages.error(request, "Please enter Password,It should not be empty")
            return render(request, 'login.html')
        if not user.exists():
            messages.error(request, "User is incorrect ,please enter correct username")
            return render(request, 'login.html')
        else:
            auth_user = authenticate(username=username, password=password)
            #print("auth_user:", auth_user)
            if auth_user is not None:
                if check_password(password, user[0].password):
                    login(request, auth_user)
                    messages.success(request, "User login succesfully")
                    return render(request,'home.html',{'user':auth_user})
                else:
                    messages.error(request, "password is incorrect")
                    return render(request, 'login.html')
            else:
                messages.error(request,'Password does not match,Please try with valid one')
                return render(request, 'login.html')
    return render(request, 'login.html')


def Homepage(request):
    return render(request, 'home.html')

def Contact(request):
    return render(request,'contact.html')

def Logout(request):
    logout(request)
    return redirect('login')

def ForgetPassword(request):
    if request.method == "POST":
        email = request.POST.get('email')
        #print("email:",email)
        if email == "":
            messages.warning(request,"Please enter email first")
            return render(request,'forgetpwd.html')
        else:
            user_email=User.objects.filter(email=email)
            print("user_email:",user_email[0])
            if user_email.exists():
                subject='Password Reset request'
                message = render_to_string('forgetpwd_email_send_template.html',{
                            'user':user_email[0].username,
                            'domain':get_current_site(request).domain,
                            'uid':urlsafe_base64_encode(force_bytes(user_email[0].id)),
                            'token':PasswordResetTokenGenerator().make_token(user_email[0]),
                            'protocol':'http'
                })
                #email=EmailMessage(subject,message,to=[email])
                #email.send(email)
                send_mail(subject,message,recipient_list=[email],from_email=settings.EMAIL_HOST_USER,fail_silently=True)
                return render(request,'forgetpwd_email_send.html')
            else:
                messages.info(request,"Email id does not exist ,please check with valid email address")
                return render(request,'forgetpwd.html')

    return render(request,'forgetpwd.html')


def ForgetPasswordEmailSend(request):
    return render(request,'forgetpwd_email_send.html')

def ForgetPasswordDone(request,**args):
    if request.method=="GET":
        uidb64= args['uidb64']
        token = args['token']
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(id=uid)
        print(user,token)
        if not PasswordResetTokenGenerator().check_token(user,token):
            messages.error(request, "Reset password link get expired,please request with new one")
            return redirect('login')
        else:
            return render(request, 'forgetpwd_done.html')


    if request.method=="POST":
        uid=force_str(urlsafe_base64_decode(args['uidb64']))
        user=User.objects.get(id=uid)
        if user !=None:
            new_password=request.POST.get('new_password')
            confirm_password=request.POST.get('confirm_password')
            if new_password == "" and confirm_password == "":
                messages.info(request, "Both the password should not be empty")
                return render(request, 'forgetpwd_done.html')
            elif new_password != confirm_password:
                messages.error(request, "Password does not match, please try again!!")
                return render(request, 'forgetpwd_done.html')
            else:
                user.set_password(new_password)
                user.save()
                return redirect('login')

        else:
            messages.error(request, "Username does not exists")
            return render(request, 'forgetpwd_done.html')
    return render(request,'forgetpwd_done.html')


def ChangePassword(request):
    if request.method=="POST":
        old_password=request.POST.get('old_password')
        new_password=request.POST.get('new_password')
        confirm_password=request.POST.get('confirm_password')
        user=request.user
        #print('user:',user.password)
        if user != None:
            if check_password(old_password, user.password):
                if new_password == confirm_password:
                    user.set_password(new_password)
                    user.save()
                    messages.success(request,"Password change done successfully")
                    return render(request,'home.html')
                else:
                    messages.error(request, "New Password and confirm password does not matched")
                    return render(request, 'ChangePassword.html')
            else:
                messages.error(request, "Old Password does not matched")
                return render(request, 'ChangePassword.html')
        return render(request, 'ChangePassword.html')
    return render(request, 'ChangePassword.html')