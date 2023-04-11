from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login
from .models import CustomUser
import json

# Create your views here.

from django.http import JsonResponse

def facial_auth(request):
    if request.method == 'POST':
        # Retrieve the facial data from the request
        facial_data = request.POST.get('facial_data', None)

        # Save the facial data to the user's profile
        if facial_data:
            request.user.facial_data = json.loads(facial_data)
            request.user.save()

        return JsonResponse({'status': 'success'})

    return render(request, 'facial_auth.html')


def signup(request):
    if request.method == 'POST':
        email = request.POST['email']
        username = request.POST.get('username')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2') # request.POST => request.POST.get()
        facial_data = request.POST.get('facial_data', None)  # Add this line
        
        # Check if passwords match
        if password1 != password2:
            return render(request, 'signup.html', {'error': 'Passwords do not match'})
        
        # Check if user with the same email already exists
        if CustomUser.objects.filter(email=email).exists():
            return render(request, 'signup.html', {'error': 'Email is already taken'})
        
        # Check if user with the same username already exists
        if CustomUser.objects.filter(username=username).exists():
            return render(request, 'signup.html', {'error': 'Username is already taken'})
        
        # Create new user
        user = CustomUser.objects.create_user(username=username, email=email, password=password1, facial_data=facial_data)
        user.save()
        
        # Redirect to login page
        return redirect('login')
    
    # Render the signup form if the request method is GET
    return render(request, 'signup.html')

def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        facial_data = request.POST.get('facial_data', None)
        print(request.POST)
        try:
            user = CustomUser.objects.get(email=email)
            if user.check_password(password):
                '''
                if facial_data:
                    # Perform facial authentication
                    # If the facial authentication fails, show an error message and redirect to the login page.
                    # Otherwise, proceed with the login.
                    pass
                auth_login(request, user)
                messages.success(request, 'Logged in successfully.')
                '''
                print('checked')
                return redirect('umain')
            else:
                messages.error(request, 'Invalid email or password.')
                print('invalid')
                return redirect('umain')
        except CustomUser.DoesNotExist:
            messages.error(request, 'Invalid email or password.')
            print('not exist')
            return redirect('login')
    else:
        return render(request, 'login.html')
    
def umain(request):
    if request.method == 'POST':
        print(request.POST)
        if 'settings' in request.POST.keys():
            print('go to settings')
            return redirect('settings')
        pass
        
        return redirect('umain')
    else:
        return render(request, 'umain.html')
    
def settings(request):
    return render(request, 'settings.html')
    

from django.contrib.auth import logout
from django.shortcuts import redirect

def logout_view(request):
    logout(request)
    return redirect('facial_auth')  # Replace 'main_page' with the name of the view for your main page.

