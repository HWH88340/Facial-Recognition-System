from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login
from .models import CustomUser
import json
import pymongo
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
        client = pymongo.MongoClient('mongodb+srv://admin:admin@security.ju0aixd.mongodb.net/?retryWrites=true&w=majority')
        db = client.admin
        email = request.POST['email']
        username = request.POST.get('username')
        password = request.POST.get('password')
        facial_data = request.POST.get('facial_data', None)  # Add this line
        
        # Check if user with the same email already exists
        if CustomUser.objects.filter(email=email).exists():
            return render(request, 'signup.html', {'error': 'Email is already taken'})
        
        # Check if user with the same username already exists
        if CustomUser.objects.filter(username=username).exists():
            return render(request, 'signup.html', {'error': 'Username is already taken'})
        # Create new user
        #user = CustomUser.objects.create_user(username=username, email=email, password=password, facial_data=facial_data)
        #user.save()
        db = client.customers
        customers = db.customers
        

        if customers.count_documents({'email': email}) != 0:
            return render(request, 'signup.html', {'error': 'Email is already taken'})
        if customers.count_documents({'username': username}) != 0:
            return render(request, 'signup.html', {'error': 'Username is already taken'})
        customer = {'email': email, 'username': username, 'password': password}

        db.customers.insert_one(customer)
        # Redirect to login page
        return redirect('login')
    
    # Render the signup form if the request method is GET
    return render(request, 'signup.html')

def login(request):
    if request.method == 'POST':
        client = pymongo.MongoClient('mongodb+srv://admin:admin@security.ju0aixd.mongodb.net/?retryWrites=true&w=majority')
        db = client.admin
        db = client.customers
        customers = db.customers
        email = request.POST.get('email')
        password = request.POST.get('password')
        facial_data = request.POST.get('facial_data', None)
        print(request.POST)
        if customers.count_documents({'$and': [{'email': email}, {'password': password}]}):
            messages.success(request, 'Login successfully.')
            request.session['email'] = email
            request.session['password'] = password
            return redirect('umain')
        else:
            messages.error(request, 'Invalid email or password.')
            print('invalid')
            return redirect('login')
    else:
        return render(request, 'login.html')
    
def umain(request):
    email = request.session.get('email')
    password = request.session.get('password')
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
    email = request.session.get('email')
    password = request.session.get('password')
    client = pymongo.MongoClient('mongodb+srv://admin:admin@security.ju0aixd.mongodb.net/?retryWrites=true&w=majority')
    db = client.admin
    db = client.customers
    customers = db.customers
    data = list(customers.find({'$and': [{'email': email}, {'password': password}]}))
    context = {'data': data[0]}
    if request.method == 'POST':
        print('receive request')
        key_info = list(request.POST.keys())
        print(key_info)
        if key_info:
            print(key_info[1])
            if 'edit'in key_info[1]:
                request.session['action'] = key_info[1][:4]
                request.session['type'] = key_info[1][5:]
                return redirect('editordel')
            elif 'delete' in key_info[1]:
                request.session['action'] = key_info[1][:6]
                request.session['type'] = key_info[1][7:]
                return redirect('editordel')
        return redirect('settings')
    else:
        return render(request, 'settings.html', context)

def editordel(request):
    action = request.session['action']
    action_type = request.session['type']
    email = request.session.get('email')
    password = request.session.get('password')
    data = {'action': action, 'type': action_type}
    context = {'data': data}

    if request.method == 'POST':
        if 'update' in request.POST.keys():
            modified_info = request.POST.get('info1')
            modified_info_conf = request.POST.get('info2')
            if modified_info != modified_info_conf:
                return render(request, 'editordel.html', {'error': 'Two inputs do not match.'})
            client = pymongo.MongoClient('mongodb+srv://admin:admin@security.ju0aixd.mongodb.net/?retryWrites=true&w=majority')
            db = client.admin
            db = client.customers
            customers = db.customers
            # Find document to be modified
            document = customers.find_one({'email': email, 'password': password})
            
            if document:
                if action == 'edit':
                    customers.update_one({'email': email, 'password': password}, {'$set': {action_type: modified_info}})
                if action == 'delete':
                    customers.delete_one({'email': email, 'password': password})
            return redirect('login')
        return redirect('settings')
    else:
        return render(request, 'editordel.html', context)




from django.contrib.auth import logout
from django.shortcuts import redirect

def logout_view(request):
    logout(request)
    return redirect('facial_auth')  # Replace 'main_page' with the name of the view for your main page.

