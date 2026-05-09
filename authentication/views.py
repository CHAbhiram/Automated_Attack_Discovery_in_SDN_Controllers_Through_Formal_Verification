from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import LoginForm, RegisterForm
from .models import CustomUser


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:home')

    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            # Update last login IP
            ip = request.META.get('REMOTE_ADDR')
            CustomUser.objects.filter(pk=user.pk).update(last_login_ip=ip)
            messages.success(
                request,
                f'Welcome back, {user.first_name or user.username}!'
            )
            return redirect('dashboard:home')
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm(request)

    return render(request, 'authentication/login.html', {'form': form})


def logout_view(request):
    username = request.user.username
    logout(request)
    messages.info(request, f'Goodbye, {username}! You have been logged out.')
    return redirect('authentication:login')


def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:home')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            # DO NOT call login(request, user) here
            messages.success(
                request,
                f'Account created successfully, {user.first_name or user.username}! '
                f'Please sign in with your credentials.'
            )
            return redirect('authentication:login')  # Go to Sign In page
        else:
            messages.error(request, 'Please fix the errors below.')
    else:
        form = RegisterForm()

    return render(request, 'authentication/register.html', {'form': form})


@login_required
def profile_view(request):
    if request.method == 'POST':
        # Allow updating basic profile info
        user = request.user
        user.first_name = request.POST.get('first_name', user.first_name)
        user.last_name = request.POST.get('last_name', user.last_name)
        user.department = request.POST.get('department', user.department)
        user.phone = request.POST.get('phone', user.phone)
        user.save()
        messages.success(request, 'Profile updated successfully!')
        return redirect('authentication:profile')
    return render(request, 'authentication/profile.html', {'user': request.user})
