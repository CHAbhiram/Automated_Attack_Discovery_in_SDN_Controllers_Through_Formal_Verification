from django.shortcuts import redirect
from django.contrib import messages

ADMIN_ONLY_PATHS = [
    '/admin-panel/',
    '/verification/rules/create/',
    '/verification/assertions/create/',
    '/verification/jobs/create/',
]

USER_BLOCKED_PATHS = [
    '/simulations/create/',
]


class RoleBasedAccessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            path = request.path
            role = getattr(request.user, 'role', 'viewer')

            # Block non-admins from admin panel
            if path.startswith('/admin-panel/'):
                if role != 'admin' and not request.user.is_superuser:
                    from django.contrib import messages
                    messages.error(request, 'Admin access required.')
                    from django.shortcuts import redirect
                    return redirect('dashboard:home')

            # Block viewers from CREATING simulations (not viewing)
            if path.startswith('/simulations/create/'):
                if role == 'viewer':
                    from django.contrib import messages
                    from django.shortcuts import redirect
                    messages.error(request, 'You do not have permission to create simulations.')
                    return redirect('attack_simulation:list')

            # Block non-admins from running simulations
            if '/simulations/' in path and '/run/' in path:
                if role != 'admin' and not request.user.is_superuser:
                    from django.contrib import messages
                    from django.shortcuts import redirect
                    messages.error(request, 'Only admins can run simulations.')
                    return redirect('attack_simulation:list')

            # Block viewers/analysts from verification create pages
            if role != 'admin':
                restricted = [
                    '/verification/rules/create/',
                    '/verification/assertions/create/',
                    '/verification/jobs/create/',
                ]
                if path in restricted:
                    from django.contrib import messages
                    from django.shortcuts import redirect
                    messages.error(request, 'Admin access required.')
                    return redirect('dashboard:home')

        return self.get_response(request)
    