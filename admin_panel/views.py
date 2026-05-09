from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from authentication.models import CustomUser
from network_model.models import SDNController, SDNSwitch, SDNHost, CommunicationFlow
from vulnerability_analysis.models import Vulnerability, SecurityAlert
from attack_simulation.models import AttackScenario


def admin_required(view_func):
    from functools import wraps
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated or request.user.role != 'admin':
            messages.error(request, 'Admin access required.')
            return redirect('dashboard:home')
        return view_func(request, *args, **kwargs)
    return wrapper


@login_required
@admin_required
def admin_dashboard(request):
    context = {
        'total_users': CustomUser.objects.count(),
        'admin_users': CustomUser.objects.filter(role='admin').count(),
        'analyst_users': CustomUser.objects.filter(role='analyst').count(),
        'viewer_users': CustomUser.objects.filter(role='viewer').count(),
        'users': CustomUser.objects.all().order_by('-date_joined')[:10],
        'controllers': SDNController.objects.all(),
        'total_vulns': Vulnerability.objects.count(),
        'unresolved_alerts': SecurityAlert.objects.filter(is_resolved=False).count(),
        'total_simulations': AttackScenario.objects.count(),
    }
    return render(request, 'admin_panel/dashboard.html', context)

@login_required
@admin_required
def create_user(request):
    from authentication.forms import AdminUserCreateForm
    if request.method == 'POST':
        form = AdminUserCreateForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, f'User "{user.username}" created with role: {user.get_role_display()}')
            return redirect('admin_panel:user_management')
        else:
            messages.error(request, 'Please fix the errors below.')
    else:
        form = AdminUserCreateForm()
    return render(request, 'admin_panel/create_user.html', {'form': form})

@login_required
@admin_required
def user_management(request):
    users = CustomUser.objects.all().order_by('-date_joined')
    return render(request, 'admin_panel/user_management.html', {
        'users': users,
        'active_count': users.filter(is_active=True).count(),
        'inactive_count': users.filter(is_active=False).count(),
    })


@login_required
@admin_required
def toggle_user(request, pk):
    user = get_object_or_404(CustomUser, pk=pk)
    if user != request.user:
        user.is_active = not user.is_active
        user.save()
        status = 'activated' if user.is_active else 'deactivated'
        messages.success(request, f'User {user.username} has been {status}.')
    return redirect('admin_panel:user_management')


@login_required
@admin_required
def change_user_role(request, pk):
    user = get_object_or_404(CustomUser, pk=pk)
    if request.method == 'POST' and user != request.user:
        new_role = request.POST.get('role')
        if new_role in ['admin', 'analyst', 'viewer']:
            user.role = new_role
            user.save()
            messages.success(request, f'Role updated to {new_role} for {user.username}.')
    return redirect('admin_panel:user_management')


@login_required
@admin_required
def network_config(request):
    controllers = SDNController.objects.prefetch_related('switches__hosts').all()
    switches = SDNSwitch.objects.select_related('controller').all()
    hosts = SDNHost.objects.select_related('switch').all()

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'add_controller':
            SDNController.objects.create(
                name=request.POST.get('name'),
                ip_address=request.POST.get('ip_address'),
                port=request.POST.get('port', 6633),
                controller_type=request.POST.get('controller_type', 'OpenDaylight'),
                version=request.POST.get('version', '1.0'),
                description=request.POST.get('description', ''),
            )
            messages.success(request, 'Controller added successfully!')

        elif action == 'add_switch':
            ctrl_id = request.POST.get('controller_id')
            if ctrl_id:
                SDNSwitch.objects.create(
                    controller_id=ctrl_id,
                    name=request.POST.get('sw_name'),
                    dpid=request.POST.get('dpid'),
                    ip_address=request.POST.get('sw_ip'),
                    of_version=request.POST.get('of_version', '1.3'),
                    flow_table_size=request.POST.get('flow_table_size', 1000),
                    description=request.POST.get('sw_description', ''),
                )
                messages.success(request, 'Switch added successfully!')

        elif action == 'add_host':
            sw_id = request.POST.get('switch_id')
            if sw_id:
                SDNHost.objects.create(
                    switch_id=sw_id,
                    name=request.POST.get('host_name'),
                    ip_address=request.POST.get('host_ip'),
                    mac_address=request.POST.get('mac_address'),
                    port_number=request.POST.get('port_number', 1),
                    os_type=request.POST.get('os_type', ''),
                    description=request.POST.get('host_description', ''),
                )
                messages.success(request, 'Host added successfully!')

        elif action == 'delete_controller':
            ctrl_id = request.POST.get('ctrl_id')
            SDNController.objects.filter(pk=ctrl_id).delete()
            messages.success(request, 'Controller deleted.')

        elif action == 'delete_switch':
            sw_id = request.POST.get('sw_id')
            SDNSwitch.objects.filter(pk=sw_id).delete()
            messages.success(request, 'Switch deleted.')

        elif action == 'delete_host':
            host_id = request.POST.get('host_id')
            SDNHost.objects.filter(pk=host_id).delete()
            messages.success(request, 'Host deleted.')

        elif action == 'update_controller_status':
            ctrl_id = request.POST.get('ctrl_id')
            new_status = request.POST.get('new_status')
            SDNController.objects.filter(pk=ctrl_id).update(status=new_status)
            messages.success(request, 'Controller status updated.')

        return redirect('admin_panel:network_config')

    return render(request, 'admin_panel/network_config.html', {
        'controllers': controllers,
        'switches': switches,
        'hosts': hosts,
    })


@login_required
@admin_required
def openflow_settings(request):
    controllers = SDNController.objects.all()
    switches = SDNSwitch.objects.select_related('controller').all()

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'update_of_version':
            sw_id = request.POST.get('switch_id')
            of_version = request.POST.get('of_version')
            SDNSwitch.objects.filter(pk=sw_id).update(of_version=of_version)
            messages.success(request, 'OpenFlow version updated.')
        elif action == 'update_controller_port':
            ctrl_id = request.POST.get('controller_id')
            port = request.POST.get('port')
            SDNController.objects.filter(pk=ctrl_id).update(port=port)
            messages.success(request, 'Controller port updated.')
        return redirect('admin_panel:openflow_settings')

    return render(request, 'admin_panel/openflow_settings.html', {
        'controllers': controllers,
        'switches': switches,
        'of_versions': ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5'],
    })


@login_required
@admin_required
def security_policies(request):
    from network_model.models import SDNController

    vulns = Vulnerability.objects.filter(is_patched=False).order_by('-cvss_score')
    alerts = SecurityAlert.objects.filter(is_resolved=False)
    patched = Vulnerability.objects.filter(is_patched=True).count()

    # Predefined automated fixes
    fix_definitions = [
        {'key': 'tls_auth',       'name': 'Enable TLS Authentication',          'description': 'Enforce TLS mutual authentication on all controller-switch connections'},
        {'key': 'arp_inspection', 'name': 'Dynamic ARP Inspection',             'description': 'Enable DAI on all switches to prevent ARP spoofing'},
        {'key': 'rate_limit',     'name': 'Control Plane Rate Limiting',         'description': 'Limit packet-in rate to prevent DoS saturation attacks'},
        {'key': 'flow_monitor',   'name': 'Flow Table Monitoring',               'description': 'Enable real-time flow table change alerts and anomaly detection'},
        {'key': 'lldp_auth',      'name': 'Authenticated LLDP',                  'description': 'Verify LLDP packets to prevent topology poisoning'},
        {'key': 'port_security',  'name': 'Port Security Enforcement',           'description': 'Enable port-based MAC address restriction on switch ports'},
        {'key': 'vlan_segment',   'name': 'Network Segmentation',                'description': 'Apply VLAN segmentation to isolate sensitive network segments'},
        {'key': 'log_siem',       'name': 'SIEM Log Integration',                'description': 'Forward all security events to centralized SIEM system'},
    ]

    # Track which fixes have been applied (stored in session)
    applied_fixes = request.session.get('applied_fixes', [])
    automated_fix_list = []
    for fix in fix_definitions:
        automated_fix_list.append({**fix, 'applied': fix['key'] in applied_fixes})

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'patch_vuln':
            vuln_id = request.POST.get('patch_vuln')
            if vuln_id:
                vuln = get_object_or_404(Vulnerability, pk=vuln_id)
                vuln.is_patched = True
                vuln.patched_at = timezone.now()
                vuln.save()
                try:
                    from formal_verification.models import SecurityLog
                    SecurityLog.objects.create(
                        log_type='policy', severity='info',
                        title=f'Vulnerability Patched: {vuln.name}',
                        message=f'"{vuln.name}" (CVSS: {vuln.cvss_score}) marked as patched by {request.user.username}.',
                        user=request.user, component='Security Policy Manager',
                    )
                except Exception:
                    pass
                messages.success(request, f'"{vuln.name}" marked as patched!')

        elif action == 'patch_all':
            count = Vulnerability.objects.filter(is_patched=False).count()
            Vulnerability.objects.filter(is_patched=False).update(
                is_patched=True, patched_at=timezone.now()
            )
            messages.success(request, f'{count} vulnerabilities marked as patched!')

        elif action == 'resolve_alert':
            alert_id = request.POST.get('resolve_alert')
            if alert_id:
                alert = get_object_or_404(SecurityAlert, pk=alert_id)
                alert.is_resolved = True
                alert.save()
                messages.success(request, 'Alert resolved!')

        elif action == 'apply_fix':
            fix_key = request.POST.get('fix_key')
            if fix_key and fix_key not in applied_fixes:
                applied_fixes.append(fix_key)
                request.session['applied_fixes'] = applied_fixes
                fix_name = next((f['name'] for f in fix_definitions if f['key'] == fix_key), fix_key)
                try:
                    from formal_verification.models import SecurityLog
                    SecurityLog.objects.create(
                        log_type='policy', severity='info',
                        title=f'Automated Fix Applied: {fix_name}',
                        message=f'Security fix "{fix_name}" applied at controller level by {request.user.username}.',
                        user=request.user, component='Automated Fix Engine',
                    )
                except Exception:
                    pass
                messages.success(request, f'Fix "{fix_name}" applied successfully!')

        elif action == 'apply_all_fixes':
            for fix in fix_definitions:
                if fix['key'] not in applied_fixes:
                    applied_fixes.append(fix['key'])
            request.session['applied_fixes'] = applied_fixes
            messages.success(request, f'All {len(fix_definitions)} automated fixes applied!')

        return redirect('admin_panel:security_policies')

    return render(request, 'admin_panel/security_policies.html', {
        'unpatched_vulns': Vulnerability.objects.filter(is_patched=False).order_by('-cvss_score'),
        'alerts': SecurityAlert.objects.filter(is_resolved=False),
        'patched_count': patched,
        'automated_fix_list': automated_fix_list,
        'automated_fixes': len(applied_fixes),
    })


@login_required
@admin_required
def system_monitoring(request):
    context = {
        'controllers': SDNController.objects.all(),
        'active_flows': CommunicationFlow.objects.count(),
        'suspicious_flows': CommunicationFlow.objects.filter(is_suspicious=True).count(),
        'malicious_hosts': SDNHost.objects.filter(is_malicious=True).count(),
        'recent_alerts': SecurityAlert.objects.order_by('-created_at')[:10],
        'compromised_switches': SDNSwitch.objects.filter(status='compromised').count(),
        'total_switches': SDNSwitch.objects.count(),
        'active_switches': SDNSwitch.objects.filter(status='active').count(),
        'total_hosts': SDNHost.objects.count(),
    }
    try:
        from formal_verification.models import SecurityLog
        context['recent_logs'] = SecurityLog.objects.order_by('-created_at')[:8]
    except Exception:
        context['recent_logs'] = []
    return render(request, 'admin_panel/system_monitoring.html', context)
