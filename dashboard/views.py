from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from network_model.models import SDNController, SDNSwitch, SDNHost, CommunicationFlow
from vulnerability_analysis.models import Vulnerability, AttackPath, SecurityAlert
from attack_simulation.models import AttackScenario, SimulationResult
from reports.models import Report


@login_required
def home(request):
    """Route to role-specific dashboard"""
    if request.user.role == 'admin':
        return admin_home(request)
    else:
        return user_home(request)


def user_home(request):
    """Dashboard for analysts and viewers"""
    context = {
        'total_controllers': SDNController.objects.count(),
        'total_switches': SDNSwitch.objects.count(),
        'total_hosts': SDNHost.objects.count(),
        'total_flows': CommunicationFlow.objects.count(),
        'critical_vulns': Vulnerability.objects.filter(severity='critical').count(),
        'high_vulns': Vulnerability.objects.filter(severity='high').count(),
        'medium_vulns': Vulnerability.objects.filter(severity='medium').count(),
        'low_vulns': Vulnerability.objects.filter(severity='low').count(),
        'total_vulns': Vulnerability.objects.count(),
        'patched_vulns': Vulnerability.objects.filter(is_patched=True).count(),
        'total_simulations': AttackScenario.objects.count(),
        'successful_attacks': SimulationResult.objects.filter(is_successful=True).count(),
        'recent_alerts': SecurityAlert.objects.filter(is_resolved=False).order_by('-created_at')[:5],
        'recent_vulns': Vulnerability.objects.order_by('-detected_at')[:5],
        'recent_simulations': AttackScenario.objects.filter(status='completed').order_by('-executed_at')[:5],
        'my_reports': Report.objects.filter(generated_by=request.user).count(),
        'attack_paths': AttackPath.objects.filter(is_active=True).count(),
        'packet_vulns': Vulnerability.objects.filter(vuln_type__in=['packet_injection', 'replay_attack', 'flow_rule_tampering']).count(),
        'topology_vulns': Vulnerability.objects.filter(vuln_type__in=['topology_poisoning', 'arp_spoofing', 'man_in_middle']).count(),
        'unresolved_alerts': SecurityAlert.objects.filter(is_resolved=False).count(),
    }
    return render(request, 'dashboard/user_home.html', context)


def admin_home(request):
    """Dashboard for admins"""
    from authentication.models import CustomUser
    try:
        from formal_verification.models import VerificationJob, VerificationResult
        verif_jobs = VerificationJob.objects.count()
        verif_violations = VerificationResult.objects.filter(result='violated').count()
    except Exception:
        verif_jobs = 0
        verif_violations = 0

    context = {
        'total_controllers': SDNController.objects.count(),
        'total_switches': SDNSwitch.objects.count(),
        'total_hosts': SDNHost.objects.count(),
        'total_flows': CommunicationFlow.objects.count(),
        'active_controllers': SDNController.objects.filter(status='active').count(),
        'compromised_switches': SDNSwitch.objects.filter(status='compromised').count(),
        'critical_vulns': Vulnerability.objects.filter(severity='critical').count(),
        'total_vulns': Vulnerability.objects.count(),
        'unpatched_vulns': Vulnerability.objects.filter(is_patched=False).count(),
        'total_simulations': AttackScenario.objects.count(),
        'successful_attacks': SimulationResult.objects.filter(is_successful=True).count(),
        'pending_simulations': AttackScenario.objects.filter(status='pending').count(),
        'total_users': CustomUser.objects.count(),
        'active_users': CustomUser.objects.filter(is_active=True).count(),
        'recent_alerts': SecurityAlert.objects.filter(is_resolved=False).order_by('-created_at')[:5],
        'unresolved_alerts': SecurityAlert.objects.filter(is_resolved=False).count(),
        'recent_vulns': Vulnerability.objects.order_by('-detected_at')[:5],
        'recent_simulations': AttackScenario.objects.order_by('-created_at')[:5],
        'total_reports': Report.objects.count(),
        'verif_jobs': verif_jobs,
        'verif_violations': verif_violations,
        'suspicious_flows': CommunicationFlow.objects.filter(is_suspicious=True).count(),
        'malicious_hosts': SDNHost.objects.filter(is_malicious=True).count(),
    }
    return render(request, 'dashboard/admin_home.html', context)
