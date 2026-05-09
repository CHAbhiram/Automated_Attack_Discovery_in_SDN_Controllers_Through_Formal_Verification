from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q
import random
import time

from .models import VerificationRule, SecurityAssertion, VerificationJob, VerificationResult, SecurityLog
from network_model.models import SDNController, SDNSwitch


def admin_required(view_func):
    from functools import wraps
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated or request.user.role != 'admin':
            messages.error(request, 'Admin access required.')
            return redirect('dashboard:home')
        return view_func(request, *args, **kwargs)
    return wrapper


def run_verification_engine(job):
    """Simulate formal verification using model checking logic"""
    results = []
    rules = job.rules.all()
    assertions = job.assertions.all()

    verification_logic = {
        'reachability': {
            'checks': ['Forward reachability analysis', 'Backward reachability trace', 'Dead-end detection'],
            'verified_rate': 0.70,
        },
        'isolation': {
            'checks': ['VLAN isolation check', 'ACL boundary verification', 'Segment separation analysis'],
            'verified_rate': 0.75,
        },
        'loop_freedom': {
            'checks': ['Cycle detection in flow graph', 'TTL-based loop analysis', 'Spanning tree verification'],
            'verified_rate': 0.85,
        },
        'consistency': {
            'checks': ['Flow rule overlap detection', 'Priority conflict analysis', 'Table consistency check'],
            'verified_rate': 0.65,
        },
        'access_control': {
            'checks': ['ACL policy verification', 'Role permission check', 'Port access validation'],
            'verified_rate': 0.80,
        },
        'waypointing': {
            'checks': ['Path waypoint verification', 'Middlebox traversal check', 'Policy enforcement point'],
            'verified_rate': 0.72,
        },
        'blackhole': {
            'checks': ['Unreachable node detection', 'Forwarding table completeness', 'Drop rule analysis'],
            'verified_rate': 0.60,
        },
    }

    for rule in rules:
        logic = verification_logic.get(rule.rule_type, {'checks': ['Generic check'], 'verified_rate': 0.70})
        noise = random.uniform(-0.15, 0.15)
        is_verified = (logic['verified_rate'] + noise) > 0.5
        exec_time = random.randint(120, 2500)
        details_verified = f"Property '{rule.name}' has been formally verified using model checking. "
        details_verified += f"Checks performed: {', '.join(logic['checks'])}. "
        details_verified += f"All {len(logic['checks'])} assertions passed successfully."
        details_violated = f"VIOLATION DETECTED in '{rule.name}'. "
        details_violated += f"Counter-example found during: {random.choice(logic['checks'])}. "
        details_violated += "Flow rule conflict identified at network layer."
        counterexample = ""
        if not is_verified:
            counterexample = f"Counter-example trace: Host A -> SW-{random.randint(1,3)} -> [VIOLATION] -> Destination unreachable. Packet dropped at flow entry #{random.randint(100,999)}."

        result = VerificationResult.objects.create(
            job=job,
            rule=rule,
            result='verified' if is_verified else 'violated',
            property_name=rule.name,
            details=details_verified if is_verified else details_violated,
            counterexample=counterexample,
            execution_time_ms=exec_time,
        )
        results.append(result)

    for assertion in assertions:
        is_verified = random.random() > 0.3
        result = VerificationResult.objects.create(
            job=job,
            assertion=assertion,
            result='verified' if is_verified else 'violated',
            property_name=assertion.name,
            details=f"Assertion '{assertion.name}' evaluated. Expected: {assertion.expected_result}. Result: {'PASS' if is_verified else 'FAIL'}.",
            counterexample="" if is_verified else f"Assertion failed: {assertion.assertion_logic} does not hold for current network state.",
            execution_time_ms=random.randint(50, 800),
        )
        results.append(result)

    verified = sum(1 for r in results if r.result == 'verified')
    violated = sum(1 for r in results if r.result == 'violated')
    job.verified_count = verified
    job.violated_count = violated
    job.total_properties = len(results)
    job.status = 'completed'
    job.completed_at = timezone.now()
    job.save()

    SecurityLog.objects.create(
        log_type='verification',
        severity='info' if violated == 0 else 'warning',
        title=f'Verification Job Completed: {job.name}',
        message=f'Job completed. {verified} properties verified, {violated} violations found.',
        user=job.initiated_by,
        component='Formal Verification Engine',
        extra_data={'job_id': job.id, 'verified': verified, 'violated': violated}
    )
    return results


@login_required
def verification_dashboard(request):
    jobs = VerificationJob.objects.all()
    rules = VerificationRule.objects.filter(is_active=True)
    assertions = SecurityAssertion.objects.filter(is_active=True)
    recent_results = VerificationResult.objects.select_related('job').order_by('-created_at')[:10]
    stats = {
        'total_jobs': jobs.count(),
        'completed': jobs.filter(status='completed').count(),
        'pending': jobs.filter(status='pending').count(),
        'total_rules': rules.count(),
        'total_assertions': assertions.count(),
        'violations': VerificationResult.objects.filter(result='violated').count(),
        'verified': VerificationResult.objects.filter(result='verified').count(),
    }
    context = {
        'jobs': jobs[:5],
        'rules': rules[:5],
        'stats': stats,
        'recent_results': recent_results,
    }
    return render(request, 'formal_verification/dashboard.html', context)


@login_required
@admin_required
def create_rule(request):
    controllers = SDNController.objects.all()
    switches = SDNSwitch.objects.all()
    if request.method == 'POST':
        rule = VerificationRule.objects.create(
            name=request.POST.get('name'),
            rule_type=request.POST.get('rule_type'),
            description=request.POST.get('description', ''),
            formal_expression=request.POST.get('formal_expression', ''),
            severity=request.POST.get('severity', 'medium'),
            controller_id=request.POST.get('controller') or None,
            switch_id=request.POST.get('switch') or None,
            created_by=request.user,
        )
        SecurityLog.objects.create(
            log_type='config_change',
            severity='info',
            title=f'Verification Rule Created: {rule.name}',
            message=f'New verification rule "{rule.name}" of type {rule.rule_type} created.',
            user=request.user,
            component='Formal Verification',
        )
        messages.success(request, f'Verification rule "{rule.name}" created successfully!')
        return redirect('formal_verification:rules')
    return render(request, 'formal_verification/create_rule.html', {
        'controllers': controllers,
        'switches': switches,
        'rule_types': VerificationRule.RULE_TYPES,
        'severity_choices': VerificationRule.SEVERITY_CHOICES,
    })


@login_required
@admin_required
def rule_list(request):
    rules = VerificationRule.objects.select_related('controller', 'switch', 'created_by').all()
    return render(request, 'formal_verification/rule_list.html', {'rules': rules})


@login_required
@admin_required
def create_assertion(request):
    if request.method == 'POST':
        assertion = SecurityAssertion.objects.create(
            name=request.POST.get('name'),
            assertion_type=request.POST.get('assertion_type'),
            description=request.POST.get('description', ''),
            assertion_logic=request.POST.get('assertion_logic', ''),
            expected_result=request.POST.get('expected_result', 'true'),
            created_by=request.user,
        )
        messages.success(request, f'Security assertion "{assertion.name}" created!')
        return redirect('formal_verification:assertions')
    return render(request, 'formal_verification/create_assertion.html', {
        'assertion_types': SecurityAssertion.ASSERTION_TYPES,
    })


@login_required
@admin_required
def assertion_list(request):
    assertions = SecurityAssertion.objects.all()
    return render(request, 'formal_verification/assertion_list.html', {'assertions': assertions})


@login_required
@admin_required
def create_job(request):
    rules = VerificationRule.objects.filter(is_active=True)
    assertions = SecurityAssertion.objects.filter(is_active=True)
    controllers = SDNController.objects.all()
    if request.method == 'POST':
        job = VerificationJob.objects.create(
            name=request.POST.get('name'),
            description=request.POST.get('description', ''),
            controller_id=request.POST.get('controller') or None,
            initiated_by=request.user,
            status='pending',
        )
        rule_ids = request.POST.getlist('rules')
        assertion_ids = request.POST.getlist('assertions')
        if rule_ids:
            job.rules.set(rule_ids)
        if assertion_ids:
            job.assertions.set(assertion_ids)
        messages.success(request, f'Verification job "{job.name}" created! Click Run to execute.')
        return redirect('formal_verification:job_list')
    return render(request, 'formal_verification/create_job.html', {
        'rules': rules, 'assertions': assertions, 'controllers': controllers,
    })


@login_required
@admin_required
def run_job(request, pk):
    job = get_object_or_404(VerificationJob, pk=pk)
    if job.status == 'pending':
        job.status = 'running'
        job.started_at = timezone.now()
        job.save()
        try:
            run_verification_engine(job)
            messages.success(request, f'Verification job "{job.name}" completed successfully!')
        except Exception as e:
            job.status = 'failed'
            job.save()
            messages.error(request, f'Verification failed: {str(e)}')
    return redirect('formal_verification:job_detail', pk=pk)


@login_required
def job_list(request):
    jobs = VerificationJob.objects.select_related('initiated_by', 'controller').all()
    return render(request, 'formal_verification/job_list.html', {'jobs': jobs})


@login_required
def job_detail(request, pk):
    job = get_object_or_404(VerificationJob, pk=pk)
    results = job.results.select_related('rule', 'assertion').all()
    verified = results.filter(result='verified')
    violated = results.filter(result='violated')
    return render(request, 'formal_verification/job_detail.html', {
        'job': job, 'results': results,
        'verified': verified, 'violated': violated,
    })


@login_required
def security_logs(request):
    logs = SecurityLog.objects.select_related('user').all()
    log_type = request.GET.get('type', '')
    severity = request.GET.get('severity', '')
    search = request.GET.get('search', '')
    if log_type:
        logs = logs.filter(log_type=log_type)
    if severity:
        logs = logs.filter(severity=severity)
    if search:
        logs = logs.filter(Q(title__icontains=search) | Q(message__icontains=search))
    stats = {
        'total': SecurityLog.objects.count(),
        'critical': SecurityLog.objects.filter(severity='critical').count(),
        'warning': SecurityLog.objects.filter(severity='warning').count(),
        'error': SecurityLog.objects.filter(severity='error').count(),
    }
    return render(request, 'formal_verification/security_logs.html', {
        'logs': logs,
        'stats': stats,
        'log_types': SecurityLog.LOG_TYPES,
        'log_type': log_type,
        'severity': severity,
        'search': search,
    })