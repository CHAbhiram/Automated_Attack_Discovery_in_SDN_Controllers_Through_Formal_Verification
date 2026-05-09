from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.contrib import messages
import random
from .models import AttackScenario, SimulationResult
from network_model.models import SDNController, SDNSwitch, SDNHost


def run_simulation(scenario):
    attack_params = {
        'arp_spoofing':          {'success_rate': 0.75, 'packets': 5000,   'impact': 7.5},
        'dos_flood':             {'success_rate': 0.85, 'packets': 50000,  'impact': 9.0},
        'topology_poisoning':    {'success_rate': 0.60, 'packets': 1000,   'impact': 8.5},
        'packet_injection':      {'success_rate': 0.70, 'packets': 3000,   'impact': 7.0},
        'controller_saturation': {'success_rate': 0.80, 'packets': 100000, 'impact': 9.5},
        'flow_table_overflow':   {'success_rate': 0.65, 'packets': 2000,   'impact': 8.0},
        'man_in_middle':         {'success_rate': 0.55, 'packets': 800,    'impact': 8.8},
    }
    params = attack_params.get(scenario.attack_type, {'success_rate': 0.5, 'packets': 1000, 'impact': 5.0})
    noise = random.uniform(-0.1, 0.1)
    success = (params['success_rate'] + noise) > 0.5
    packets = int(params['packets'] * random.uniform(0.8, 1.2))
    dropped = int(packets * random.uniform(0.1, 0.3))
    hosts = list(SDNHost.objects.values_list('ip_address', flat=True)[:3])
    timeline = [
        {'time': '0s',  'event': 'Attack initiated — reconnaissance started',         'phase': 'setup'},
        {'time': '2s',  'event': 'Network topology mapped by attacker',                'phase': 'recon'},
        {'time': '5s',  'event': f'Target identified via {scenario.attack_type}',      'phase': 'recon'},
        {'time': '8s',  'event': 'Exploit payload crafted and injected',               'phase': 'exploit'},
        {'time': '12s', 'event': 'Attack vector executed on data plane',               'phase': 'exploit'},
        {'time': '15s', 'event': f'Result: {"SUCCESS — network compromised" if success else "BLOCKED — defenses held"}', 'phase': 'impact'},
    ]
    recommendations = [
        'Enable port security and dynamic ARP inspection on all switches',
        'Implement rate limiting on SDN control plane messages',
        'Deploy anomaly-based IDS at the controller level',
        'Use TLS mutual authentication for controller-switch communication',
        'Enable real-time flow table monitoring and alerting',
        'Segment network with strict inter-VLAN routing policies',
    ]
    SimulationResult.objects.filter(scenario=scenario).delete()
    result = SimulationResult.objects.create(
        scenario=scenario,
        is_successful=success,
        packets_sent=packets,
        packets_dropped=dropped,
        affected_flows=random.randint(5, 50),
        compromised_nodes=hosts,
        attack_vector=f"Attacker exploits {scenario.get_attack_type_display()} vulnerability via SDN data plane, targeting {scenario.target_controller or 'network infrastructure'}.",
        timeline=timeline,
        recommendations=recommendations[:4],
        raw_output=f"Simulation completed at {timezone.now()}. Success={success}. Packets sent={packets}, dropped={dropped}.",
    )
    scenario.status = 'completed'
    scenario.success_rate = round(params['success_rate'] + noise, 2)
    scenario.feasibility_score = round(random.uniform(6.0, 9.5), 1)
    scenario.impact_score = round(params['impact'] + random.uniform(-0.5, 0.5), 1)
    scenario.executed_at = timezone.now()
    scenario.save()
    return result


@login_required
def simulation_list(request):
    scenarios = AttackScenario.objects.select_related('created_by').prefetch_related('result').all()
    return render(request, 'attack_simulation/simulation_list.html', {
        'scenarios': scenarios,
        'total': scenarios.count(),
        'completed': scenarios.filter(status='completed').count(),
        'successful': scenarios.filter(result__is_successful=True).count(),
        'pending': scenarios.filter(status='pending').count(),
        'can_create': request.user.role in ['admin', 'analyst'],
        'can_run': request.user.role == 'admin',
    })


@login_required
def run_attack(request, pk):
    if request.user.role != 'admin':
        messages.error(request, 'Only admins can run simulations.')
        return redirect('attack_simulation:list')
    scenario = get_object_or_404(AttackScenario, pk=pk)
    if scenario.status in ['pending', 'failed']:
        scenario.status = 'running'
        scenario.save()
        try:
            run_simulation(scenario)
            messages.success(request, f'Simulation "{scenario.name}" completed!')
        except Exception as e:
            scenario.status = 'failed'
            scenario.save()
            messages.error(request, f'Simulation failed: {str(e)}')
    return redirect('attack_simulation:result', pk=pk)


@login_required
def simulation_result(request, pk):
    scenario = get_object_or_404(AttackScenario, pk=pk)
    result = getattr(scenario, 'result', None)
    return render(request, 'attack_simulation/result.html', {
        'scenario': scenario,
        'result': result,
        'can_run': request.user.role == 'admin',
    })


@login_required
def create_scenario(request):
    if request.user.role not in ['admin', 'analyst']:
        messages.error(request, 'You do not have permission to create simulations.')
        return redirect('attack_simulation:list')
    controllers = SDNController.objects.all()
    switches = SDNSwitch.objects.all()
    hosts = SDNHost.objects.all()
    if request.method == 'POST':
        scenario = AttackScenario.objects.create(
            name=request.POST.get('name'),
            attack_type=request.POST.get('attack_type'),
            description=request.POST.get('description', ''),
            severity=request.POST.get('severity', 'medium'),
            target_controller_id=request.POST.get('target_controller') or None,
            target_switch_id=request.POST.get('target_switch') or None,
            attacker_host_id=request.POST.get('attacker_host') or None,
            created_by=request.user,
        )
        messages.success(request, f'Scenario "{scenario.name}" created! Admin can now run it.')
        return redirect('attack_simulation:list')
    return render(request, 'attack_simulation/create_scenario.html', {
        'controllers': controllers,
        'switches': switches,
        'hosts': hosts,
        'attack_types': AttackScenario.ATTACK_TYPES,
    })
