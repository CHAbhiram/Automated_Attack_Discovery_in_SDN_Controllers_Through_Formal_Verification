from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import SDNController, SDNSwitch, SDNHost, CommunicationFlow
import json

@login_required
def topology_view(request):
    controllers = SDNController.objects.prefetch_related('switches__hosts').all()
    flows = CommunicationFlow.objects.select_related('source_host', 'dest_host').all()
    context = {
        'controllers': controllers,
        'flows': flows,
        'total_controllers': controllers.count(),
        'total_switches': SDNSwitch.objects.count(),
        'total_hosts': SDNHost.objects.count(),
        'total_flows': flows.count(),
        'active_controllers': controllers.filter(status='active').count(),
        'compromised_nodes': SDNSwitch.objects.filter(status='compromised').count() + SDNHost.objects.filter(is_malicious=True).count(),
    }
    return render(request, 'network_model/topology.html', context)

@login_required
def topology_json(request):
    nodes = []
    edges = []
    controllers = SDNController.objects.all()
    for ctrl in controllers:
        nodes.append({'id': f'ctrl_{ctrl.id}', 'label': ctrl.name, 'type': 'controller',
                      'ip': ctrl.ip_address, 'status': ctrl.status, 'group': 'controller'})
        for switch in ctrl.switches.all():
            nodes.append({'id': f'sw_{switch.id}', 'label': switch.name, 'type': 'switch',
                          'ip': switch.ip_address, 'status': switch.status, 'group': 'switch'})
            edges.append({'from': f'ctrl_{ctrl.id}', 'to': f'sw_{switch.id}', 'type': 'control'})
            for host in switch.hosts.all():
                nodes.append({'id': f'host_{host.id}', 'label': host.name, 'type': 'host',
                              'ip': host.ip_address, 'malicious': host.is_malicious, 'group': 'host'})
                edges.append({'from': f'sw_{switch.id}', 'to': f'host_{host.id}', 'type': 'data'})
    for flow in CommunicationFlow.objects.select_related('source_host', 'dest_host').all():
        edges.append({'from': f'host_{flow.source_host.id}', 'to': f'host_{flow.dest_host.id}',
                      'type': 'flow', 'protocol': flow.protocol, 'suspicious': flow.is_suspicious})
    return JsonResponse({'nodes': nodes, 'edges': edges})

@login_required
def switch_list(request):
    switches = SDNSwitch.objects.select_related('controller').prefetch_related('hosts').all()
    return render(request, 'network_model/switch_list.html', {'switches': switches})

@login_required
def host_list(request):
    hosts = SDNHost.objects.select_related('switch__controller').all()
    return render(request, 'network_model/host_list.html', {'hosts': hosts})

@login_required
def flow_list(request):
    flows = CommunicationFlow.objects.select_related('source_host', 'dest_host').all()
    return render(request, 'network_model/flow_list.html', {'flows': flows})