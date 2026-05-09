from django.db import models
from authentication.models import CustomUser
from network_model.models import SDNController, SDNSwitch, SDNHost

class AttackScenario(models.Model):
    ATTACK_TYPES = (
        ('arp_spoofing', 'ARP Spoofing'),
        ('dos_flood', 'DoS Flood Attack'),
        ('topology_poisoning', 'Topology Poisoning'),
        ('packet_injection', 'Packet Injection'),
        ('controller_saturation', 'Controller Saturation'),
        ('flow_table_overflow', 'Flow Table Overflow'),
        ('man_in_middle', 'Man in the Middle'),
    )
    STATUS_CHOICES = (('pending', 'Pending'), ('running', 'Running'),
                      ('completed', 'Completed'), ('failed', 'Failed'))
    SEVERITY_CHOICES = (('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low'))

    name = models.CharField(max_length=200)
    attack_type = models.CharField(max_length=50, choices=ATTACK_TYPES)
    description = models.TextField()
    target_controller = models.ForeignKey(SDNController, on_delete=models.SET_NULL, null=True, blank=True)
    target_switch = models.ForeignKey(SDNSwitch, on_delete=models.SET_NULL, null=True, blank=True)
    attacker_host = models.ForeignKey(SDNHost, on_delete=models.SET_NULL, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    feasibility_score = models.FloatField(default=0.0)
    impact_score = models.FloatField(default=0.0)
    success_rate = models.FloatField(default=0.0)
    created_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    executed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.attack_type})"

class SimulationResult(models.Model):
    scenario = models.OneToOneField(AttackScenario, on_delete=models.CASCADE, related_name='result')
    is_successful = models.BooleanField(default=False)
    packets_sent = models.IntegerField(default=0)
    packets_dropped = models.IntegerField(default=0)
    affected_flows = models.IntegerField(default=0)
    compromised_nodes = models.JSONField(default=list)
    attack_vector = models.TextField()
    timeline = models.JSONField(default=list)
    recommendations = models.JSONField(default=list)
    raw_output = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Result: {self.scenario.name}"