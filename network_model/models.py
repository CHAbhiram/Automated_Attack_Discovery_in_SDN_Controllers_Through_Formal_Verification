from django.db import models
from authentication.models import CustomUser

class SDNController(models.Model):
    STATUS_CHOICES = (('active', 'Active'), ('inactive', 'Inactive'), ('compromised', 'Compromised'))
    name = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    port = models.IntegerField(default=6633)
    controller_type = models.CharField(max_length=50, default='OpenDaylight')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    version = models.CharField(max_length=20, default='1.0')
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.ip_address})"

class SDNSwitch(models.Model):
    STATUS_CHOICES = (('active', 'Active'), ('inactive', 'Inactive'), ('compromised', 'Compromised'))
    controller = models.ForeignKey(SDNController, on_delete=models.CASCADE, related_name='switches')
    name = models.CharField(max_length=100)
    dpid = models.CharField(max_length=50, unique=True)
    ip_address = models.GenericIPAddressField()
    of_version = models.CharField(max_length=10, default='1.3')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    flow_table_size = models.IntegerField(default=1000)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} (DPID: {self.dpid})"

class SDNHost(models.Model):
    switch = models.ForeignKey(SDNSwitch, on_delete=models.CASCADE, related_name='hosts')
    name = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    mac_address = models.CharField(max_length=17)
    port_number = models.IntegerField()
    os_type = models.CharField(max_length=50, blank=True)
    is_malicious = models.BooleanField(default=False)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.ip_address})"

class CommunicationFlow(models.Model):
    PROTOCOL_CHOICES = (('TCP', 'TCP'), ('UDP', 'UDP'), ('ICMP', 'ICMP'), ('OpenFlow', 'OpenFlow'))
    source_host = models.ForeignKey(SDNHost, on_delete=models.CASCADE, related_name='outgoing_flows')
    dest_host = models.ForeignKey(SDNHost, on_delete=models.CASCADE, related_name='incoming_flows')
    protocol = models.CharField(max_length=20, choices=PROTOCOL_CHOICES)
    src_port = models.IntegerField(null=True, blank=True)
    dst_port = models.IntegerField(null=True, blank=True)
    bandwidth = models.FloatField(default=0.0)
    is_suspicious = models.BooleanField(default=False)
    packet_count = models.BigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.source_host} -> {self.dest_host} ({self.protocol})"