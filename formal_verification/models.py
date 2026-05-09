from django.db import models
from authentication.models import CustomUser
from network_model.models import SDNController, SDNSwitch

class VerificationRule(models.Model):
    RULE_TYPES = (
        ('reachability', 'Reachability Property'),
        ('isolation', 'Network Isolation'),
        ('loop_freedom', 'Loop Freedom'),
        ('consistency', 'Flow Consistency'),
        ('access_control', 'Access Control Policy'),
        ('waypointing', 'Waypointing'),
        ('blackhole', 'Blackhole Detection'),
    )
    SEVERITY_CHOICES = (('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low'))

    name = models.CharField(max_length=200)
    rule_type = models.CharField(max_length=30, choices=RULE_TYPES)
    description = models.TextField()
    formal_expression = models.TextField(help_text='Formal logic expression or assertion')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    controller = models.ForeignKey(SDNController, on_delete=models.SET_NULL, null=True, blank=True)
    switch = models.ForeignKey(SDNSwitch, on_delete=models.SET_NULL, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.rule_type})"

    class Meta:
        ordering = ['-created_at']


class SecurityAssertion(models.Model):
    ASSERTION_TYPES = (
        ('invariant', 'Network Invariant'),
        ('safety', 'Safety Property'),
        ('liveness', 'Liveness Property'),
        ('isolation', 'Isolation Assertion'),
        ('authentication', 'Authentication Assertion'),
    )
    name = models.CharField(max_length=200)
    assertion_type = models.CharField(max_length=30, choices=ASSERTION_TYPES)
    description = models.TextField()
    assertion_logic = models.TextField(help_text='Formal assertion in predicate logic')
    expected_result = models.CharField(max_length=10, choices=(('true', 'True'), ('false', 'False')), default='true')
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.assertion_type})"


class VerificationJob(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    )
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    rules = models.ManyToManyField(VerificationRule, related_name='jobs')
    assertions = models.ManyToManyField(SecurityAssertion, related_name='jobs', blank=True)
    controller = models.ForeignKey(SDNController, on_delete=models.SET_NULL, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    initiated_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    total_properties = models.IntegerField(default=0)
    verified_count = models.IntegerField(default=0)
    violated_count = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.name} ({self.status})"

    class Meta:
        ordering = ['-created_at']


class VerificationResult(models.Model):
    RESULT_CHOICES = (('verified', 'Verified'), ('violated', 'Violated'), ('unknown', 'Unknown'))

    job = models.ForeignKey(VerificationJob, on_delete=models.CASCADE, related_name='results')
    rule = models.ForeignKey(VerificationRule, on_delete=models.SET_NULL, null=True, blank=True)
    assertion = models.ForeignKey(SecurityAssertion, on_delete=models.SET_NULL, null=True, blank=True)
    result = models.CharField(max_length=20, choices=RESULT_CHOICES)
    property_name = models.CharField(max_length=200)
    details = models.TextField()
    counterexample = models.TextField(blank=True)
    execution_time_ms = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.property_name}: {self.result}"


class SecurityLog(models.Model):
    LOG_TYPES = (
        ('auth', 'Authentication'),
        ('config_change', 'Configuration Change'),
        ('verification', 'Verification'),
        ('alert', 'Security Alert'),
        ('simulation', 'Simulation'),
        ('policy', 'Policy Change'),
        ('access', 'Access Control'),
    )
    SEVERITY_CHOICES = (('info', 'Info'), ('warning', 'Warning'), ('error', 'Error'), ('critical', 'Critical'))

    log_type = models.CharField(max_length=20, choices=LOG_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='info')
    title = models.CharField(max_length=200)
    message = models.TextField()
    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    component = models.CharField(max_length=100, blank=True)
    extra_data = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.severity.upper()}] {self.title}"

    class Meta:
        ordering = ['-created_at']
        