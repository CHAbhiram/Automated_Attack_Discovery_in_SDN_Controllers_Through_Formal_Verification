from django.db import models
from authentication.models import CustomUser

class Report(models.Model):
    REPORT_TYPES = (
        ('vulnerability', 'Vulnerability Report'),
        ('simulation', 'Simulation Report'),
        ('full', 'Full Security Report'),
        ('network', 'Network Topology Report'),
    )
    STATUS_CHOICES = (('generating', 'Generating'), ('ready', 'Ready'), ('failed', 'Failed'))
    title = models.CharField(max_length=200)
    report_type = models.CharField(max_length=30, choices=REPORT_TYPES)
    generated_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='generating')
    file_path = models.FileField(upload_to='reports/', blank=True, null=True)
    summary = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} ({self.report_type})"

    class Meta:
        ordering = ['-created_at']