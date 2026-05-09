from django.contrib import admin
from .models import VerificationRule, SecurityAssertion, VerificationJob, VerificationResult, SecurityLog
admin.site.register(VerificationRule)
admin.site.register(SecurityAssertion)
admin.site.register(VerificationJob)
admin.site.register(VerificationResult)
admin.site.register(SecurityLog)
