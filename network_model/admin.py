from django.contrib import admin
from .models import SDNController, SDNSwitch, SDNHost, CommunicationFlow
admin.site.register(SDNController)
admin.site.register(SDNSwitch)
admin.site.register(SDNHost)
admin.site.register(CommunicationFlow)