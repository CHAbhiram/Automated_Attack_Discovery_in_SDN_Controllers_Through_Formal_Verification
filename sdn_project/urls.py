from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('authentication.urls')),
    path('dashboard/', include('dashboard.urls')),
    path('network/', include('network_model.urls')),
    path('vulnerabilities/', include('vulnerability_analysis.urls')),
    path('simulations/', include('attack_simulation.urls')),
    path('reports/', include('reports.urls')),
    path('admin-panel/', include('admin_panel.urls')),
    path('verification/', include('formal_verification.urls')),   # ADD THIS
    path('', RedirectView.as_view(url='/dashboard/', permanent=False)),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
