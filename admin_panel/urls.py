from django.urls import path
from . import views

app_name = 'admin_panel'

urlpatterns = [
    path('', views.admin_dashboard, name='dashboard'),
    path('users/', views.user_management, name='user_management'),
    path('users/create/', views.create_user, name='create_user'),
    path('users/toggle/<int:pk>/', views.toggle_user, name='toggle_user'),
    path('users/role/<int:pk>/', views.change_user_role, name='change_role'),
    path('network/', views.network_config, name='network_config'),
    path('openflow/', views.openflow_settings, name='openflow_settings'),
    path('security/', views.security_policies, name='security_policies'),
    path('monitoring/', views.system_monitoring, name='system_monitoring'),
]