from django.urls import path
from . import views

app_name = 'network_model'

urlpatterns = [
    path('', views.topology_view, name='topology'),
    path('api/topology/', views.topology_json, name='topology_json'),
    path('switches/', views.switch_list, name='switch_list'),
    path('hosts/', views.host_list, name='host_list'),
    path('flows/', views.flow_list, name='flow_list'),
]