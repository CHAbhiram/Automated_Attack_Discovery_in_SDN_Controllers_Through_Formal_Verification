from django.urls import path
from . import views

app_name = 'attack_simulation'

urlpatterns = [
    path('', views.simulation_list, name='list'),
    path('create/', views.create_scenario, name='create'),
    path('run/<int:pk>/', views.run_attack, name='run'),
    path('result/<int:pk>/', views.simulation_result, name='result'),
]