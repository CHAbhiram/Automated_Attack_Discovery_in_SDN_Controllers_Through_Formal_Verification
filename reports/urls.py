from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    path('', views.report_list, name='list'),
    path('generate/', views.generate_report, name='generate'),
    path('download/<int:pk>/', views.download_report, name='download'),
    path('<int:pk>/', views.report_detail, name='detail'),
]