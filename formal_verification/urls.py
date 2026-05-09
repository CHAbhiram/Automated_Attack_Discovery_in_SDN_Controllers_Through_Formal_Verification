from django.urls import path
from . import views

app_name = 'formal_verification'

urlpatterns = [
    path('', views.verification_dashboard, name='dashboard'),
    path('rules/', views.rule_list, name='rules'),
    path('rules/create/', views.create_rule, name='create_rule'),
    path('assertions/', views.assertion_list, name='assertions'),
    path('assertions/create/', views.create_assertion, name='create_assertion'),
    path('jobs/', views.job_list, name='job_list'),
    path('jobs/create/', views.create_job, name='create_job'),
    path('jobs/<int:pk>/', views.job_detail, name='job_detail'),
    path('jobs/<int:pk>/run/', views.run_job, name='run_job'),
    path('logs/', views.security_logs, name='security_logs'),
]