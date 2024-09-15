from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name="home"),
    path('dashboard', views.dashboard, name="dashboard"),
    path('results', views.results, name="results"),
    path('report', views.report, name="report"),
    path('docs', views.docs, name="docs"),
    path('search/', views.search, name="search"),
    path('result/<int:id>', views.singleResult, name="result"),
]

#TODO
""" 
    404 route
 """