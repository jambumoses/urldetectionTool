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
    #category
    #path('tag/<str:category>', views.categories, name="categories"),
    #details / news
    #path('articles/', views.topArticles, name="topArticles"),
    #path('article/<str:headline>', views.articles, name="articles"), #(P<article_id>\w{0,50})/$
    #path('article/<str:headline>/video', views.videoArticles, name="videoArticles"),
    # all about a specific sport
    #path('sports/', views.sportsPage, name="sportspage"),
    #path('sports/<str:sport>', views.sports, name="sports"),
    #about the author and related publishes
    #path('author/<str:username>', views.author, name="author"),
    
    #contact
    #path('contact', views.contact, name="contact"),

    #news page
    #path('news/', views.news, name="news"),

    #path('entertainment/', views.entertainment, name="entertainment"),
    #path('entertainment/<str:tag>', views.entertainmentSpecific, name="entertainmentSpecific"),

]

#TODO
""" 
    404 route
 """