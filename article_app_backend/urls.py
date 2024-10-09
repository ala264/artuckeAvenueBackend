"""
URL configuration for article_app_backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from article_app import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("admin/", admin.site.urls),
    path('insert-user/', views.insert_user),
    path('insert-completed-article/', views.insert_completed_article),
    path('get-completed-articles/', views.get_completed_articles),
    path('insert-draft-article/', views.insert_draft_article),
    path('get-draft-articles/', views.get_draft_articles),
    path('sign-in/', views.sign_in),
    path('delete-completed-article/<int:article_id>/', views.deleted_completed_article),  
    path('delete-draft-article/<int:article_id>/', views.deleted_draft_article),   
    path('update-draft-article/<int:article_id>/', views.update_draft_article),
    path('update-completed-article/<int:article_id>/', views.update_completed_article), 
    path('get-article-by-username-and-name/', views.get_article_by_username_and_name, name='get_article_by_username_and_name'),
    #path('test/', views.test),
    path('check-session/', views.check_session),
    path('get-session-data/', views.getSessionData),
    path('get-author-info/', views.getAuthorInfo),
    path('insert-profile-pic/', views.insertProfilePic),
    path('get-articles-by-username/', views.get_articles_by_username),
    path('get-completed-articles-categories/', views.get_completed_articles_categories),
    path('signup/', views.signup_view),
    path('get-articles-categories/', views.get_articles_categories),
    path('get-drafts-by-username/', views.get_drafts_by_username),
    path('submit-author-response/', views.submit_author_response)
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

