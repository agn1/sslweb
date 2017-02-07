"""sslweb URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""

from django.conf.urls import url
from django.contrib import admin
from web.views import IndexView, GenerateCsrView, ShowView, DeleteView, InstallView, LoginView, LogoutView, RootsView
from django.contrib.auth import logout

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^$', IndexView.as_view()),
    url(r'^generate', GenerateCsrView.as_view()),
    url(r'^show', ShowView.as_view()),
    url(r'^delete', DeleteView.as_view()),
    url(r'^install', InstallView.as_view()),
    url(r'^roots', RootsView.as_view()),
    url(r'^login', LoginView.as_view()),
    url(r'^logout/$', LogoutView.as_view()),
]
