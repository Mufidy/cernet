"""offlineView URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
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
from classifier import views as classifier_view

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^$', classifier_view.index),
    url(r'^getData', classifier_view.getData),
    url(r'^trainModel', classifier_view.trainModel),
    url(r'^distributeModel', classifier_view.distributeModel),

    url(r'^ajaxDistribute', classifier_view.ajaxDistribute, name='ajaxDistribute'),
    url(r'^ajaxTrainModel', classifier_view.ajaxTrainModel, name='ajaxTrainModel'),
    url(r'^ajaxTestModel', classifier_view.ajaxTestModel, name='ajaxTestModel'),
    url(r'^ajaxGetData', classifier_view.ajaxGetData, name='ajaxGetData')
]
