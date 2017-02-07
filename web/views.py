from django.http import JsonResponse
from django.views.generic import RedirectView
from django.views.generic.edit import FormView
from django.views.generic.base import TemplateView
from django.views.generic.list import ListView
from web.forms import GenerateForm, ShowForm, DeleteForm, InstallForm, LoginForm, RootsForm
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.shortcuts import render, redirect
from django.utils import timezone
from django.contrib.auth import logout


decorators = [login_required(login_url='/login/')]

@method_decorator(decorators, name='dispatch')
class LogoutView(RedirectView):
    url = '/login/'

    def get(self, request, *args, **kwargs):
        logout(request)
        return super(LogoutView, self).get(request, *args, **kwargs)


@method_decorator(decorators, name='dispatch')
class IndexView(TemplateView):
    template_name = 'index.html'


class LoginView(FormView):
    form_class = LoginForm
    template_name = 'login.html'
    success_url = '/'

    def form_valid(self, form):
        user = form.authenticate(self.request)
        return super(LoginView, self).form_valid(form)


class AjaxableResponseMixin(object):
    """
    Mixin to add AJAX support to a form.
    Must be used with an object-based FormView (e.g. CreateView)
    """
    def form_invalid(self, form):
        response = super(AjaxableResponseMixin, self).form_invalid(form)
        if self.request.is_ajax():
            return JsonResponse(form.errors, status=400)
        else:
            return response

    def form_valid(self, form):
        # We make sure to call the parent's form_valid() method because
        # it might do some processing (in the case of CreateView, it will
        # call form.save() for example).
        response = super(AjaxableResponseMixin, self).form_valid(form)
        if self.request.is_ajax():
            return JsonResponse(self.jsondata)
        else:
            return response


@method_decorator(decorators, name='dispatch')
class GenerateCsrView(AjaxableResponseMixin, FormView):
    form_class = GenerateForm
    template_name = 'index.html'
    success_url = '/'

    def form_valid(self, form):
        # This method is called when valid form data has been POSTed.
        # It should return an HttpResponse.
        self.jsondata = {}
        self.jsondata['csr'] = str(form.gencsr()['csr'])
        return super(GenerateCsrView, self).form_valid(form)


@method_decorator(decorators, name='dispatch')
class ShowView(AjaxableResponseMixin, FormView):
    form_class = ShowForm
    template_name = 'index.html'
    success_url = '/'

    def form_valid(self, form):
        self.jsondata = form.showssl()
        self.jsondata['crt'] =  str(self.jsondata['crt'])
        self.jsondata['key'] =str(self.jsondata['key'])
        return super(ShowView, self).form_valid(form)


@method_decorator(decorators, name='dispatch')
class DeleteView(AjaxableResponseMixin, FormView):
        form_class = DeleteForm
        template_name = 'index.html'
        success_url = '/'

        def form_valid(self, form):
            self.jsondata = form.deletessl()
            return super(DeleteView, self).form_valid(form)


@method_decorator(decorators, name='dispatch')
class InstallView(AjaxableResponseMixin, FormView):
        form_class = InstallForm
        template_name = 'index.html'
        success_url = '/'

        def form_valid(self, form):
            self.jsondata = form.installssl()
            return super(InstallView, self).form_valid(form)


@method_decorator(decorators, name='dispatch')
class RootsView(AjaxableResponseMixin, FormView):
        form_class = RootsForm
        template_name = 'index.html'
        success_url = '/'

        def form_valid(self, form):
            self.jsondata = form.showroots()
            return super(RootsView, self).form_valid(form)
