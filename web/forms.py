# -*- coding: utf-8 -*-
from django import forms
from django.db import connections
from ssllib.sslmanager import SslManager
from django.contrib.auth import authenticate, login
import time

class Logger():

    def logger(self, user, msg, debug=False):
        logfile = '/var/log/install_ssl.log'
        with open(logfile, 'a') as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S") + ' : ' + user + ' : ' + msg + '\n')
        if debug:
            print(msg)


class LoginForm(forms.Form, Logger):
    my_default_errors = {
        'required': 'required',
        'invalid': 'invalid'
    }
    username = forms.CharField(max_length=30)
    password = forms.CharField(max_length=30)

    def authenticate(self, request):
        user = authenticate(username=self.cleaned_data['username'], password=self.cleaned_data['password'])
        if user:
            # If user has successfully logged, save his password in django database
            #user.set_password(self.cleaned_data['password'])
            #user.save() #ldap required groups don't work with it
            #print(user.ldap_user.group_dns)
            #print(user.ldap_user.group_names)
            login(request, user)
            self.logger(self.cleaned_data['username'], 'successfully login')
        return user


class GenerateForm(SslManager, forms.Form, Logger):
    def __init__(self, *args, **kwargs):
        forms.Form.__init__(self, *args, **kwargs)
        SslManager.__init__(self)

    my_default_errors = {
        'required': 'required',
        'invalid': 'invalid'
    }
    csrtext = forms.CharField(
        widget=forms.Textarea, required=True,
        error_messages=my_default_errors
    )

    def gencsr(self):
        self.logger(self.user.username, 'generate CSR')
        csrdata = self.parsecsr(self.cleaned_data['csrtext'])
        for i in csrdata:
            if i == '' or not self.is_ascii(i):
                csrdata.remove(i)
        csr = self.generatecsr(**csrdata)
        data = {
            'csr': self.crypter.encrypt(bytes(csr['csr'])),
            'key': self.crypter.encrypt(bytes(csr['key'])),
            'full_fqdn':  csrdata['commonname'].split()[0],
            'crt': '',
            }
        sql = '''INSERT INTO system.ssl_storage (dt, full_fqdn, `key`, csr, crt, provider, source)
            VALUES (CURRENT_TIMESTAMP, '{full_fqdn}', '{key}', '{csr}', '{crt}', 'pdr', 'manual');'''.format(**data)
        self.db.set_query(sql)
        csr['responseText'] = 'Ok'
        return csr


class RootsForm(forms.Form, SslManager, Logger):
    def __init__(self, *args, **kwargs):
        forms.Form.__init__(self, *args, **kwargs)
        SslManager.__init__(self)
    my_default_errors = {
        'required': 'required',
        'invalid': 'invalid'
    }
    roots = forms.CharField(error_messages=my_default_errors)

    def showroots(self):
        self.logger(self.user.username, 'show roots CERTS')
        roots = self.cleaned_data['roots']
        return {'crt': self.add_root_certs('', roots), 'responseText': 'Ok'}

class ShowForm(forms.Form, SslManager, Logger):
    def __init__(self, *args, **kwargs):
        forms.Form.__init__(self, *args, **kwargs)
        SslManager.__init__(self)

    my_default_errors = {
        'required': 'required',
        'invalid': 'invalid'
    }
    zone = forms.CharField(error_messages=my_default_errors)

    def showssl(self):
        zone  = self.cleaned_data['zone'].encode('idna')
        data = {'responseText': 'Ok'}
        self.logger(self.user.username, 'show SSL %s' % zone)
        sql = '''SELECT crt, `key` FROM system.ssl_storage WHERE full_fqdn = "{0}" ORDER BY dt DESC LIMIT 1;'''.format(zone)
        encrypted = self.db.load_object(sql)
        if encrypted:
            for key in encrypted:
                if len(encrypted[key]) > 0:
                    try:
                        data[key] = self.crypter.decrypt(bytes(encrypted[key]))
                    except:
                        self.logger(self.user.username, 'error: decrypt %s of %s failed' % (key, zone))
                        data[key] = 'Broken'
                else:
                    data[key] = 'Empty'
        else:
            data['errors'] = 'Domain not exist'
        return data


class DeleteForm(SslManager, forms.Form, Logger):
    def __init__(self, *args, **kwargs):
        forms.Form.__init__(self, *args, **kwargs)
        SslManager.__init__(self)

    my_default_errors = {
        'required': 'required',
        'invalid': 'invalid'
    }
    zone = forms.CharField(error_messages=my_default_errors)
    delencrypt = forms.CharField(error_messages=my_default_errors, required=False)

    def deletessl(self):
        self.logger(self.user.username, 'Delete SSL %s' % self.cleaned_data['zone'])
        result = {'responseText': 'Ok'}
        sql_data = self.db.load_object('''SELECT customer_id, server
            FROM billing.vhosts WHERE fqdn="{0}" LIMIT 1;'''.format(self.cleaned_data['zone']))

        if self.cleaned_data['delencrypt']:
            print(self.cleaned_data['delencrypt'])
            if sql_data:
                print(type(sql_data))
                sql = '''DELETE FROM billing.adv_services  WHERE service_type="85"
                    AND customer_id="{0}" AND (requested_data="{1}" OR requested_data="");'''.format(
                    sql_data['customer_id'], self.cleaned_data['zone'])
                self.db.set_query(sql)
            else:
                self.logger(self.user.username, 'thereis no adv service LEt\'s Encrypt for %s' % self.cleaned_data['zone'])
                result['errors'] = 'Доп услуги Let\'s Encrypt нет'
        try:
            self.soap_delete_zone(sql_data['server'], self.cleaned_data['zone'])
        except Exception as e:
            result['errors'] = 'SOAP запрос отвалился'
            self.logger(self.user.username, 'Delete soap failed for %s' % self.cleaned_data['zone'])
        return result


class InstallForm(SslManager, forms.Form, Logger):
    def __init__(self, *args, **kwargs):
        forms.Form.__init__(self, *args, **kwargs)
        SslManager.__init__(self)

    my_default_errors = {
        'required': 'required',
        'invalid': 'invalid'
    }
    zone = forms.CharField(error_messages=my_default_errors)
    crt = forms.CharField(error_messages=my_default_errors, required=False)
    key = forms.CharField(error_messages=my_default_errors, required=False)
    service_type = forms.CharField(error_messages=my_default_errors)
    root_certs = forms.CharField(error_messages=my_default_errors, required=False)
    newip = forms.CharField(error_messages=my_default_errors, required=False)

    def installssl(self):
        result = {'responseText': 'Ok', 'errors': False}
        zone  = self.cleaned_data['zone'].encode('idna')
        zone = zone if zone[:4] != 'www.' else zone[4:]
        fqdn = zone[2:] if zone[:1] == '*' else zone
        if 'timeweb' in zone:
            result['errors'] =  'Атата по рукам'
            self.logger(self.user.username, 'Need to break arms, input domain %s' % self.cleaned_data['zone'])
        crt = self.cleaned_data['crt'] if len(self.cleaned_data['crt'])>0 else False
        key = self.cleaned_data['key'] if len(self.cleaned_data['key'])>0 else False
        newip = self.cleaned_data['newip']
        service_type = self.cleaned_data['service_type']
        root_certs = self.cleaned_data['root_certs'] if self.cleaned_data['root_certs'] != 'None' else None
        ssql = '''SELECT s.customer_id, s.directory, s.php_version, s.pagespeed_enabled, v.fqdn,
                            v.server, i.ip, cst.dealer, bs.ip as serverip, ss.provider, ss.crt, ss.key
                            FROM billing.sites s, billing.vhosts v
                            LEFT JOIN billing.servers bs ON bs.name = v.server
                            LEFT JOIN billing.ip_addr i ON i.id=v.ip_id
                            LEFT JOIN billing.customers cst ON cst.cust_login=v.customer_id
                            LEFT JOIN system.ssl_storage ss ON ss.full_fqdn=v.idn_name
                            WHERE s.id=v.site_id AND v.idn_name="{0}" ORDER BY ss.id DESC LIMIT 1;'''
        data = self.db.load_object(ssql.format(zone))
        if data:
            try:
                data['key'] = key if key else self.crypter.decrypt(bytes(data['key']))
            except:
                result['errors'] = 'Отсутствует ключ для установки'
                self.logger(self.user.username, 'Thereis no key for %s' % self.cleaned_data['zone'])
            try:
                data['crt'] = crt if crt else self.crypter.decrypt(bytes(data['crt']))
            except:
                result['errors'] = 'Отсутствует сертификат для установки'
                self.logger(self.user.username, 'Thereis no crt for %s' % self.cleaned_data['zone'])
            if 'ip' in data and not newip:
                if not data['ip'] :
                    result['errors'] = 'Домен не привязан к выделенному адресу'
                    self.logger(self.user.username, 'No additional ip %s' % self.cleaned_data['zone'])

        else:
            result['errors'] = 'Отсутствуют данные для установки'
            self.logger(self.user.username, 'Thereis no data for %s' % self.cleaned_data['zone'])

        if not result['errors']:
            if self.check_idn_name(zone):
                if self.check_associate_cert_with_private_key(data['crt'], data['key']):
                    self.logger(self.user.username, 'domain: %s , newip: %s , service_type: %s, start install ssl' % (zone, newip, service_type))
                    if newip:
                        target = self.db.load_object('SELECT purpose FROM billing.servers WHERE name="{0}"'.format(data['server']))['purpose']
                        target = target if target != 'hosting' else 'hosting-personal'
                        data['ip'] = self.get_free_ip(target)
                        if data['ip']:
                            self.logger(self.user.username, 'New ip is: %s' % data['ip'])
                            self.soap_add_ip(data['ip'], data['server'], data['customer_id'])
                            self.update_a_dns(fqdn, data['ip'])
                            self.update_ip_id(zone, data['ip'])
                        else:
                            result['errors'] = 'no new ip'
                            self.logger(self.user.username, 'No new ip, domain: %s' % self.cleaned_data['zone'])
                    if not result['errors']:
                        self.update_adv_services(fqdn, data['ip'], data['customer_id'], service_type)
                        self.update_ssl_storage(zone, self.crypter.encrypt(bytes(data['key'])), self.crypter.encrypt(bytes(data['crt'])))
                        if root_certs:
                            data['crt'] = self.add_root_certs(data['crt'], root_certs)
                        self.logger(self.user.username, 'domain : %s , ip : %s , server : %s , send soap install ssl' % (self.cleaned_data['zone'], data['ip'], data['server']))
                        self.soap_install_sll(data['server'], zone, data['directory'], data['ip'], data['crt'], data['key'], data['php_version'])
                            #time.sleep(10)
                            #if not self.check_ssl_install(fqdn, data['ip']):
                            #    result['errors'] = 'Домен не отвечает по HTTPS'
                            #    self.logger(self.user.username, 'HTTPS check failed: %s' % self.cleaned_data['zone'])
                else:
                    result['errors'] = 'Ошибка соответствия сертификата и ключа'
                    self.logger(self.user.username, 'Check associate key and crt failed. %s' % self.cleaned_data['zone'])
            else:
                result['errors'] = 'Поле idn.name не соответствует fqdn'
                self.logger(self.user.username, 'IDN check failed. %s' % self.cleaned_data['zone'])
        print(result['errors'])
        return result
