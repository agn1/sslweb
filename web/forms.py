# -*- coding: utf-8 -*-
from django import forms
from django.db import connections
from sslmanager import SslManager, check_zone
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
        with open('rootca/'+self.cleaned_data['roots']) as f:
            roots = ''.join(f.readlines())
        return {'crt': roots, 'responseText': 'Ok'}

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
            if 'crt' in data:
                if data['crt'] != 'Empty':
                    data['issuer'] = self.get_issuer(data['crt'])
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

    @check_zone
    def deletessl(self):
        zone = self.cleaned_data['zone'].encode('idna')
        self.logger(self.user.username, 'Delete SSL %s' % zone)
        result = {'responseText': 'Ok'}
        sql_data = self.db.load_object('''SELECT customer_id, server
            FROM billing.vhosts WHERE idn_name="{0}" LIMIT 1;'''.format(self.cleaned_data['zone']))
        if sql_data:
            if self.cleaned_data['delencrypt']:
                sql = '''DELETE FROM billing.adv_services  WHERE service_type="85"
                    AND customer_id="{0}" AND (requested_data="{1}" OR requested_data="");'''.format(
                    sql_data['customer_id'], zone)
                self.db.set_query(sql)
            try:
                self.soap_delete_zone(sql_data['server'], zone)
            except Exception as e:
                result['errors'] = 'Ошибка удаления сертификата. SOAP failed'
                self.logger(self.user.username, str(e))
                self.logger(self.user.username, 'Delete soap failed for %s' % zone)
        else:
            self.logger(self.user.username, 'Domain %s is not exist in database' % zone)
            result['errors'] = 'Домен не существует'
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
    sslip = forms.CharField(error_messages=my_default_errors)

    @check_zone
    def installssl(self):
        result = {'responseText': 'Ok', 'errors': False}
        zone  = self.cleaned_data['zone'].encode('idna')
        zone = zone if zone[:4] != 'www.' else zone[4:]
#        if 'timeweb' in zone:
#            result['errors'] =  'Атата по рукам'
#            self.logger(self.user.username, 'ALERT! Input domain: %s' % self.cleaned_data['zone'])
        sslip = self.cleaned_data['sslip']
        password = self.cleaned_data['password']
        service_type = self.cleaned_data['service_type']
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
            for k in 'crt', 'key':
                try:
                    ## get crt and key, if it posted cut not ascii symbols else get it from database
                    data[k] = ''.join(i for i in self.cleaned_data[k] if ord(i)<128) if len(self.cleaned_data[k])>0 else self.crypter.decrypt(bytes(data[k]))
                except Exception as e:
                    print(str(e))
                    result['errors'] = 'Отсутствует %s для установки' % k
                    self.logger(self.user.username, 'There is no %s for %s' % (k, zone))
                if 'ENCRYPTED' in key and password:
                    data['key'] = self.delete_passphrase_from_key(data['key'], password)
                    if data['key'] is None:
                        result['errors'] = 'Не удалось удалить пароль из ключа'
                        self.logger(self.user.username, 'delete passphrase from key failed')
             if 'ip' in data and sslip != 'newip':
                if sslip == 'serverip':
                    data['ip'] = self.db.load_object('SELECT ip FROM billing.servers WHERE name="%s"' % data['server'])['ip']
                elif not data['ip'] and sslip == 'currentip':
                    result['errors'] = 'Домен не привязан к выделенному адресу в дополнительных услугах'
                    self.logger(self.user.username, 'No additional ip %s' % zone)

        else:
            result['errors'] = 'Домен не привязан к сайту'
            self.logger(self.user.username, 'Thereis no data for %s' % zone)
        if not result['errors']:
            if self.check_idn_name(zone):
                if self.check_associate_cert_with_private_key(data['crt'], data['key']):
                    self.logger(self.user.username, 'domain: %s , newip: %s , service_type: %s, start install ssl' % (zone, sslip, service_type))
                    if sslip == 'newip':
                        target = self.db.load_object('SELECT purpose FROM billing.servers WHERE name="{0}"'.format(data['server']))['purpose']
                        target = target if target != 'hosting' else 'hosting-personal'
                        data['ip'] = self.get_free_ip(target)
                        if data['ip']:
                            self.logger(self.user.username, 'New ip is: %s' % data['ip'])
                            self.soap_add_ip(data['ip'], data['server'], data['customer_id'])
                            self.update_a_dns(zone, data['ip'])
                            self.update_ip_id(zone, data['ip'])
                            result['responseText'] = 'Ok'
                        else:
                            result['errors'] = 'Не удалось выделить новый ip адрес'
                            self.logger(self.user.username, 'No new ip, domain: %s' % zone)
                    if not result['errors']:
                        self.update_adv_services(zone, data['ip'], data['customer_id'], service_type)
                        self.update_ssl_storage(zone, self.crypter.encrypt(bytes(data['key'])), self.crypter.encrypt(bytes(data['crt'])))
                        if data['crt'].count('BEGIN CERTIFICATE') == 1:
                            data['crt'] = self.add_root_certs(data['crt'])
                        self.logger(self.user.username, 'domain : %s , ip : %s , server : %s , send soap install ssl' % (zone, data['ip'], data['server']))
                        self.soap_install_sll(data['server'], zone, data['directory'], data['ip'], data['crt'], data['key'], data['php_version'])
                else:
                    result['errors'] = 'Ошибка соответствия сертификата и ключа'
                    self.logger(self.user.username, 'Check associate key and crt failed. %s' % zone)
            else:
                result['errors'] = 'Поле idn.name не соответствует fqdn'
                self.logger(self.user.username, 'IDN check failed. %s' % zone)
        print(result['errors'])
        return result
