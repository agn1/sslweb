from django import forms
from django.db import connections
from ssllib.sslmanager import SslManager
from django.contrib.auth import authenticate, login


class LoginForm(forms.Form):
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
            print(user.ldap_user.group_dns)
            print(user.ldap_user.group_names)
            login(request, user)
        return user

class GenerateForm(SslManager, forms.Form):
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
        csrdata = self.parsecsr(self.cleaned_data['csrtext'])
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


class RootsForm(forms.Form, SslManager):
    def __init__(self, *args, **kwargs):
        forms.Form.__init__(self, *args, **kwargs)
        SslManager.__init__(self)
    my_default_errors = {
        'required': 'required',
        'invalid': 'invalid'
    }
    roots = forms.CharField(error_messages=my_default_errors)

    def showroots(self):
        roots = self.cleaned_data['roots']
        print(roots)
        return {'crt': self.add_root_certs('', roots), 'responseText': 'Ok'}

class ShowForm(forms.Form, SslManager):
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
        sql = '''SELECT crt, `key` FROM system.ssl_storage WHERE full_fqdn = "{0}" ORDER BY dt DESC LIMIT 1;'''.format(zone)
        encrypted = self.db.load_object(sql)
        print(encrypted)
        try:
            crt = self.crypter.decrypt(bytes(encrypted['crt']))
        except:
            crt = ''
        try:
            key = self.crypter.decrypt(bytes(encrypted['key']))
        except:
            key = ''
        return {'crt': crt, 'key': key, 'responseText': 'Ok'}


class DeleteForm(SslManager, forms.Form):
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
        sql_data = self.db.load_object('''SELECT customer_id, server
            FROM billing.vhosts WHERE fqdn="{0}" LIMIT 1;'''.format(self.cleaned_data['zone']))
        print(sql_data)

        if self.cleaned_data['delencrypt']:
            sql = '''DELETE FROM billing.adv_services  WHERE service_type="85"
                AND customer_id="{0}" AND (requested_data="{1}" OR requested_data="");'''.format(
                sql_data['customer_id'], self.cleaned_data['zone'])
            print(sql)
            self.db.set_query(sql)
        try:
            self.soap_delete_zone(sql_data['server'], self.cleaned_data['zone'])
        except Exception as e:

        return {'responseText': 'Ok'}


class InstallForm(SslManager, forms.Form):
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
        zone  = self.cleaned_data['zone'].encode('idna')
        zone = zone if zone[:4] != 'www.' else zone[4:]
        crt = self.cleaned_data['crt'] if len(self.cleaned_data['crt'])>0 else False
        key = self.cleaned_data['key'] if len(self.cleaned_data['key'])>0 else False
        newip = self.cleaned_data['newip']
        service_type = self.cleaned_data['service_type']
        root_certs = self.cleaned_data['root_certs'] if self.cleaned_data['root_certs'] != 'None' else None
        result = {'responseText': 'Ok'}
        print(newip)
        print(service_type)
        print(root_certs)
        ssql = '''SELECT s.customer_id, s.directory, s.php_version, s.pagespeed_enabled, v.fqdn,
                            v.server, i.ip, cst.dealer, bs.ip as serverip, ss.provider, ss.crt, ss.key
                            FROM billing.sites s, billing.vhosts v
                            LEFT JOIN billing.servers bs ON bs.name = v.server
                            LEFT JOIN billing.ip_addr i ON i.id=v.ip_id
                            LEFT JOIN billing.customers cst ON cst.cust_login=v.customer_id
                            LEFT JOIN system.ssl_storage ss ON ss.full_fqdn=v.idn_name
                            WHERE s.id=v.site_id AND v.idn_name="{0}" ORDER BY ss.id DESC LIMIT 1;'''
        data = self.db.load_object(ssql.format(zone))
        try:
            print('decrypt ssl from base')
            data['key'] = self.crypter.decrypt(bytes(data['key']))
            data['crt'] = self.crypter.decrypt(bytes(data['crt']))
        except:
            print('decrypt data from base failed')
        data['key'] = key if key else data['key']
        data['crt'] = crt if crt else data['crt']
        if self.check_idn_name(zone):
            print('IDN check complete')
            if self.check_associate_cert_with_private_key(data['crt'], data['key']):
                print('check_associate_cert_with_private_key check complete')
                if newip:
                    print('new ip is:')
                    target = self.db.load_object('SELECT purpose FROM billing.servers WHERE name="{0}"'.format(data['server']))['purpose']
                    target = target if target != 'hosting' else target+'-personal'
                    data['ip'] = self.get_free_ip(target)
                    print(data['ip'])
                    if data['ip']:
                        self.soap_add_ip(data['ip'], data['server'], data['customer_id'])
                        self.update_a_dns(zone, data['ip'])
                        self.update_ip_id(zone, data['ip'])
                    else:
                        return {'responseText': 'no new ip'}
                print('update_adv_services')
                self.update_adv_services(zone, data['ip'], data['customer_id'], service_type)
                print('update_ssl_storage')
                self.update_ssl_storage(zone, self.crypter.encrypt(bytes(data['key'])), self.crypter.encrypt(bytes(data['crt'])))
                if root_certs:
                    print(type(root_certs))
                    data['crt'] = self.add_root_certs(data['crt'], root_certs)
                self.soap_install_sll(data['server'], zone, data['directory'], data['ip'], data['crt'], data['key'], data['php_version'])
            else:
                result['errors'] = 'Ошибка соответствия сертификата и ключа'
        else:
            result['errors'] = 'Поле idn.name не соответствует fqdn'
        return result
