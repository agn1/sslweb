# -*- coding: utf-8 -*-
import sys
sys.path.append('/usr/lib/python2.7/dist-packages')
from twtools import dbw
from twtools import soap
import requests
import json
from os import listdir
import re
import OpenSSL
from cryptography.fernet import Fernet


def check_zone(function):
    def wrapper(self):
        zone = self.cleaned_data['zone'].encode('idna')
        if 'timeweb' in self.cleaned_data['zone']:
            self.cleaned_data['zone'] = 'TW'
        return function(self)
    return wrapper


class SslManager():

    def __init__(self):
        self.db = dbw.DBClient('ssl')
        self.rootcadir = 'rootca/'
        self.logfile = '/var/log/install_ssl.log'
        self.comodo_file = '/home/sslweb/comodo.crt'
        self.letsencrypt_file = '/home/sslweb/letsencrypt.crt'
        self.crypter = Fernet('VCNu9lxyYQ16OCb2SmgIdF0WESqeJp_8PIg76AlMWDI=')
        self.ipapiurl = 'http://noc:7508/api/v1.0/NOC/GetFreeIp'
        self.ipapiuser = 'vapi'
        self.ipapipass = 'SE2a9e3eHuWen0pO'
        self.result = {'responseText': 'Ok', 'errors': []}

    def is_ascii(self, s):
        return all(ord(c) < 128 for c in s)

    def update_status_ssl(self, status, zone):
        status_id_sql = """SELECT id FROM support.ssl_requests WHERE fqdn = '{fqdn}'
            AND r_status IN ('new', 'pending', 'received') ORDER BY id DESC LIMIT 1;"""
        status_id = self.db.load_object(status_id_sql.format(fqdn=zone))
        if status_id:
            update_sql = """UPDATE support.ssl_requests
                SET error = 'N', error_reason = '', r_status = '{new_status}'
                WHERE id = '{request_id}';"""
            self.db.set_query(update_sql.format(new_status=status,request_id=status_id['id']))


    def delete_passphrase_from_key(self, key, password):
        try:
            crypted = OpenSSL.crypto.load_privatekey(
                OpenSSL.crypto.FILETYPE_PEM, key, str(password)
                )
            return OpenSSL.crypto.dump_privatekey(
                OpenSSL.crypto.FILETYPE_PEM, crypted
                )
        except:
            return None

    def check_associate_cert_with_private_key(self, crt , key):
        try:
            private_key_obj = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
            cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, crt)
            context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
            context.use_privatekey(private_key_obj)
            context.use_certificate(cert_obj)
            context.check_privatekey()
            return True
        except:
            return False

    def get_issuer(self, crt):
        try:
            cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, crt)
            return cert_obj.get_issuer()
        except:
            return None

    def get_free_ip(self, target):
        result = None
        data = {"target": target, "location":"4", "ipv4":"true"}
        kwargs = {'data': json.dumps(data),
                  'headers': {'content-type': 'application/json'},
                  'auth': (self.ipapiuser, self.ipapipass)}
        _response = requests.get(self.ipapiurl, **kwargs)
        if _response.status_code == 200:
            jr = _response.json()
            if 'data' in jr:
                result = jr['data']['ipv4'][0]['ip']
        return result

    def check_ssl_install(self, zone, ip):
        headers = {'Host': zone}
        r = requests.get('https://' + str(ip), verify=False, headers=headers)
        return True if r.status_code == 200 else False

    def check_idn_name(self, zone):
        idn = self.db.load_object('SELECT idn_name FROM billing.vhosts WHERE idn_name="{0}"'.format(zone))
        return self.is_ascii(idn['idn_name']) if idn else False

    def update_a_dns(self, zone, ip):
        zone = zone[2:] if zone[0:1] == '*' else zone
        self.db.set_query('DELETE FROM billing.dns_records where fqdn="{0}" and type="a";'.format(zone))
        self.db.set_query('INSERT INTO billing.dns_records (fqdn, type, value) VALUES ("{0}", "a", "{1}")'.format(zone, ip))
        self.db.set_query('UPDATE billing.vhosts SET serial=serial+1 WHERE fqdn=idn_name AND fqdn="{0}";'.format(zone))

    def update_ip_id(self, zone, ip):
        self.db.set_query('UPDATE billing.vhosts SET ip_id=(SELECT id FROM billing.ip_addr WHERE ip="{0}") WHERE idn_name="{1}";'.format(ip, zone))
        if zone[0:1] == '*':
            self.db.set_query('UPDATE billing.vhosts SET ip_id=(SELECT id FROM billing.ip_addr WHERE ip="{0}") WHERE idn_name="{1}";'.format(ip, zone[2:]))

    def update_adv_services(self, zone, ip, user, service_type):
        zone = zone[2:] if zone[0:1] == '*' else zone
        adv = self.db.load_object_list('''SELECT id, info, requested_data FROM billing.adv_services WHERE customer_id="{user}"
            AND service_type="{service_type}";'''.format(user=user, service_type=service_type))
        if adv:
            for i in adv:
                if i['info'] == ip:
                    self.db.set_query('''UPDATE billing.adv_services
                        SET requested_data='{0}' WHERE id='{1}';'''.format('{"fqdn": "%s"}' % zone, i['id'])
                    )
                    break
                elif '"'+zone+'"' in i['requested_data'] or zone == i['requested_data']:
                    self.db.set_query('''UPDATE billing.adv_services
                        SET info='{0}' WHERE id='{1}';'''.format(ip, i['id'])
                    )
                    break
        else:
            self.db.set_query('''INSERT INTO billing.adv_services
                (service_type, customer_id, add_date, end_date, info, service_comment, service_status, requested_data, vds_id, pay_for)
                VALUES ('{0}', '{1}', CURRENT_TIMESTAMP, NOW() + INTERVAL 1 YEAR, '{2}', '','new', '{3}','0','y');'''.format(
                    service_type, user, ip, '{"fqdn": "%s"}' % zone
                )
            )
        adv = self.db.load_object('''SELECT count(id) as count FROM billing.adv_services WHERE customer_id="{user}"
            AND service_type="{service_type}" AND info="{ip}";'''.format(user=user, service_type=service_type, ip=ip))
        if adv['count'] == 0 :
            self.db.set_query('''INSERT INTO billing.adv_services
                (service_type, customer_id, add_date, end_date, info, service_comment, service_status, requested_data, vds_id, pay_for)
                VALUES ('{0}', '{1}', CURRENT_TIMESTAMP, NOW() + INTERVAL 1 YEAR, '{2}', '','new', '{3}','0','y');'''.format(
                    service_type, user, ip, '{"fqdn": "%s"}' % zone
                )
            )

    def update_ssl_storage(self, zone, key, crt):
        ssql = 'SELECT id, `key`, `crt` FROM system.ssl_storage WHERE full_fqdn = "{0}" ORDER BY dt DESC LIMIT 1'
        isql = '''INSERT INTO system.ssl_storage (dt, full_fqdn, `key`, csr, crt, provider, source)
             VALUES (CURRENT_TIMESTAMP, '{0}', '{1}', '', '{2}', 'self', 'manual');'''
        ssldata = self.db.load_object(ssql.format(zone))
        if ssldata:
            if len(ssldata['crt']) == 0:
                usql = 'UPDATE system.ssl_storage SET crt="{0}" WHERE id={1}'
                self.db.set_query(usql.format(crt, ssldata['id']))
                self.update_status_ssl('received', zone)
            else:
                if self.check_associate_cert_with_private_key(self.crypter.decrypt(bytes(crt)), self.crypter.decrypt(bytes(ssldata['key']))):
                    if self.crypter.decrypt(bytes(crt)) != self.crypter.decrypt(bytes(ssldata['crt'])):
                        self.db.set_query(isql.format(zone, key, crt))
                else:
                    self.db.set_query(isql.format(zone, key, crt))
        else:
            self.db.set_query(isql.format(zone, key, crt))

    def add_root_certs(self, crt):
        for f in listdir(self.rootcadir):
            if f in str(self.get_issuer(crt)) or f.upper() in str(self.get_issuer(crt)):
                with open(self.rootcadir+f, 'r') as f:
                    if len(crt) > 0:
                        crt +=  '\n'
                        crt += ''.join(f.readlines())
        return crt

    def soap_install_sll(self, server, zone, root_path, nginx_ip, crt, key, php_version, blocked, pagespeed_json, nginx_ipv6):
        s = soap.SOAPClient(server, 'SSL')
        s.InstallSSL(zone, root_path, nginx_ip, crt, key, php_version, blocked, pagespeed_json, nginx_ipv6)
        self.update_status_ssl('installed', zone)

    def soap_add_ip(self, ip, server, user):
        s = soap.SOAPClient(server, 'Ip')
        s.AddIp(ip, user)

    def soap_create_nginx_zone(self, server, zone, root_path, server_ip, ip, ipv6, ddos, blocked, php, redirect, pagespeed_json):
        s =  soap.SOAPClient(server, 'Apache')
        s.InstallNginx(zone, root_path, server_ip, ip, "", ipv6, ddos, blocked, php, redirect, pagespeed_json)

    def soap_delete_zone(self, server, zone):
        s = soap.SOAPClient(server, 'SSL')
        s.RemoveSSL(zone)

    def parse_csr(self, csrtext):
        csr = {}
        for line in csrtext.split('\n'):
            array = line.split()
            if len(line.split()) > 0:
                if line.split()[0].lower() == 'domain':
                    csr['commonname'] = array[1]
                elif line.split()[0].lower() == 'name':
                    csr['organizationalunit'] = ' '.join(array[1:])
                elif line.split()[0].lower() == 'username':
                    csr['emailAddress'] = array[-1]
                elif line.split()[0].lower() == 'company':
                    csr['organization'] = ' '.join(array[1:])
                elif line.split()[0].lower() == 'state/region/province':
                    csr['state'] = ' '.join(array[1:])
                elif line.split()[0].lower() == 'city':
                    csr['locality'] = ' '.join(array[1:])
                elif line.split()[0].lower() == 'country':
                    csr['country'] = ' '.join(array[1:])
        short2long = {"RU":"Russia",
            "UA":"Ukraine",
            "AE":"United Arab Emirates",
            "GB":"United Kingdom",
            "US":"United States",
            "AR":"Argentina",
            "AZ":"Azerbaijan",
            "AM":"Armenia",
            "BY":"Belarus",
            "BR":"Brazil",
            "BG":"Bulgaria",
            "CA":"Canada",
            "CY":"Cyprus",
            "CZ":"Czech Republic",
            "DK":"Denmark",
            "FI":"Finland",
            "FR":"France",
            "GR":"Greece",
            "GE":"Georgia",
            "DE":"Germany",
            "IL":"Israel",
            "IT":"Italy",
            "PK":"Pakistan",
            "UZ":"Uzbekistan",
            "BE":"Belgium",
            "AT":"Austria",
            "LV":"Latvia",
        }
        if 'country' in csr:
            for key in short2long.keys():
                if short2long[key] == csr['country']:
                    csr['country']=key
        return csr

    def generatecsr(self, **kwargs):
        """
        Args:
            commonname (str).

            country (str).

            state (str).

            city (str).

            organization (str).

            organizationalunit (str).

            emailAddress (str).

        Returns:
            {'key': str, 'csr': str).  Dictioanry containing private key and certificate
            signing request (PEM).
        """
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        req = OpenSSL.crypto.X509Req()
        req.get_subject().CN = kwargs['commonname']
        req.get_subject().C = kwargs['country']
        req.get_subject().ST = kwargs['state']
        req.get_subject().L = kwargs['locality']
        req.get_subject().O = kwargs['organization']
        req.get_subject().OU = kwargs['organizationalunit']
        req.get_subject().emailAddress = kwargs['emailAddress']

        req.set_pubkey(key)
        req.sign(key, 'sha256')

        private_key = OpenSSL.crypto.dump_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, key)

        csr = OpenSSL.crypto.dump_certificate_request(
                   OpenSSL.crypto.FILETYPE_PEM, req)

        return {'key': private_key, 'csr': csr}


        '{SHA512}7Ftw+tt26PQ/Yu6Sy2Oj3fD+VIC9Sri+JSsf8DAYGF+2S+tC2MZByzsi9lt7c5PKks1bYGmecNb5Y27ZG4bslg=='

