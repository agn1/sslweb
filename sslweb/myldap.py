from django_auth_ldap.backend import LDAPBackend
from django.contrib.auth import get_user_model


class MyLDAPBackend(LDAPBackend):
    """ A custom LDAP authentication backend """

    def authenticate(self, username, password):
        """ Overrides LDAPBackend.authenticate to save user password in django """

        user = LDAPBackend.authenticate(self, username, password)

        # If user has successfully logged, save his password in django database
        if user:
            user.set_password(password)
            user.save()

        return user

    def get_or_create_user(self, username, ldap_user):
        """ Overrides LDAPBackend.get_or_create_user to force from_ldap to True """
        kwargs = {
            'username': username,
            'defaults': {'from_ldap': True}
        }
        user_model = get_user_model()
        return user_model.objects.get_or_create(**kwargs)
