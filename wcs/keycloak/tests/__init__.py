from bs4 import BeautifulSoup
from plone.app.testing import setRoles
from plone.app.testing import TEST_USER_ID
from plone.app.testing import TEST_USER_NAME
from plone.app.testing import TEST_USER_PASSWORD
from plone.testing.zope import Browser
from unittest import TestCase
from wcs.keycloak.testing import KEYCLOAKPASPLUGIN_FUNCTIONAL_TESTING
from wcs.keycloak.utils import install_plugin
from wcs.keycloak.utils import PLUGIN_ID
import operator
import transaction


class FunctionalTesting(TestCase):
    layer = KEYCLOAKPASPLUGIN_FUNCTIONAL_TESTING

    def setUp(self):
        self.portal = self.layer['portal']
        self.request = self.layer['request']

        self._create_plugin()
        self.plugin = getattr(self.portal.acl_users, PLUGIN_ID)

    def tearDown(self):
        super().tearDown()
        self.portal.acl_users.manage_delObjects([PLUGIN_ID])

    def grant(self, *roles):
        setRoles(self.portal, TEST_USER_ID, list(roles))
        transaction.commit()

    def get_browser(self, logged_in=True):
        browser = Browser(self.layer['app'])
        browser.handleErrors = False

        if logged_in:
            browser.open(self.portal.absolute_url() + '/login_form')
            browser.getControl(name='__ac_name').value = TEST_USER_NAME
            browser.getControl(name='__ac_password').value = TEST_USER_PASSWORD
            browser.getControl(name='buttons.login').click()
        return browser

    def setup_realm(self, filename='test-realm.json'):
        self.layer['delete_realm']()
        self.layer['create_realm'](filename=filename)

    def _create_plugin(self):
        install_plugin()
        transaction.commit()

    def _find_content(self, data, query, method='select_one'):
        soup = BeautifulSoup(data, 'html.parser')
        find = operator.methodcaller(method, query)
        return find(soup)
