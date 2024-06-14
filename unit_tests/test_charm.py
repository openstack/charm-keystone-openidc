import json
import logging
import os
import shutil
import sys
import tempfile
import unittest
import uuid

from unittest import mock

import requests_mock
from ops.testing import Harness

sys.path.append('src')  # noqa

import charm


logger = logging.getLogger(__name__)
WELL_KNOWN_URL = 'https://example.com/.well-known/openid-configuration'
WELL_KNOWN_URL_INVALID = 'http://example.com/.well-known/openid-configuration'
INTROSPECTION_ENDPOINT_INVALID = 'http://idp.example.com/oauth2'
CRYPTO_PASSPHRASE = '1e19bb8a-a92d-4377-8226-5e8fc475822c'


class BaseTestCharm(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.harness = Harness(charm.KeystoneOpenIDCCharm, meta='''
            name: keystone-openidc
            provides:
              keystone-fid-service-provider:
                interface: keystone-fid-service-provider
                scope: container
              websso-fid-service-provider:
                interface: websso-fid-service-provider
                scope: global
            peers:
              cluster:
                interface: cluster
        ''')
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def tearDown(self):
        try:
            shutil.rmtree(self.tmpdir, ignore_errors=True)
        except Exception as ex:
            logger.debug(ex)


class TestRelations(BaseTestCharm):
    def test_add_relation(self):
        self.harness.add_relation('keystone-fid-service-provider', 'keystone')


class TestCharm(BaseTestCharm):
    def setUp(self):
        super().setUp()

        # bootstrap the charm
        self.crypto_passphrase = uuid.UUID(CRYPTO_PASSPHRASE)

        # disable hooks to avoid trigger them implicitly while the relations
        # are being setup and the mocks are not in place yet.
        self.harness.disable_hooks()

        # configure relation keystone <-> keystone-openidc
        rid = self.harness.add_relation('keystone-fid-service-provider',
                                        'keystone')
        self.harness.add_relation_unit(rid, 'keystone/0')
        self.harness.update_relation_data(rid, 'keystone/0',
                                          {'port': '5000',
                                           'tls-enabled': 'true',
                                           'hostname': '"10.5.250.250"'})

        # configure peer relation for keystone-openidc
        logger.debug(f'Adding cluster relation for '
                     f'{self.harness.charm.unit.app.name}')
        rid = self.harness.add_relation('cluster',
                                        self.harness.charm.unit.app.name)
        self.harness.update_relation_data(
            rid, self.harness.charm.unit.app.name,
            {'oidc-crypto-passphrase': str(self.crypto_passphrase)})

    @mock.patch('os.fchown')
    @mock.patch('os.chown')
    def test_render_config_leader(self, chown, fchown):
        opts = {
            'oidc-provider-metadata-url': WELL_KNOWN_URL,
            'oidc-provider-issuer': 'foo',
            'oidc-client-id': 'keystone',
            'oidc-client-secret': 'ubuntu11',
        }

        well_known_url_content = {
            'introspection_endpoint': INTROSPECTION_ENDPOINT_INVALID,
        }
        self.harness.set_leader(True)
        with requests_mock.Mocker() as m, \
                 mock.patch(  # noqa: E127
                     "charm.KeystoneOpenIDCCharm.config_dir",
                     new_callable=mock.PropertyMock,
                     return_value=self.tmpdir.name):
            m.get(WELL_KNOWN_URL, json=well_known_url_content)
            self.harness.update_config(
                key_values=opts)
            self.harness.charm.render_config()
            fpath = self.harness.charm.options.openidc_location_config
            self.assertTrue(os.path.isfile(fpath))
            with open(fpath) as f:
                content = f.read()
                self.assertIn(
                    f'OIDCProviderMetadataURL {WELL_KNOWN_URL}',
                    content
                )
                self.assertIn(
                    f'OIDCCryptoPassphrase {str(self.crypto_passphrase)}',
                    content
                )

    def test_find_missing_keys_no_metadata_url(self):
        opts = {
            'oidc-provider-metadata-url': '',
        }
        self.harness.update_config(key_values=opts)
        missing_keys = self.harness.charm.find_missing_keys()
        missing_keys.sort()

        expected = ['idp_id',
                    'oidc_client_id',
                    'oidc_provider_metadata_url']
        expected.sort()
        self.assertEqual(missing_keys, expected)

    def test_find_missing_keys_manual_configuration(self):
        opts = {
            'oidc-provider-metadata-url': '',
            'oidc-provider-issuer': 'foo',
            'oidc-client-id': 'keystone',
        }
        self.harness.update_config(key_values=opts)
        missing_keys = self.harness.charm.find_missing_keys()
        missing_keys.sort()

        expected = ['idp_id',
                    'oidc_provider_auth_endpoint',
                    'oidc_provider_token_endpoint',
                    'oidc_provider_token_endpoint_auth',
                    'oidc_provider_user_info_endpoint',
                    'oidc_provider_jwks_uri']
        expected.sort()
        self.assertEqual(missing_keys, expected)

    def test_find_missing_keys_invalid_oidc_oauth_verify_jwks_uri(self):
        opts = {
            'oidc-provider-metadata-url': WELL_KNOWN_URL,
            'oidc-provider-issuer': 'foo',
            'oidc-client-id': 'keystone',
            'oidc-oauth-verify-jwks-uri': 'http://idp.example.com/jwks'
        }

        self.harness.update_config(key_values=opts)
        self.assertRaises(charm.CharmConfigError,
                          self.harness.charm.find_missing_keys)

    def test_find_missing_keys_invalid_introspection_endpoint(self):
        opts = {
            'oidc-provider-metadata-url': WELL_KNOWN_URL,
            'oidc-provider-issuer': 'foo',
            'oidc-client-id': 'keystone',
            'oidc-oauth-verify-jwks-uri': 'http://idp.example.com/jwks'
        }

        well_known_url_content = {
            'introspection_endpoint': INTROSPECTION_ENDPOINT_INVALID,
        }
        self.harness.update_config(key_values=opts)
        with requests_mock.Mocker() as m:
            m.get(WELL_KNOWN_URL, json=well_known_url_content)
            self.assertRaises(charm.CharmConfigError,
                              self.harness.charm.find_missing_keys)

    def test_update_websso_data(self):
        rid = self.harness.add_relation('websso-fid-service-provider',
                                        'openstack-dashboard')
        self.harness.add_relation_unit(rid, 'openstack-dashboard/0')
        self.harness.charm._update_websso_data()
        data = self.harness.get_relation_data(rid, 'keystone-openidc/0')
        options = self.harness.charm.options
        expected = {'protocol-name': json.dumps(options.protocol_id),
                    'idp-name': json.dumps(options.idp_id),
                    'user-facing-name': json.dumps(options.user_facing_name)}
        self.assertDictEqual(data, expected)

        # check that on config-changed the data is updated on the relation.
        self.harness.update_config(key_values={'user-facing-name': 'My IdP'})
        self.harness.charm.options = charm.KeystoneOpenIDCOptions(
            self.harness.charm
        )
        self.harness.charm._update_websso_data()
        data = self.harness.get_relation_data(rid, 'keystone-openidc/0')
        expected['user-facing-name'] = json.dumps('My IdP')
        self.assertDictEqual(data, expected)
