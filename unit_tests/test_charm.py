import logging
import os
import sys
import tempfile
import unittest
import uuid

from unittest import mock

from ops.testing import Harness

sys.path.append('src')  # noqa

import charm


logger = logging.getLogger(__name__)
WELL_KNOWN_URL = 'https://example.com/.well-known/openid-configuration'


class TestCharm(unittest.TestCase):
    def setUp(self):
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

    def test_add_relation(self):
        self.harness.add_relation('keystone-fid-service-provider', 'keystone')

    @mock.patch('charm.uuid4')
    @mock.patch('os.fchown')
    @mock.patch('os.chown')
    def test_render_config_leader(self, chown, fchown, uuid4):
        crypto_passphrase = uuid.UUID('1e19bb8a-a92d-4377-8226-5e8fc475822c')
        uuid4.return_value = crypto_passphrase

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
            {'oidc-crypto-passphrase': str(crypto_passphrase)})
        self.harness.set_leader(True)
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch("charm.KeystoneOpenIDCCharm.config_dir",
                            new_callable=mock.PropertyMock,
                            return_value=tmpdir):
                self.harness.update_config(
                    key_values={'oidc-provider-metadata-url': WELL_KNOWN_URL})
                self.harness.charm.render_config()
                fpath = self.harness.charm.options.openidc_location_config
                self.assertTrue(os.path.isfile(fpath))
                with open(fpath) as f:
                    content = f.read()
                    self.assertIn(f'OIDCProviderMetadataURL {WELL_KNOWN_URL}',
                                  content)
                    self.assertIn(
                        f'OIDCCryptoPassphrase {str(crypto_passphrase)}',
                        content
                    )
