import os
import sys
import tempfile
import unittest
import uuid

from unittest import mock

from ops.testing import Harness

sys.path.append('src')  # noqa

import charm


WELL_KNOWN_URL = 'https://example.com/.well-known/openid-configuration'


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(charm.KeystoneOpenIDCCharm, meta='''
            name: keystone-openidc
            requires:
              keystone-fid-service-provider:
                interface: keystone-fid-service-provider
                scope: container
        ''')
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_add_relation(self):
        self.harness.add_relation('keystone-fid-service-provider', 'keystone')

    @mock.patch('charm.uuid4')
    @mock.patch('os.fchown')
    @mock.patch('os.chown')
    def test_render_config_leader(self, chown, fchown, uuid4):
        client_secret = uuid.UUID('1e19bb8a-a92d-4377-8226-5e8fc475822c')
        uuid4.return_value = client_secret
        rid = self.harness.add_relation('keystone-fid-service-provider',
                                        'keystone')
        self.harness.update_relation_data(rid,
                                          self.harness.charm.unit.app.name,
                                          {'foo': 'bar'})
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
                    self.assertIn(f'OIDCCryptoPassphrase {str(client_secret)}',
                                  content)
