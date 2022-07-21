import os
import sys
import tempfile
import unittest

from unittest import mock

from ops.testing import Harness

sys.path.append('src')  # noqa

import charm


WELL_KNOWN_URL = 'https://example.com/.well-known/openid-configuration'


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(charm.KeystoneOpenIDCCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @mock.patch('os.fchown')
    @mock.patch('os.chown')
    def test_render_config(self, chown, fchown):
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
