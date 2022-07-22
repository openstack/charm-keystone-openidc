#!/usr/bin/env python3
#
# Copyright 2022 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
import subprocess

from typing import List
from uuid import uuid4

from ops.main import main
from ops.model import StatusBase

import ops.model
import ops_openstack.core

from ops_openstack.adapters import (
    ConfigurationAdapter,
)
from charmhelpers.contrib.openstack import templating as os_templating
from charmhelpers.core import host as ch_host
from charmhelpers.core import templating


logger = logging.getLogger(__name__)
CONFIG_DIR = '/etc/apache2/openidc'


class KeyStoneOpenIDCError(Exception):
    pass


class KeystoneOpenIDCOptions(ConfigurationAdapter):

    def __init__(self, charm_instance):
        self.charm_instance = charm_instance
        super().__init__(charm_instance)

    @property
    def openidc_location_config(self):
        service_name = self.charm_instance.unit.app.name
        return os.path.join(self.charm_instance.config_dir,
                            f'openidc-location.{service_name}.conf')

    @property
    def oidc_auth_path(self):
        service_name = self.charm_instance.unit.app.name
        return (f'/v3/OS-FEDERATION/identity_providers/{service_name}'
                f'/protocols/openid/auth')

    @property
    def oidc_crypto_passphrase(self):

        data = None
        for relation in self.charm_instance.framework.model.relations.get(
                'keystone-fid-service-provider'):
            data = relation.data[self.charm_instance.unit.app]
            break

        if not data:
            raise KeyStoneOpenIDCError('data bag on relation '
                                       'keystone-fid-service-provider '
                                       'not found')

        client_secret = data.get('oidc-client-secret')
        if client_secret:
            logger.debug('Using oidc-client-secret from app data base')
            return client_secret
        elif self.charm_instance.unit.is_leader():
            # we need to set the client secret since we are the leader and the
            # secret hasn't been set.
            logger.info('Generating oidc-client-secret')
            client_secret = str(uuid4())
            data.update({'oidc-client-secret': client_secret})
            return client_secret
        else:
            logger.debug('The oidc-client-secret has not been set, '
                         'and I am a follower')
            return None


class KeystoneOpenIDCCharm(ops_openstack.core.OSBaseCharm):

    PACKAGES = ['libapache2-mod-auth-openidc']

    REQUIRED_RELATIONS = ['keystone-fid-service-provider',
                          'websso-fid-service-provider']

    APACHE2_MODULE = 'auth_openidc'

    CONFIG_FILE_OWNER = 'root'
    CONFIG_FILE_GROUP = 'www-data'

    release = 'xena'  # First release supported.

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        super().register_status_check(self._check_status)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.options = KeystoneOpenIDCOptions(self)

    def _on_config_changed(self, _):
        for relation in self.framework.model.relations.get(
                'keystone-fid-service-provider'):
            self.set_principal_unit_relation_data(relation.data[self.unit])

        self.render_config()

    def services(self) -> List[str]:
        """Determine the list of services that should be running."""
        return []

    def _check_status(self) -> StatusBase:
        pass

    def enable_module(self):
        logger.info(f'Enabling apache2 module: {self.APACHE2_MODULE}')
        subprocess.check_call(['a2enmod', self.APACHE2_MODULE])

    def disable_module(self):
        logger.info(f'Disabling apache2 module: {self.APACHE2_MODULE}')
        subprocess.check_call(['a2dismod', self.APACHE2_MODULE])

    def set_principal_unit_relation_data(
            self,
            relation_data_to_be_set: ops.model.RelationData,
    ):
        pass

    def render_config(self):
        """Render Service Provider configuration files to be used by Apache."""
        ch_host.mkdir(self.config_dir,
                      perms=0o750,
                      owner=self.CONFIG_FILE_OWNER,
                      group=self.CONFIG_FILE_GROUP)
        templating.render(
            source='apache-openidc-location.conf',
            template_loader=os_templating.get_loader('templates/',
                                                     self.release),
            target=self.options.openidc_location_config,
            context={'options': KeystoneOpenIDCOptions(self)},
            owner=self.CONFIG_FILE_OWNER,
            group=self.CONFIG_FILE_GROUP,
            perms=0o440
        )

    @property
    def config_dir(self):
        return CONFIG_DIR


if __name__ == "__main__":
    main(ops_openstack.core.get_charm_class_for_release())
