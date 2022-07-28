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

import json
import logging
import os
import subprocess

from typing import List
from uuid import uuid4

from ops.main import main
from ops.model import StatusBase, ActiveStatus

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


class KeystoneOpenIDCError(Exception):
    pass


class KeystoneOpenIDCOptions(ConfigurationAdapter):

    def __init__(self, charm_instance):
        self.charm_instance = charm_instance
        super().__init__(charm_instance)

    def _get_principal_data(self):
        relation = self.charm_instance.model.get_relation(
            'keystone-fid-service-provider')
        if len(relation.units) > 0:
            return relation.data[list(relation.units)[0]]
        else:
            logger.debug('There are no related units via '
                         'keystone-fid-service-provider')
            return None

    @property
    def hostname(self) -> str:
        """Hostname as advertised by the principal charm"""
        data = self._get_principal_data()
        if data:
            return json.loads(data['hostname'])
        else:
            logger.debug('There are no related units via '
                         'keystone-fid-service-provider')
            return None

    @property
    def openidc_location_config(self) -> str:
        return os.path.join(self.charm_instance.config_dir,
                            f'openidc-location.{self.idp_id}.conf')

    @property
    def oidc_auth_path(self) -> str:
        service_name = self.charm_instance.unit.app.name
        return (f'/v3/OS-FEDERATION/identity_providers/{service_name}'
                f'/protocols/openid/auth')

    @property
    def idp_id(self) -> str:
        return self.charm_instance.unit.app.name

    @property
    def scheme(self) -> str:
        data = self._get_principal_data()
        try:
            tls_enabled = json.loads(data['tls-enabled'])
            return 'https' if tls_enabled else 'http'
        except (TypeError, KeyError):
            return None

    @property
    def port(self) -> int:
        data = self._get_principal_data()
        try:
            return json.loads(data['port'])
        except (TypeError, KeyError):
            return None

    @property
    def oidc_crypto_passphrase(self) -> str:

        data = None
        relation = self.charm_instance.model.get_relation('cluster')
        data = relation.data[self.charm_instance.unit.app]

        if not data:
            raise KeystoneOpenIDCError('data bag on peer relation not found')

        client_secret = data.get('oidc-client-secret')
        if client_secret:
            logger.debug('Using oidc-client-secret from app data base')
            return client_secret
        else:
            logger.warn('The oidc-client-secret has not been set')
            return None


class KeystoneOpenIDCCharm(ops_openstack.core.OSBaseCharm):

    PACKAGES = ['libapache2-mod-auth-openidc']

    REQUIRED_RELATIONS = ['keystone-fid-service-provider',
                          'websso-fid-service-provider']

    APACHE2_MODULE = 'auth_openidc'

    CONFIG_FILE_OWNER = 'root'
    CONFIG_FILE_GROUP = 'www-data'

    release = 'xena'  # First release supported.

    protocol_name = 'openidc'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        super().register_status_check(self._check_status)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.cluster_relation_created,
                               self._on_cluster_relation_created)
        self.framework.observe(self.on.start, self._on_start)
        self.options = KeystoneOpenIDCOptions(self)
        self.framework.observe(self.on.cluster_relation_changed,
                               self._on_cluster_relation_changed)
        self.framework.observe(
            self.on.keystone_fid_service_provider_relation_created,
            self._on_keystone_fid_service_provider_relation_created
        )

    # Event handlers

    # Extending the default handler for install hook to enable the apache2
    # openidc module.
    def on_install(self, _):
        super().on_install(_)
        self.enable_module()

    def _on_start(self, _):
        self._stored.is_started = True

    def _on_keystone_fid_service_provider_relation_created(self, event):

        if not self.is_data_ready():
            event.defer()

        relation = self.model.get_relation('keystone-fid-service-provider')
        data = relation.data[self.unit]

        data['protocol-name'] = json.dumps(self.protocol_name)

    def _on_config_changed(self, event):
        self._stored.is_started = True
        if not self.is_data_ready():
            logger.debug(f'relation data is not ready yet, deferring {event}')
            event.defer()
            return

        with ch_host.restart_on_change(
                self.restart_map,
                restart_functions=self.restart_functions):
            self.render_config()

    def _on_cluster_relation_created(self, _):

        if self.unit.is_leader():
            # we need to set the client secret since we are the leader and the
            # secret hasn't been set.
            data = None
            relations = self.framework.model.relations.get(
                'cluster')
            for relation in relations:
                data = relation.data[self.unit.app]
                break
            logger.info('Generating oidc-client-secret')
            client_secret = str(uuid4())
            data.update({'oidc-client-secret': client_secret})
        else:
            logger.debug('Not leader, skipping oidc-client-secret generation')

    def _on_cluster_relation_changed(self, _):
        self._on_config_changed(_)

    # properties
    @property
    def restart_map(self):
        return {self.options.openidc_location_config: ['apache2']}

    @property
    def restart_functions(self):
        return {'apache2': self.request_restart}

    def is_data_ready(self):
        options = KeystoneOpenIDCOptions(self)
        required_keys = ['oidc_crypto_passphrase']
        for key in required_keys:
            if getattr(options, key) == None:  # noqa: E711
                return False

        return True

    def services(self) -> List[str]:
        """Determine the list of services that should be running."""
        return []

    def _check_status(self) -> StatusBase:
        if self.is_data_ready():
            return ActiveStatus('ready')
        else:
            return BlockedStatus('incomplete data')

    def enable_module(self):
        logger.info(f'Enabling apache2 module: {self.APACHE2_MODULE}')
        subprocess.check_call(['a2enmod', self.APACHE2_MODULE])

    def disable_module(self):
        logger.info(f'Disabling apache2 module: {self.APACHE2_MODULE}')
        subprocess.check_call(['a2dismod', self.APACHE2_MODULE])

    def request_restart(self):
        """Request a restart of the service to the principal."""
        relation = self.model.get_relation('keystone-fid-service-provider')
        data = relation.data[self.unit]
        data['restart-nonce']

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
    main(KeystoneOpenIDCCharm)
