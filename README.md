# Overview

This subordinate charm provides a way to integrate an Open ID Connect based
identity provider with Keystone using
[mod_auth_openidc][mod_auth_openidc]. Apache
operates as an OpenID Connect Relaying Party towards an OpenID Connect
Provider.

# Usage

## Configuration

To display all configuration option information run `juju config
keystone-openidc`. If the application is not deployed then see the charm's
[Configure tab][keystone-openidc-configure] in the
Charmhub. Finally, the [Juju documentation][juju-docs-config-apps] provides
general guidance on configuring applications.

## Deployment

These deployment instructions assume the following applications are present:
[keystone][keystone-charm] and
[openstack-dashboard][openstack-dashboard-charm]

To deploy keystone-openidc:

    juju deploy keystone-openidc

Join keystone-openidc to keystone:

    juju add-relation keystone:keystone-fid-service-provider keystone-openidc:keystone-fid-service-provider

Join keystone-openidc to openstack-dashboard to provide SSO access through Horizon:

    juju add-relation openstack-dashboard:websso-fid-service-provider keystone-openidc:websso-fid-service-provider

Enable Horizon as a trusted dashboard for Web Single Single-On for Keystone:

    juju add-relation openstack-dashboard:websso-trusted-dashboard keystone:websso-trusted-dashboard

**You must add this relation for Horizon and Keystone. If you do not, Keystone will return a 401 error that the login domain for Horizon is not a trusted domain.**

Now provide an OpenID Connect client credentials and the URL for autodiscovery
of the backend's configuration:

    juju config keystone-openidc \
        oidc-client-id="<CLIENT_ID>" \
        oidc-client-secret="<CLIENT_SECRET>" \
        oidc-provider-metadata-url="https://example.com/.well-known/openid-configuration"

Here is a bundle representation of the deployment:

```yaml
applications:
  keystone-openidc:
    charm: ch:keystone-openid
    num_units: 0
    options:
      oidc-client-id: "<CLIENT_ID>"
      oidc-client-secret: "<CLIENT_SECRET>"
      oidc-provider-metadata-url: "https://example.com/.well-known/openid-configuration"
relations:
- - keystone:keystone-fid-service-provider
  - keystone-openidc:keystone-fid-service-provider
- - openstack-dashboard:websso-fid-service-provider
  - keystone-openidc:websso-fid-service-provider
```

## OpenStack CLI Authentication

The [OpenStack client][openstackclient-homepage] supports authentication
against an OpenID Connect identity provider using [Bearer Access Token
authentication flow][bearer-access-token-flow] only. This requires the
keystone-openidc charm to have its configuration option `auth-type` set to
'auth-openidc' (the default).

Here is an example of the environment variables that need to be set for the
OpenStack client to authenticate successfully:

```bash
export OS_AUTH_TYPE=v3oidcpassword
export OS_DISCOVERY_ENDPOINT="https://example.com/.well-known/openid-configuration"

export OS_OPENID_SCOPE="openid email profile"
export OS_CLIENT_ID="<CLIENT_SECRET>"
export OS_CLIENT_SECRET="<CLIENT_SECRET>"
export OS_IDENTITY_PROVIDER=openid
export OS_PROTOCOL=openid

# At the end include openstack specific config, like OS_USERNAME, OS_PASSWORD, etc.
# ...
```

<!-- To test the example above run the following commands in a local copy of
the keystone-openidc git repo:

  tox -e build
  tox -e func-target -- noble-caracal --keep-model
-->

## Proxies

The keystone-openidc charm uses the `juju-https-proxy` model configuration when
set and its value is passed to
[OIDCOutgoingProxy in Apache mod_auth_openidc module](https://github.com/OpenIDC/mod_auth_openidc/blob/v2.4.12.3/auth_openidc.conf#L839-L842).

# Bugs

Please report bugs on [Launchpad][keystone-openidc-filebug].

For general charm questions refer to the [OpenStack Charm Guide][cg].

<!-- LINKS -->

[bearer-access-token-flow]: https://www.rfc-editor.org/rfc/rfc6750
[cg]: https://docs.openstack.org/charm-guide
[juju-docs-config-apps]: https://juju.is/docs/olm/configure-an-application
[keystone-openidc-configure]: https://charmhub.io/keystone-openidc/configure
[keystone-openidc-filebug]: https://bugs.launchpad.net/charm-keystone-openidc/+filebug
[keystone-charm]: https://charmhub.io/keystone
[mod_auth_openidc]: https://github.com/zmartzone/mod_auth_openidc
[openstackclient-homepage]: https://docs.openstack.org/python-openstackclient/latest/
[openstack-dashboard-charm]: https://charmhub.io/openstack-dashboard
