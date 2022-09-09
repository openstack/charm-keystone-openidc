#!/bin/bash -eux
#
# Example script to issue a token using an account backed by OpenID Connect,
# the script automatically gather the information from the juju model and
# assumes certain information for the objects created by openidc-test-fixture.
#

export OS_AUTH_TYPE=v3oidcpassword
export OS_DISCOVERY_ENDPOINT="$(juju config keystone-openidc oidc-provider-metadata-url)"

export OS_OPENID_SCOPE="openid email profile"
export OS_CLIENT_ID="$(juju config keystone-openidc oidc-client-id)"
export OS_CLIENT_SECRET="$(juju config keystone-openidc oidc-client-secret)"

# openstack identity provider list
export OS_IDENTITY_PROVIDER=openid

# openstack federation protocol list --identity-provider $OS_IDENTITY_PROVIDER
export OS_PROTOCOL=openid  # map to the protocol associated to the identity provider


# openstack specific config
export OS_USERNAME=janedoe
export OS_PASSWORD=f00bar
export OS_AUTH_URL=https://$(juju config keystone vip):5000/v3
export OS_IDENTITY_API_VERSION=3
export OS_PROJECT_NAME=janedoe_project
export OS_PROJECT_DOMAIN_NAME=federated_domain
export OS_REGION_NAME=RegionOne

openstack token issue
