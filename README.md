# Overview

This subordinate charm provides a way to integrate a Open ID Connect based
identity provider with Keystone using
[mod_auth_openidc](https://github.com/zmartzone/mod_auth_openidc). Apache
operates as a OpenID Connect Relaying Party towards an OpenID Connect
Provider.

# Usage

Use this charm with the [Keystone charm](https://charmhub.io/keystone):

    juju deploy keystone
    juju deploy openstack-dashboard
    juju deploy keystone-openidc
    juju add-relation keystone:keystone-fid-service-provider keystone-openidc:keystone-fid-service-provider
    juju add-relation openstack-dashboard:websso-fid-service-provider keystone-openidc:websso-fid-service-provider


In a bundle:

```yaml
applications:
  keystone-openidc:
    charm: ch:keystone-openid
    num_units: 0
relations:
- - keystone:keystone-fid-service-provider
  - keystone-openidc:keystone-fid-service-provider
```

# Prerequisites


# Bugs

Please report bugs on [Launchpad][lp-bugs-charm-keystone-openidc].

For general charm questions refer to the [OpenStack Charm Guide][cg].

<!-- LINKS -->

[cg]: https://docs.openstack.org/charm-guide
[lp-bugs-charm-keystone-openidc]: https://bugs.launchpad.net/charm-keystone-openidc/+filebug
