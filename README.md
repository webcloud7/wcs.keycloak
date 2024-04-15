# wcs.keycloak

wcs.keycloak

## Goal


## TL;DR


## Architecure


### Dependecies:

See [python3-keycloak](https://github.com/marcospereirampj/python-keycloak)


## Features

- Seach user
- Search groups
- Links to keycloak console for user and group management
- Resolve group members

## Installation


Add plugin to your buildout
```
[buildout]

...

eggs =
    wcs.keycloak
```


Add wcs.keycloak to plone docker image
```
$ docker run -p 8080:8080 -e SITE="mysite" -e ADDONS="wcs.keycloak" plone
```

From the ZMI go to `acl_users` and add the keycloak plugin.


## Development

It's best to use a local IDP, for example keycloak in order to make changes to this package.

Start a local keycloak server using docker:

```
$ docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:24.0.2 start-dev

```

Install and run a test plone instance:

```
$ git clone git@github.com:webcloud7/wcs.keycloak.git && cd wcs.keycloak
$ make install
$ make run
```


# Test

You need a local docker installation to run tests.

The package provides a docker test layer, which spins up keycloak and loads various configuration files into keycloak.


```
$ make test
```

Run individual tests:

```
$ ./bin/test -t test_whatever
```
