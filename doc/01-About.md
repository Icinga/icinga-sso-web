# Icinga Web SSO

This module adds OpenID Connect (OIDC) single sign-on to Icinga Web.
It places a "Login with \<provider\>" button on the login page for each configured provider.
Users are authenticated against the chosen provider and logged in to Icinga Web.

## Features

* Multiple providers can be configured simultaneously, each gets its own login button
* The username claim is configurable per provider: nickname (e.g. jdoe), full name (e.g. John Doe), ...
* Group mapping from a provider to Icinga Web groups is optional
* The claim used for group names is configurable per provider
* OAuth scopes can be added if needed in a special case
* User and group names can be transformed via a search/replace regex (e.g. to add a provider-specific prefix)

## License

Icinga Web SSO and its documentation are licensed under the terms of the
GNU General Public License Version 3.
