# Changelog

All notable changes to this module are documented in this file.

## [Unreleased]

- Rename the provider field `Base URL` to `Discovery URL` and explain that it must end with
  `/.well-known/openid-configuration` (#6)
- Show a readable error instead of an internal server error if the OIDC login fails (#20)
- Fix the login if the provider sends the groups as a string instead of an array (#12)
- Name the provider fields in the documentation after their configuration keys (#9)
- Redirect to the originally requested URL after the OIDC login (#13)
- Fix the logout after the first token refresh if the provider doesn't rotate the refresh token (#18)
- Fix the link to the documentation in the README (#4)

## [1.0.0] - 2026-06-26

- Initial release

[Unreleased]: https://github.com/Icinga/icinga-sso-web/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Icinga/icinga-sso-web/releases/tag/v1.0.0
