<!-- {% if index %} -->
# Installing Icinga Web SSO

The recommended way to install Icinga Web SSO is to use prebuilt packages for
all supported platforms from our official release repository.
Please follow the steps listed for your target operating system,
which guide you through setting up the repository and installing Icinga Web SSO.

<!-- {% else %} -->
<!-- {% if not icingaDocs %} -->

## Installing the Package

If the [repository](https://packages.icinga.com) is not configured yet, please add it first.
Then use your distribution's package manager to install the `icinga-sso-web` package
or install [from source](02-Installation.md.d/From-Source.md).
<!-- {% endif %} -->

This concludes the installation. Now proceed with the [configuration](03-Configuration.md).
<!-- {% endif %} --><!-- {# end else if index #} -->
