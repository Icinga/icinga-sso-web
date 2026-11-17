<?php

// SPDX-FileCopyrightText: 2026 Icinga GmbH <https://icinga.com>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Icinga\Module\Sso;

use Icinga\Application\Icinga;
use Icinga\Data\ConfigObject;
use Icinga\Util\Json;
use Icinga\Web\Session;
use ipl\Stdlib\Str;
use ipl\Web\Url;

/**
 * Start of the OIDC login with a provider
 */
class Login
{
    /**
     * Get the login URL on the host of the given redirect URL
     *
     * The login state lives in the session, which belongs to a single host. The login has to start on the host
     * the provider returns the user to, which is the host of the redirect URL.
     *
     * @param string $redirectUrl Redirect URL of the provider
     * @param string $providerId ID of the provider
     * @param ?string $redirect Icinga Web URL to show after the login, or null for the dashboard
     *
     * @return ?Url Absolute login URL, or null if the redirect URL isn't a redirection endpoint of this module
     */
    public static function getUrl(string $redirectUrl, string $providerId, ?string $redirect = null): ?Url
    {
        $parts = parse_url($redirectUrl);
        $endpointPath = isset($parts['path']) ? rtrim($parts['path'], '/') : '';

        if (
            ! isset($parts['scheme'], $parts['host'])
            || ! str_ends_with($endpointPath, '/sso/oidc/redirection-endpoint')
        ) {
            return null;
        }

        $path = substr($endpointPath, 0, -strlen('redirection-endpoint')) . 'login';

        // Url::fromPath() treats a URL as internal only if its scheme, host and port match those of the request
        // (SERVER_NAME and SERVER_PORT) and then drops all three. module.js would resolve the remaining relative URL
        // against the host of the browser. The scheme, host and port are set explicitly to get an absolute URL on the
        // host of the redirect URL in any case.
        return Url::fromPath($path, array_filter(
            ['provider' => $providerId, 'redirect' => $redirect],
            fn ($value) => $value !== null
        ))
            ->setIsExternal()
            ->setScheme($parts['scheme'])
            ->setHost($parts['host'])
            ->setPort((string) ($parts['port'] ?? ''))
            ->setBasePath('/')
            ->setPath(ltrim($path, '/'));
    }

    /**
     * Redirect to the login URL on the host of the redirect URL and exit if the request is on another host
     *
     * Does nothing if the redirect URL isn't a redirection endpoint of this module. The scheme is not compared,
     * because a proxy that terminates TLS hides the scheme of the browser from Icinga Web.
     *
     * @param ConfigObject<string> $config Provider configuration
     * @param string $providerId ID of the provider
     * @param ?string $redirect Icinga Web URL to show after the login, or null for the dashboard
     *
     * @return void
     */
    public static function switchHost(ConfigObject $config, string $providerId, ?string $redirect): void
    {
        $redirectUrl = (string) $config->get('redirect_url');
        $loginUrl = static::getUrl($redirectUrl, $providerId, $redirect);

        if ($loginUrl === null) {
            return;
        }

        /** @var \Icinga\Application\Web $app */
        $app = Icinga::app();

        // Browsers omit the default port in the Host header, but the redirect URL may contain it. Both ports are
        // dropped for any scheme, because a proxy that terminates TLS hides the scheme from Icinga Web.
        $normalize = function (string $url): array {
            $parts = parse_url($url);
            $port = $parts['port'] ?? null;

            return [strtolower($parts['host'] ?? ''), in_array($port, [80, 443], true) ? null : $port];
        };

        if ($normalize('//' . $app->getRequest()->getHttpHost()) === $normalize($redirectUrl)) {
            return;
        }

        $response = $app->getResponse();
        $response->setHeader('X-Icinga-Redirect-Http', 'yes');
        $response->redirectAndExit($loginUrl);
    }

    /**
     * Redirect the user to the authorization endpoint of the given provider and exit
     *
     * Stores the login state in the session. After the login,
     * {@see \Icinga\Module\Sso\Controllers\OidcController::redirectionEndpointAction()}
     * redirects the user to the given target.
     *
     * @param ConfigObject<string> $config Provider configuration
     * @param object $openidCfg Discovery document of the provider, whose `authorization_endpoint` must be a string
     * @param ?string $redirect Icinga Web URL to show after the login, or null for the dashboard
     *
     * @return never
     */
    public static function start(ConfigObject $config, object $openidCfg, ?string $redirect): never
    {
        $state = function_exists('openssl_random_pseudo_bytes')
            ? bin2hex(openssl_random_pseudo_bytes(16))
            : sprintf('%x', mt_rand());

        Session::getSession()->getNamespace('oidc')->set('login', (object) [
            'ctime'      => time(),
            'state'      => $state,
            'redirect'   => $redirect,
            'config'     => (object) $config->toArray(),
            'discovered' => $openidCfg
        ]);

        $claims = [$config->get('username_claim') => (object) ['essential' => true]];

        if ($config->get('map_groups') === 'y') {
            $claims[$config->get('groups_claim')] = null;
        }

        /** @var \Icinga\Application\Web $app */
        $app = Icinga::app();
        $response = $app->getResponse();
        $response->setHeader('X-Icinga-Redirect-Http', 'yes');

        // Many providers require the offline_access scope for refresh tokens.
        // Others don't know it at all and hard-reject it, but provide refresh tokens by default.
        // Hence, we must include offline_access in the default set, but strip it if it's not supported.
        // Same with the groups scope for group mapping.
        // scopes_supported is optional, so a provider without it gets all configured scopes.
        // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
        $scopes = Str::trimSplit($config->get('scopes'), ' ');

        if (is_array($openidCfg->scopes_supported ?? null)) {
            $scopes = array_intersect($scopes, $openidCfg->scopes_supported);
        }

        $response->redirectAndExit(Url::fromPath($openidCfg->authorization_endpoint, [
            'client_id'     => $config->get('client_id'),
            'scope'         => implode(' ', $scopes),
            'redirect_uri'  => $config->get('redirect_url'),
            'response_type' => 'code',
            'state'         => $state,
            'claims'        => Json::encode((object) ['id_token' => (object) $claims, 'userinfo' => (object) $claims])
        ]));
    }
}
