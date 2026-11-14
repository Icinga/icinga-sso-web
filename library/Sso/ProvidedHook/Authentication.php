<?php

// SPDX-FileCopyrightText: 2026 Icinga GmbH <https://icinga.com>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Icinga\Module\Sso\ProvidedHook;

use GuzzleHttp\Client;
use Icinga\Application\Hook\ApplicationStateHook;
use Icinga\Application\Hook\AuthenticationHook;
use Icinga\Authentication\Auth;
use Icinga\User;
use Icinga\Util\Json;
use Icinga\Web\Session;
use Icinga\Web\Url;
use Throwable;

class Authentication extends AuthenticationHook
{
    /**
     * Refresh OIDC tokens if expired.
     *
     * This is intentionally not done via {@link ApplicationStateHook}.
     * An attacker could otherwise block own requests to /application-state and stay logged in forever.
     *
     * @param User $user
     */
    public function onAuthFromSession(User $user): void
    {
        $nsp = Session::getSession()->getNamespace('oidc');
        $session = $nsp->get('session');
        $provider = $nsp->get('provider');

        if (! $session || ! $provider || $session->mtime + $session->tokens->expires_in > time()) {
            return;
        }

        try {
            $tokens = Json::decode(
                (new Client())->post($provider->discovered->token_endpoint, ['form_params' => [
                    'grant_type'    => 'refresh_token',
                    'refresh_token' => $session->tokens->refresh_token,
                    'client_id'     => $provider->config->client_id,
                    'client_secret' => $provider->config->client_secret
                ]])->getBody()->getContents()
            );

            // The server MAY omit the refresh token if it did not rotate it. In that case, keep using the old one.
            // https://datatracker.ietf.org/doc/html/rfc6749#section-6
            $tokens->refresh_token ??= $session->tokens->refresh_token;

            // The server MAY omit the ID token, too. RP-initiated logout still needs it as hint.
            // https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
            $tokens->id_token ??= $session->tokens->id_token ?? null;

            $nsp->set('session', (object) [
                'mtime'  => time(),
                'tokens' => $tokens
            ]);
        } catch (Throwable $e) {
            Auth::getInstance()->removeAuthorization();
            throw $e;
        }
    }

    /**
     * Get the end-session endpoint of the provider to log out there, too
     *
     * Implements OpenID Connect RP-Initiated Logout for providers with the logout_at_provider setting.
     * The provider redirects the browser back to the Icinga Web login page,
     * which it accepts only if that URL is registered as post logout redirect URI.
     * Icinga Web versions without this hook method don't call it and always redirect to the login page.
     *
     * @param User $user
     *
     * @return ?Url The end-session endpoint, or null if the user didn't log in via SSO,
     *   the provider has the setting off or doesn't advertise the endpoint
     *
     * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
     */
    public function getLogoutRedirectUrl(User $user): ?Url
    {
        $nsp = Session::getSession()->getNamespace('oidc');
        $session = $nsp->get('session');
        $provider = $nsp->get('provider');
        $endSessionEndpoint = $provider?->discovered->end_session_endpoint ?? null;

        if (
            ! $session
            || ($provider->config->logout_at_provider ?? null) !== 'y'
            || ! is_string($endSessionEndpoint)
        ) {
            return null;
        }

        return Url::fromPath($endSessionEndpoint, array_filter([
            'id_token_hint'            => $session->tokens->id_token ?? null,
            'client_id'                => $provider->config->client_id,
            'post_logout_redirect_uri' => static::getPostLogoutRedirectUri($provider->config->redirect_url)
        ]));
    }

    /**
     * Get the URL the provider redirects the browser to after RP-initiated logout
     *
     * The URL points to the Icinga Web login page. It takes scheme, host and port from the redirect URL,
     * which is registered at the provider already. The request may lack them,
     * e.g. behind a reverse proxy that terminates TLS.
     *
     * @param string $redirectUrl The redirect URL of the provider configuration
     *
     * @return string The absolute URL, or the URL relative to the host if the redirect URL has no host
     */
    public static function getPostLogoutRedirectUri(string $redirectUrl): string
    {
        $loginUrl = Url::fromPath('authentication/login')->getAbsoluteUrl();
        $origin = parse_url($redirectUrl);

        if (! isset($origin['scheme'], $origin['host'])) {
            return $loginUrl;
        }

        return sprintf(
            '%s://%s%s%s',
            $origin['scheme'],
            $origin['host'],
            isset($origin['port']) ? ':' . $origin['port'] : '',
            $loginUrl
        );
    }
}
