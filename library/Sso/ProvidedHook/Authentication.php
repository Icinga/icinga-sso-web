<?php

// SPDX-FileCopyrightText: 2026 Icinga GmbH <https://icinga.com>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Icinga\Module\Sso\ProvidedHook;

use GuzzleHttp\Client;
use Icinga\Application\Hook\ApplicationStateHook;
use Icinga\Application\Hook\AuthenticationHook;
use Icinga\Application\Logger;
use Icinga\Authentication\Auth;
use Icinga\User;
use Icinga\Util\Json;
use Icinga\Web\Session;
use Throwable;

class Authentication extends AuthenticationHook
{
    /**
     * Refresh OIDC tokens if expired.
     *
     * This is intentionally not done via {@link ApplicationStateHook}.
     * An attacker could otherwise block own requests to /application-state and stay logged in forever.
     *
     * Logs the user out if the access token expired and the session has no refresh token.
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

        $refreshToken = $session->tokens->refresh_token ?? '';

        if ($refreshToken === '') {
            Auth::getInstance()->removeAuthorization();
            Logger::info(
                'Logged out user "%s" because the access token expired and the session has no refresh token',
                $user->getUsername()
            );

            return;
        }

        try {
            $tokens = Json::decode(
                (new Client())->post($provider->discovered->token_endpoint, ['form_params' => [
                    'grant_type'    => 'refresh_token',
                    'refresh_token' => $refreshToken,
                    'client_id'     => $provider->config->client_id,
                    'client_secret' => $provider->config->client_secret
                ]])->getBody()->getContents()
            );

            // The server MAY omit the refresh token if it did not rotate it. In that case, keep using the old one.
            // https://datatracker.ietf.org/doc/html/rfc6749#section-6
            $tokens->refresh_token ??= $refreshToken;

            $nsp->set('session', (object) [
                'mtime'  => time(),
                'tokens' => $tokens
            ]);
        } catch (Throwable $e) {
            Auth::getInstance()->removeAuthorization();
            throw $e;
        }
    }
}
