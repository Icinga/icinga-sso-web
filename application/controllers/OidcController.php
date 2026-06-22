<?php

// SPDX-FileCopyrightText: 2026 Icinga GmbH <https://icinga.com>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Icinga\Module\Sso\Controllers;

use GuzzleHttp\Client;
use Icinga\Application\Hook\AuthenticationHook;
use Icinga\Exception\AuthenticationException;
use Icinga\Security\SecurityException;
use Icinga\User;
use Icinga\Util\Json;
use Icinga\Web\Session;
use ipl\Web\Compat\CompatController;

class OidcController extends CompatController
{
    protected $requiresAuthentication = false;

    public function redirectionEndpointAction(): void
    {
        $state = $this->params->getRequired('state');
        $code = $this->params->getRequired('code');

        $session = Session::getSession()->getNamespace('oidc');
        $login = $session->get('login');

        if ($login?->ctime < time() - 3600 || ! hash_equals($login->state, $state)) {
            throw new SecurityException($this->translate('Invalid or expired state'));
        }

        $client = new Client();

        $tokens = Json::decode($client->post($login->discovered->token_endpoint, ['form_params' => [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'client_id'     => $login->config->client_id,
            'client_secret' => $login->config->client_secret,
            'redirect_uri'  => $login->config->redirect_url
        ]])->getBody()->getContents());

        // "the TLS server validation MAY be used to validate the issuer in place of checking the token signature"
        // -- https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
        list($header, $payloadBase64Url, $signature) = explode('.', $tokens->id_token);

        // Convert Base 64 URL Safe Alphabet (https://datatracker.ietf.org/doc/html/rfc4648#section-5)
        // to regular Base 64 Alphabet:
        $payloadBase64 = str_replace(['-', '_'], ['+', '/'], $payloadBase64Url);

        $claims = Json::decode(base64_decode($payloadBase64));
        $username = $claims->{$login->config->username_claim} ?? null;
        $groups = null;

        if (($login->config->map_groups ?? null) === 'y') {
            $groups = $claims->{$login->config->groups_claim} ?? null;
        }

        if ($username === null || $groups === null && ($login->config->map_groups ?? null) === 'y') {
            // Requested claims may be not part of the ID token. Such must be retrieved from the userinfo endpoint.
            // E.g. GitLab includes groups only in the userinfo endpoint (but groups_direct only in the ID token)
            // https://docs.gitlab.com/integration/openid_connect_provider/

            $userinfo = Json::decode($client->get($login->discovered->userinfo_endpoint, ['headers' => [
                'Authorization' => "Bearer $tokens->access_token"
            ]])->getBody()->getContents());

            if ($username === null) {
                $username = $userinfo->{$login->config->username_claim} ?? null;
            }

            if ($groups === null && ($login->config->map_groups ?? null) === 'y') {
                $groups = $userinfo->{$login->config->groups_claim} ?? null;
            }
        }

        if ((string) $username === '') {
            throw new AuthenticationException($this->translate('Authorization server did not provide a username'));
        }

        $usernameSearch = $login->config->username_search ?? '';

        if ($usernameSearch !== '') {
            $username = preg_replace($usernameSearch, $login->config->username_replace ?? '', $username);
        }

        if ((string) $username === '') {
            throw new AuthenticationException($this->translate(
                'Username became empty after applying search and replace'
            ));
        }

        if ($groups !== null) {
            $groupnameSearch = $login->config->groupname_search ?? '';

            if ($groupnameSearch !== '') {
                $groups = array_map(function ($group) use ($groupnameSearch, $login): string {
                    return preg_replace($groupnameSearch, $login->config->groupname_replace ?? '', $group);
                }, $groups);
            }
        }

        $session->set('session', (object) [
            'mtime'  => time(),
            'tokens' => $tokens
        ]);

        $session->set('provider', (object) [
            'config'     => $login->config,
            'discovered' => $login->discovered
        ]);

        $user = (new User($username))->setGroups($groups ?? []);

        $this->Auth()->setAuthenticated($user);
        $session->delete('login');
        AuthenticationHook::triggerLogin($user);
        $this->redirectNow('dashboard');
    }
}
