<?php

// SPDX-FileCopyrightText: 2026 Icinga GmbH <https://icinga.com>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Icinga\Module\Sso\Controllers;

use GuzzleHttp\Client;
use Icinga\Application\Hook\AuthenticationHook;
use Icinga\Application\Modules\Manager;
use Icinga\Exception\AuthenticationException;
use Icinga\Exception\Http\HttpException;
use Icinga\Module\Sso\Login;
use Icinga\Security\SecurityException;
use Icinga\User;
use Icinga\Util\Json;
use Icinga\Web\Form\Element\LoginRedirect;
use Icinga\Web\Session;
use ipl\Web\Compat\CompatController;
use ipl\Stdlib\Str;

class OidcController extends CompatController
{
    protected $requiresAuthentication = false;

    /**
     * Assert the given permission, except the module permission for the login action
     *
     * The module permission is asserted for every logged-in user before an action runs. The login action redirects
     * logged-in users to a target that checks its own permissions and starts the login for everyone else. Users who
     * lack the module permission must reach it as well.
     *
     * @param string $permission Name of the permission
     *
     * @return void
     *
     * @throws SecurityException If the current user lacks the given permission
     */
    public function assertPermission($permission): void
    {
        if (
            $this->getRequest()->getActionName() === 'login'
            && $permission === Manager::MODULE_PERMISSION_NS . $this->getModuleName()
        ) {
            return;
        }

        parent::assertPermission($permission);
    }

    /**
     * Start the login with the provider given by the `provider` parameter
     *
     * Identity providers link to this URL to log users in without the Icinga Web login page.
     * Users who are already logged in go straight to the `redirect` parameter.
     *
     * @return void
     *
     * @throws \Icinga\Exception\Http\HttpBadRequestException If the `redirect` parameter points to an external URL
     * @throws \Icinga\Exception\MissingParameterException If the `provider` parameter is missing
     * @throws \Icinga\Exception\Http\HttpNotFoundException If the provider doesn't exist
     * @throws HttpException If the discovery request to the provider fails or its response is invalid
     */
    public function loginAction(): void
    {
        // Checked up front, so a rejected target doesn't fail only after the login with the provider.
        $redirectUrl = (new LoginRedirect('redirect'))->setValue($this->params->get('redirect'))->getUrl();

        if ($this->Auth()->isAuthenticated()) {
            $this->redirectNow($redirectUrl);
        }

        $id = $this->params->getRequired('provider');
        $providers = $this->Config('providers');

        if (! $providers->hasSection($id)) {
            $this->httpNotFound($this->translate('Provider not found'));
        }

        $config = $providers->getSection($id);

        Login::start($config, Login::discover($config), $this->params->get('redirect'));
    }

    public function redirectionEndpointAction(): void
    {
        $state = $this->params->getRequired('state');

        $session = Session::getSession()->getNamespace('oidc');
        $login = $session->get('login');

        if ($login?->ctime < time() - 3600 || ! hash_equals($login->state, $state)) {
            throw new SecurityException($this->translate('Invalid or expired state'));
        }

        // Consumed before anything can fail, so the state is single-use. The error page writes the session.
        $session->delete('login');

        // Checked after the state, so only the provider of this login can make us display a message.
        // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
        $error = $this->params->get('error');

        if ($error !== null) {
            $details = array_filter([$this->params->get('error_description'), $this->params->get('error_uri')]);

            $message = sprintf(
                $this->translate('Authorization server rejected the login: %s'),
                empty($details) ? $error : $error . ' (' . implode(', ', $details) . ')'
            );

            if ($error === 'access_denied') {
                // E.g. the user declined consent. That's no server fault to answer with 500 and log as error.
                throw new HttpException(403, $message);
            }

            throw new AuthenticationException($message);
        }

        $code = $this->params->getRequired('code');

        // Resolved up front, so a rejected target costs no token exchange.
        $redirectUrl = (new LoginRedirect('redirect'))->setValue($login->redirect ?? null)->getUrl();

        $client = new Client();

        $tokenEndpoint = $login->discovered->token_endpoint;
        $tokens = Login::requestJson('token', $tokenEndpoint, fn () => $client->post($tokenEndpoint, [
            'form_params' => [
                'grant_type'    => 'authorization_code',
                'code'          => $code,
                'client_id'     => $login->config->client_id,
                'client_secret' => $login->config->client_secret,
                'redirect_uri'  => $login->config->redirect_url
            ]
        ]));

        if (! is_string($tokens->id_token ?? null)) {
            // E.g. an error answered with status 200 instead of 400, so the request didn't fail.
            if (is_string($tokens->error ?? null)) {
                throw new AuthenticationException(sprintf(
                    $this->translate('Authorization server rejected the token request: %s'),
                    $tokens->error
                ));
            }

            throw new AuthenticationException($this->translate(
                'Authorization server did not return an ID token. Check the provider configuration.'
            ));
        }

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

            $userinfoEndpoint = $login->discovered->userinfo_endpoint;
            $userinfo = Login::requestJson('userinfo', $userinfoEndpoint, fn () => $client->get(
                $userinfoEndpoint,
                ['headers' => ['Authorization' => "Bearer $tokens->access_token"]]
            ));

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

        if (is_string($groups)) {
            $groups = array_filter(Str::trimSplit($groups));
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
        AuthenticationHook::triggerLogin($user);
        $this->redirectNow($redirectUrl);
    }
}
