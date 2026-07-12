<?php

// SPDX-FileCopyrightText: 2026 Icinga GmbH <https://icinga.com>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Icinga\Module\Sso\ProvidedHook;

use GuzzleHttp\Client;
use Icinga\Application\Config;
use Icinga\Application\Hook\LoginButtonHook;
use Icinga\Application\Icinga;
use Icinga\Authentication\LoginButton;
use Icinga\Data\ConfigObject;
use Icinga\Util\Json;
use Icinga\Web\Session;
use ipl\Html\Text;
use ipl\I18n\Translation;
use ipl\Stdlib\Str;
use ipl\Web\Url;

class ButtonHook extends LoginButtonHook
{
    use Translation;

    /** @var string Session key used to prevent auto-redirect loops (e.g. after a failed IdP login) */
    private const AUTO_REDIRECT_GUARD = 'auto_redirect_attempted';

    public function getButtons(): array
    {
        $providers = Config::module('sso', 'providers');

        $this->maybeAutoRedirect($providers);

        $buttons = [];

        foreach ($providers as $id => $section) {
            $buttons[$id] = new LoginButton(
                function () use ($section): void {
                    $this->login($section);
                },
                new Text(sprintf($this->translate('Login with %s'), $section->name))
            );
        }

        return $buttons;
    }

    /**
     * Redirect straight to the sole configured provider if it is set up for automatic redirection
     *
     * Only triggers for plain GET requests to avoid interfering with form submissions, and refuses to
     * redirect again within the same session once it already tried once, to avoid bouncing the user back
     * and forth if the provider itself sends them back to the login page (e.g. on error). Appending
     * ?ssoSkip=1 to the login URL always shows the normal login form instead, e.g. to reach a local
     * fallback account while the provider is unreachable.
     */
    protected function maybeAutoRedirect(iterable $providers): void
    {
        $request = Icinga::app()->getRequest();

        if ($request->getMethod() !== 'GET' || $request->getUrl()->getParam('ssoSkip')) {
            return;
        }

        $sole = null;
        $count = 0;
        foreach ($providers as $section) {
            $count++;
            $sole = $section;
        }

        if ($count !== 1 || $sole->get('auto_redirect') !== 'y') {
            return;
        }

        $guard = Session::getSession()->getNamespace('sso');
        if ($guard->get(self::AUTO_REDIRECT_GUARD)) {
            return;
        }

        $guard->set(self::AUTO_REDIRECT_GUARD, true);

        $this->login($sole);
    }

    protected function login(ConfigObject $config): void
    {
        $openidCfg = Json::decode((new Client())->get($config->get('base_url'))->getBody()->getContents());

        $state = function_exists('openssl_random_pseudo_bytes')
            ? bin2hex(openssl_random_pseudo_bytes(16))
            : sprintf('%x', mt_rand());

        Session::getSession()->getNamespace('oidc')->set('login', (object) [
            'ctime'      => time(),
            'state'      => $state,
            'config'     => (object) $config->toArray(),
            'discovered' => $openidCfg
        ]);

        $claims = [$config->get('username_claim') => (object) ['essential' => true]];

        if ($config->get('map_groups') === 'y') {
            $claims[$config->get('groups_claim')] = null;
        }

        $response = Icinga::app()->getResponse();
        $response->setHeader('X-Icinga-Redirect-Http', 'yes');

        // Many providers require the offline_access scope for refresh tokens.
        // Others don't know it at all and hard-reject it, but provide refresh tokens by default.
        // Hence, we must include offline_access in the default set, but strip it if it's not supported.
        // Same with the groups scope for group mapping.
        $response->redirectAndExit(Url::fromPath($openidCfg->authorization_endpoint, [
            'client_id'     => $config->get('client_id'),
            'scope'         => implode(' ', array_intersect(
                Str::trimSplit($config->get('scopes'), ' '),
                $openidCfg->scopes_supported
            )),
            'redirect_uri'  => $config->get('redirect_url'),
            'response_type' => 'code',
            'state'         => $state,
            'claims'        => Json::encode((object) ['id_token' => (object) $claims, 'userinfo' => (object) $claims])
        ]));
    }
}
