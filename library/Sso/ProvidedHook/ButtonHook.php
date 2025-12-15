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

    public function getButtons(): array
    {
        $buttons = [];

        foreach (Config::module('sso', 'providers') as $id => $section) {
            $buttons[$id] = new LoginButton(
                function () use ($section): void {
                    $this->login($section);
                },
                new Text(sprintf($this->translate('Login with %s'), $section->name))
            );
        }

        return $buttons;
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
