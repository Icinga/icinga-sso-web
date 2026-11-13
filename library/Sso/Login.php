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
     * Redirect the user to the authorization endpoint of the given provider and exit
     *
     * Stores the login state in the session. After the login,
     * {@see \Icinga\Module\Sso\Controllers\OidcController::redirectionEndpointAction()}
     * redirects the user to the given target.
     *
     * @param ConfigObject<string> $config Provider configuration
     * @param object $openidCfg Discovery document of the provider
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
