<?php

// SPDX-FileCopyrightText: 2026 Icinga GmbH <https://icinga.com>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Icinga\Module\Sso;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\GuzzleException;
use Icinga\Application\Icinga;
use Icinga\Application\Logger;
use Icinga\Data\ConfigObject;
use Icinga\Exception\Http\HttpException;
use Icinga\Exception\Json\JsonDecodeException;
use Icinga\Util\Json;
use Icinga\Web\Session;
use ipl\I18n\StaticTranslator;
use ipl\Stdlib\Str;
use ipl\Web\Url;
use Psr\Http\Message\ResponseInterface;

/**
 * OIDC login with a provider and the requests to its authorization server
 */
class Login
{
    /**
     * Fetch the discovery document of the given provider
     *
     * Logs the details of a failure once. The exception message alone must tell users what went wrong, because the
     * login page and the error page show nothing else.
     *
     * @param ConfigObject<string> $config Provider configuration
     *
     * @return object Discovery document, whose `authorization_endpoint` is a string
     *
     * @throws HttpException If the request fails or the response is invalid
     */
    public static function discover(ConfigObject $config): object
    {
        $url = $config->get('base_url');
        $openidCfg = static::requestJson('discovery', $url, fn (): ResponseInterface => (new Client())->get($url));

        if (! is_object($openidCfg) || ! is_string($openidCfg->authorization_endpoint ?? null)) {
            Logger::error('OIDC discovery response from %s has no authorization endpoint', $url);

            throw static::invalidResponse('discovery');
        }

        return $openidCfg;
    }

    /**
     * Send a request to the authorization server and decode its JSON response
     *
     * Logs the details of a failure once and throws an exception with a message that tells an unreachable server apart
     * from a rejection and an invalid response.
     *
     * @param string $name Name of the request, e.g. `token`
     * @param string $url URL of the request, for the log
     * @param callable(): ResponseInterface $request Sends the request
     *
     * @return mixed Decoded response body
     *
     * @throws HttpException If the request fails or the response is no valid JSON
     */
    public static function requestJson(string $name, string $url, callable $request): mixed
    {
        try {
            $response = $request();
        } catch (GuzzleException $e) {
            // Not chained as previous: the error page shows previous messages, which may contain the server response.
            Logger::error('OIDC %s request failed: %s', $name, $e);

            if ($e instanceof BadResponseException) {
                $message = static::translate(
                    'Authorization server rejected the %s request. Check the provider configuration.'
                );
            } else {
                $message = static::translate(
                    'Failed to reach the authorization server with the %s request. Check its URL, DNS and TLS.'
                );
            }

            // 502 because the upstream request failed.
            throw new HttpException(502, sprintf($message, $name));
        }

        try {
            return Json::decode($response->getBody()->getContents());
        } catch (JsonDecodeException $e) {
            Logger::error('OIDC %s response from %s is no valid JSON: %s', $name, $url, $e);

            throw static::invalidResponse($name);
        }
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

    /**
     * Create the exception for an invalid response of the authorization server
     *
     * @param string $name Name of the request, e.g. `token`
     *
     * @return HttpException
     */
    protected static function invalidResponse(string $name): HttpException
    {
        return new HttpException(502, sprintf(
            static::translate('Authorization server sent an invalid %s response. Check the provider configuration.'),
            $name
        ));
    }

    /**
     * Translate a message
     *
     * @param string $message
     *
     * @return string Translated message, or the original message if no translation exists
     */
    protected static function translate(string $message): string
    {
        return StaticTranslator::$instance->translate($message);
    }
}
