<?php

// SPDX-FileCopyrightText: 2026 Icinga GmbH <https://icinga.com>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Icinga\Module\Sso\ProvidedHook;

use GuzzleHttp\Client;
use Icinga\Application\Config;
use Icinga\Application\Hook\LoginButtonHook;
use Icinga\Authentication\LoginButton;
use Icinga\Module\Sso\Login;
use Icinga\Util\Json;
use ipl\Html\Text;
use ipl\I18n\Translation;
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
                    Login::start(
                        $section,
                        Json::decode((new Client())->get($section->get('base_url'))->getBody()->getContents()),
                        Url::fromRequest()->getParam('redirect')
                    );
                },
                new Text(sprintf($this->translate('Login with %s'), $section->name))
            );
        }

        return $buttons;
    }
}
