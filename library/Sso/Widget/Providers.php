<?php

// SPDX-FileCopyrightText: 2026 Icinga GmbH <https://icinga.com>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Icinga\Module\Sso\Widget;

use Icinga\Application\Config;
use ipl\Html\Table;
use ipl\I18n\Translation;
use ipl\Web\Url;
use ipl\Web\Widget\ActionLink;
use ipl\Web\Widget\Link;

class Providers extends Table
{
    use Translation;

    protected $defaultAttributes = ['class' => 'common-table'];

    protected function assemble(): void
    {
        $this->getHeader()->addHtml(static::row([$this->translate('Name'), $this->translate('Remove')], null, 'th'));

        foreach (Config::module('sso', 'providers') as $id => $section) {
            $this->getBody()->addHtml(static::row([
                new Link($section->name, Url::fromPath('sso/providers/edit', ['id' => $id]), [
                    'data-icinga-modal'   => true,
                    'data-no-icinga-ajax' => true
                ]),
                new ActionLink(null, Url::fromPath('sso/providers/remove', ['id' => $id]), 'remove', [
                    'data-icinga-modal'   => true,
                    'data-no-icinga-ajax' => true
                ])
            ]));
        }
    }
}
