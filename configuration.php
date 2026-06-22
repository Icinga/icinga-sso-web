<?php

// SPDX-FileCopyrightText: 2026 Icinga GmbH <https://icinga.com>
// SPDX-License-Identifier: GPL-3.0-or-later

/** @var \Icinga\Application\Modules\Module $this */

$this->provideConfigTab('providers', [
    'label' => $this->translate('Providers'),
    'title' => $this->translate('Manage OpenID providers'),
    'icon'  => 'users',
    'url'   => 'providers'
]);
