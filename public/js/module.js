// SPDX-FileCopyrightText: 2026 Icinga GmbH <https://icinga.com>
// SPDX-License-Identifier: GPL-3.0-or-later

;(function (Icinga) {
    'use strict';

    class ResolveAbsoluteUrl extends Icinga.EventListener {
        constructor(icinga) {
            super(icinga);

            this.on('rendered', '.icinga-module.module-sso', event => this.rendered(event), this);
        }

        rendered(event) {
            for (const input of event.target.getElementsByClassName('resolve-absolute-url')) {
                if (/^\//.exec(input.value)) {
                    // Url::fromPath('module/controller/action')->getAbsoluteUrl() returns a URI relative
                    // to the current host, e.g. /icingaweb2/module/controller/action.
                    // Completing it to an absolute URL on the server side (using $_SERVER) is theoretically possible,
                    // but the quality of the result would depend on all reverse proxies' (if any) configuration.

                    const a = document.createElement('a');
                    a.href = input.value; // Set relative URL
                    input.value = a.href; // Get absolute URL
                }
            }
        }
    }

    Icinga.Behaviors = Icinga.Behaviors || {};
    Icinga.Behaviors.ResolveAbsoluteUrl = ResolveAbsoluteUrl;
})(Icinga);
