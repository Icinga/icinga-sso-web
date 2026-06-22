<?php

// SPDX-FileCopyrightText: 2026 Icinga GmbH <https://icinga.com>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Icinga\Module\Sso\Form;

use Icinga\Web\Session;
use ipl\Web\Common\CsrfCounterMeasure;
use ipl\Web\Compat\CompatForm;

class ConfirmRemovalForm extends CompatForm
{
    use CsrfCounterMeasure;

    protected function assemble(): void
    {
        $this->addElement('submit', 'btn_submit', [
            'label' => $this->translate('Remove'),
            'class' => 'btn-remove'
        ]);

        $this->addElement($this->createCsrfCounterMeasure(Session::getSession()->getId()));
    }
}
