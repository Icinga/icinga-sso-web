<?php

// SPDX-FileCopyrightText: 2026 Icinga GmbH <https://icinga.com>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Icinga\Module\Sso\Controllers;

use GuzzleHttp\Psr7\ServerRequest;
use Icinga\Exception\NotFoundError;
use Icinga\Module\Sso\Form\ConfirmRemovalForm;
use Icinga\Module\Sso\Form\ProviderForm;
use Icinga\Module\Sso\Widget\Providers;
use ipl\Html\Form;
use ipl\Web\Compat\CompatController;
use ipl\Web\Url;
use ipl\Web\Widget\ButtonLink;

class ProvidersController extends CompatController
{
    public function init(): void
    {
        $this->assertPermission('config/modules');
        parent::init();
    }

    public function indexAction(): void
    {
        $this->addControl(new ButtonLink(
            $this->translate('New'),
            'sso/providers/create',
            'plus',
            [
                'data-icinga-modal'   => true,
                'data-no-icinga-ajax' => true
            ]
        ));

        $this->addContent(new Providers());

        foreach ($this->Module()->getConfigTabs()->activate('providers')->getTabs() as $tab) {
            $this->tabs->add($tab->getName(), $tab);
        }
    }

    public function createAction(): void
    {
        $this->modalizeForm((new ProviderForm())->on(ProviderForm::ON_SUCCESS, function (ProviderForm $form): void {
            $config = $this->Config('providers');
            $config->setSection(uniqid(), $form->getFlatValues());
            $config->saveIni();
        }));

        $this->setTitle($this->translate('New Provider'));
    }

    public function editAction(): void
    {
        $id = $this->params->getRequired('id');
        $config = $this->Config('providers');

        if (! $config->hasSection($id)) {
            throw new NotFoundError($this->translate('Provider not found'));
        }

        $section = $config->getSection($id)->toArray();

        // In the config file, advanced settings are stored directly in the section (flat),
        // but the form expects them to be under the advanced_settings fieldset (nested).
        $section['advanced_settings'] = $section;

        $this->modalizeForm(
            (new ProviderForm())
                ->populate($section)
                ->on(ProviderForm::ON_SUCCESS, function (ProviderForm $form) use ($id, $config): void {
                    $config->setSection($id, $form->getFlatValues());
                    $config->saveIni();
                })
        );

        $this->setTitle($this->translate('Edit Provider'));
    }

    public function removeAction(): void
    {
        $id = $this->params->getRequired('id');
        $config = $this->Config('providers');

        if (! $config->hasSection($id)) {
            throw new NotFoundError($this->translate('Provider not found'));
        }

        $this->modalizeForm(
            (new ConfirmRemovalForm())->on(ConfirmRemovalForm::ON_SUCCESS, function () use ($id, $config): void {
                $config->removeSection($id);
                $config->saveIni();
            })
        );

        $this->setTitle($this->translate('Remove Provider'));
    }

    /**
     * Make $form submitting to the containing modal (if any), not the page in the background.
     * Let it handle the current request and add it to the content.
     * Also redirect to the page in the background on success.
     * Call after $form->on(Form::ON_SUCCESS)!
     *
     * @param Form $form
     */
    protected function modalizeForm(Form $form): void
    {
        $form->on(Form::ON_SUCCESS, function (): void {
            $this->redirectNow('__REFRESH__');
        });

        $form->setAction(Url::fromRequest()->getAbsoluteUrl());
        $form->handleRequest(ServerRequest::fromGlobals());
        $this->addContent($form);
    }
}
