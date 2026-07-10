<?php

// SPDX-FileCopyrightText: 2026 Icinga GmbH <https://icinga.com>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Icinga\Module\Sso\Form;

use GuzzleHttp\Client;
use Icinga\Util\Json;
use Icinga\Web\Session;
use ipl\Html\FormElement\FieldsetElement;
use ipl\I18n\Translation;
use ipl\Validator\RegexMatchValidator;
use ipl\Validator\RegexSyntaxValidator;
use ipl\Web\Common\CsrfCounterMeasure;
use ipl\Web\Compat\CompatForm;
use ipl\Web\Url;
use Throwable;

class ProviderForm extends CompatForm
{
    use CsrfCounterMeasure;
    use Translation;

    protected function assemble(): void
    {
        $this->addElement('text', 'name', [
            'label'       => $this->translate('Name'),
            'description' => $this->translate('Display Name'),
            'required'    => true
        ]);

        $this->addElement('text', 'base_url', [
            'label'       => $this->translate('Discovery URL'),
            'description' => $this->translate('Must end with /.well-known/openid-configuration'),
            'placeholder' => 'https://example.com/.well-known/openid-configuration',
            'required'    => true,
            'class'       => 'autosubmit',
            'validators'  => [new RegexMatchValidator([
                'pattern'         => '~\Ahttps?://~',
                'notMatchMessage' => $this->translate('The URL must start with http:// or https://')
            ])]
        ]);

        $this->addElement('text', 'client_id', [
            'label'       => $this->translate('Client ID'),
            'description' => $this->translate('Identifies your OAuth application to the provider'),
            'required'    => true
        ]);

        $this->addElement('password', 'client_secret', [
            'label'       => $this->translate('Client Secret'),
            'description' => $this->translate('Authenticates your OAuth application to the provider'),
            'required'    => true
        ]);

        // Many providers require the offline_access scope for refresh tokens
        $this->addElement('text', 'scopes', [
            'label'       => $this->translate('OAuth Scopes'),
            'description' => $this->translate('Space separated, your OAuth application must allow these'),
            'value'       => 'openid profile offline_access groups',
        ]);

        $this->addElement('text', 'redirect_url', [
            'label'       => $this->translate('Redirect URL'),
            'description' => $this->translate(
                'Must point to this Icinga Web instance and match your OAuth application configuration'
            ),
            'value'       => Url::fromPath('sso/oidc/redirection-endpoint')->getAbsoluteUrl(),
            'class'       => 'resolve-absolute-url',
            'required'    => true
        ]);

        $this->addElement('text', 'username_claim', [
            'label'       => $this->translate('Username Field'),
            'description' => $this->translate('Claim providing the desired username'),
            'value'       => 'preferred_username',
            'required'    => true
        ]);

        $this->addElement('checkbox', 'map_groups', [
            'label'       => $this->translate('Map Groups'),
            'description' => $this->translate('Apply group memberships from the provider to Icinga Web'),
            'value'       => 'y',
            'class'       => 'autosubmit'
        ]);

        $this->addElement('text', 'groups_claim', [
            'label'       => $this->translate('Groups Field'),
            'description' => $this->translate('Claim providing the desired groups'),
            'value'       => 'groups',
            'required'    => $this->getPopulatedValue('map_groups', 'y') === 'y'
        ]);

        $advanced = new FieldsetElement('advanced_settings');
        $advanced->setLabel($this->translate('Advanced Settings'));
        $this->addElement($advanced);

        $advanced->addElement('text', 'username_search', [
            'label'       => $this->translate('Username Search Regex'),
            'description' => $this->translate('Regular expression to search for in upstream usernames'),
            'placeholder' => '/(.+)/i',
            'validators'  => [new RegexSyntaxValidator()]
        ]);

        $advanced->addElement('text', 'username_replace', [
            'label'       => $this->translate('Username Search Replacement'),
            'description' => $this->translate('What to replace occurrences of the above regex with'),
            'placeholder' => '${1}'
        ]);

        $advanced->addElement('text', 'groupname_search', [
            'label'       => $this->translate('Group Name Search Regex'),
            'description' => $this->translate('Regular expression to search for in upstream group names'),
            'placeholder' => '/(.+)/i',
            'validators'  => [new RegexSyntaxValidator()]
        ]);

        $advanced->addElement('text', 'groupname_replace', [
            'label'       => $this->translate('Group Name Search Replacement'),
            'description' => $this->translate('What to replace occurrences of the above regex with'),
            'placeholder' => '${1}'
        ]);

        $this->addElement('submit', 'btn_submit', [
            'label' => $this->translate('Save')
        ]);

        $this->addElement($this->createCsrfCounterMeasure(Session::getSession()->getId()));
    }

    public function validate(): static
    {
        parent::validate();
        if (! $this->isValid) {
            return $this;
        }

        if ($this->getPopulatedValue('force_creation') === 'y') {
            return $this;
        }

        try {
            Json::decode((new Client())->get($this->getValue('base_url'))->getBody()->getContents());
        } catch (Throwable $e) {
            $this->addMessage(
                $this->translate('Failed to contact the OpenID provider: %s'),
                $e->getMessage()
            );

            $forceCheckbox = $this->createElement(
                'checkbox',
                'force_creation',
                [
                    'ignore'      => true,
                    'label'       => $this->translate('Force Changes'),
                    'description' => $this->translate(
                        'Check this box to enforce changes without connectivity validation'
                    )
                ]
            );

            $this->registerElement($forceCheckbox);
            $this->decorate($forceCheckbox);
            $this->prepend($forceCheckbox);

            $this->isValid = false;
        }

        return $this;
    }

    /**
     * Just like {@link getValues}, but flattens array values (fieldset) into the top-level array
     *
     * @return array
     */
    public function getFlatValues(): array
    {
        $values = [];

        foreach ($this->getValues() as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $subKey => $subValue) {
                    $values[$subKey] = $subValue;
                }
            } else {
                $values[$key] = $value;
            }
        }

        return $values;
    }
}
