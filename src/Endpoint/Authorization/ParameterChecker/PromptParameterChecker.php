<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization\ParameterChecker;

use Assert\Assertion;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;

final class PromptParameterChecker implements ParameterCheckerInterface
{
    const PROMPT_NONE = 'none';
    const PROMPT_LOGIN = 'login';
    const PROMPT_CONSENT = 'consent';
    const PROMPT_SELECT_ACCOUNT = 'select_account';

    /**
     * {@inheritdoc}
     */
    public function checkerParameter(ClientInterface $client, array &$parameters)
    {
        if (!array_key_exists('prompt', $parameters)) {
            return;
        }
        Assertion::true(empty(array_diff($parameters['prompt'], $this->getAllowedPromptValues())), sprintf('Invalid parameter "prompt". Allowed values are %s', json_encode($this->getAllowedPromptValues())));
        Assertion::false(in_array('none', $parameters['prompt']) && 1 !== count($parameters['prompt']), 'Invalid parameter "prompt". Prompt value "none" must be used alone.');
    }

    /**
     * {@inheritdoc}
     */
    public function getError()
    {
        return ExceptionManagerInterface::INVALID_REQUEST;
    }

    /**
     * @return string[]
     */
    private function getAllowedPromptValues()
    {
        return [
            self::PROMPT_NONE,
            self::PROMPT_LOGIN,
            self::PROMPT_CONSENT,
            self::PROMPT_SELECT_ACCOUNT,
        ];
    }
}
