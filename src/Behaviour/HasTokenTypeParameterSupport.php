<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Behaviour;

trait HasTokenTypeParameterSupport
{
    /**
     * @var bool
     */
    private $token_type_parameter_allowed = false;

    /**
     * @return \OAuth2\TokenType\TokenTypeManagerInterface
     */
    abstract protected function getTokenTypeManager();

    /**
     * @param array $request_parameters
     *
     * @return \OAuth2\TokenType\TokenTypeInterface
     */
    protected function getTokenTypeFromRequest(array $request_parameters)
    {
        if (true === $this->isAccessTokenTypeParameterAllowed() && array_key_exists('token_type', $request_parameters)) {
            return $this->getTokenTypeManager()->getTokenType($request_parameters['token_type']);
        } else {
            return $this->getTokenTypeManager()->getDefaultTokenType();
        }
    }

    /**
     * @return bool
     */
    public function isAccessTokenTypeParameterAllowed()
    {
        return $this->token_type_parameter_allowed;
    }

    public function allowAccessTokenTypeParameter()
    {
        $this->token_type_parameter_allowed = true;
    }

    public function disallowAccessTokenTypeParameter()
    {
        $this->token_type_parameter_allowed = false;
    }
}
