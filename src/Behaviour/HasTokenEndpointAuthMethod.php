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

use OAuth2\Client\AuthenticationMethod\AuthenticationMethodInterface;

trait HasTokenEndpointAuthMethod
{
    /**
     * @var \OAuth2\Client\AuthenticationMethod\AuthenticationMethodInterface[]
     */
    private $authentication_methods = [];

    /**
     * @param \OAuth2\Client\AuthenticationMethod\AuthenticationMethodInterface $authentication_method
     */
    public function addAuthenticationMethod(AuthenticationMethodInterface $authentication_method)
    {
        $this->authentication_methods[] = $authentication_method;
    }

    /**
     * @return array
     */
    public function getSupportedAuthenticationMethods()
    {
        $result = [];
        foreach ($this->getAuthenticationMethods() as $method) {
            $result = array_merge(
                $result,
                $method->getSupportedAuthenticationMethods()
            );
        }

        return array_unique($result);
    }

    /**
     * @return \OAuth2\Client\AuthenticationMethod\AuthenticationMethodInterface[]
     */
    private function getAuthenticationMethods()
    {
        return $this->authentication_methods;
    }
}
