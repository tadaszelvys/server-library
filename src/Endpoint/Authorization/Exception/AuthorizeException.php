<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization\Exception;

use OAuth2\Endpoint\Authorization\AuthorizationInterface;

class AuthorizeException extends \Exception
{
    /**
     * @var \OAuth2\Endpoint\Authorization\AuthorizationInterface
     */
    private $authorization;

    /**
     * AuthorizationException constructor.
     *
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     */
    public function __construct(AuthorizationInterface $authorization)
    {
        $this->authorization = $authorization;
    }

    /**
     * @return \OAuth2\Endpoint\Authorization\AuthorizationInterface
     */
    public function getAuthorization()
    {
        return $this->authorization;
    }
}
