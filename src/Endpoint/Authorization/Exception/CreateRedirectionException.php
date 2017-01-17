<?php

declare(strict_types=1);

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

class CreateRedirectionException extends \Exception
{
    /**
     * @var \OAuth2\Endpoint\Authorization\AuthorizationInterface
     */
    private $authorization;

    /**
     * @var string
     */
    private $description = null;

    /**
     * CreateRedirectionException constructor.
     *
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     * @param string                                                $message
     * @param null|string                                           $description
     */
    public function __construct(AuthorizationInterface $authorization, $message, $description = null)
    {
        parent::__construct($message);
        $this->authorization = $authorization;
        $this->description = $description;
    }

    /**
     * @return \OAuth2\Endpoint\Authorization\AuthorizationInterface
     */
    public function getAuthorization()
    {
        return $this->authorization;
    }

    /**
     * @return null|string
     */
    public function getDescription()
    {
        return $this->description;
    }
}
