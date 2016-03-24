<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Scope;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

final class ErrorScopePolicy implements ScopePolicyInterface
{
    use HasExceptionManager;

    /**
     * ErrorScopePolicy constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(ExceptionManagerInterface $exception_manager)
    {
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'error';
    }

    /**
     * {@inheritdoc}
     */
    public function checkScopePolicy(array &$scope, ClientInterface $client, ServerRequestInterface $request = null)
    {
        if (empty($scope)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_SCOPE, 'No scope was requested.');
        }
    }
}
