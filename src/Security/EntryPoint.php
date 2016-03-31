<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Security;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasTokenTypeManager;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Token\TokenTypeManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class EntryPoint implements EntryPointInterface
{
    use HasExceptionManager;
    use HasTokenTypeManager;

    /**
     * EntryPoint constructor.
     *
     * @param \OAuth2\Token\TokenTypeManagerInterface     $token_type_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(TokenTypeManagerInterface $token_type_manager,
                                ExceptionManagerInterface $exception_manager
    ) {
        $this->setTokenTypeManager($token_type_manager);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function start(ServerRequestInterface $request, ResponseInterface &$response)
    {
        $exception = $this->getExceptionManager()->getAuthenticateException(
            ExceptionManagerInterface::UNAUTHORIZED_CLIENT,
            null,
            ['schemes' => $this->getTokenTypeManager()->getTokenTypeSchemes()]
        );

        $exception->getHttpResponse($response);
    }
}
