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

namespace OAuth2\Middleware;

use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use OAuth2\TokenType\TokenTypeManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

final class TokenTypeMiddleware implements MiddlewareInterface
{
    /**
     * @var bool
     */
    private $tokenTypeParameterAllowed;

    /**
     * @var TokenTypeManagerInterface
     */
    private $tokenTypeManager;

    /**
     * ClientAuthenticationMiddleware constructor.
     *
     * @param TokenTypeManagerInterface $tokenTypeManager
     * @param bool                      $tokenTypeParameterAllowed
     */
    public function __construct(TokenTypeManagerInterface $tokenTypeManager, bool $tokenTypeParameterAllowed)
    {
        $this->tokenTypeManager = $tokenTypeManager;
    }

    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        $tokenType = $this->findTokenType($request);
        $request = $request->withAttribute('token_type', $tokenType);

        return $delegate->process($request);
    }

    /**
     * @param ServerRequestInterface $request
     *
     * @return \OAuth2\TokenType\TokenTypeInterface
     */
    private function findTokenType(ServerRequestInterface $request)
    {
        $params = $request->getParsedBody();
        if (true === $this->tokenTypeParameterAllowed && array_key_exists('token_type', $params)) {
            return $this->tokenTypeManager->getTokenType($params['token_type']);
        } else {
            return $this->tokenTypeManager->getDefaultTokenType();
        }
    }
}
