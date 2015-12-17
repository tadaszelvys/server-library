<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class AccessTokenTypeManager implements AccessTokenTypeManagerInterface
{
    use HasExceptionManager;

    /**
     * ClientCredentialsGrantType constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(ExceptionManagerInterface $exception_manager)
    {
        $this->setExceptionManager($exception_manager);
    }

    /**
     * @var \OAuth2\Token\AccessTokenTypeInterface[]
     */
    private $access_token_types = [];

    /**
     * @var null|\OAuth2\Token\AccessTokenTypeInterface
     */
    private $default_access_token_type = null;

    /**
     * {@inheritdoc}
     */
    public function addAccessTokenType(AccessTokenTypeInterface $access_token_type, $default = false)
    {
        $this->access_token_types[] = $access_token_type;
        if (null === $this->default_access_token_type || true === $default) {
            $this->default_access_token_type = $access_token_type;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function findAccessToken(ServerRequestInterface $request, AccessTokenTypeInterface &$access_token_type = null)
    {
        foreach ($this->access_token_types as $type) {
            if (null !== $token = $type->findAccessToken($request)) {
                $access_token_type = $type;

                return $token;
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getDefaultAccessTokenType()
    {
        if (null === $this->default_access_token_type) {
            $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'No access token type defined or invalid access token type.');
            throw $exception;
        }

        return $this->default_access_token_type;
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenTypes()
    {
        return $this->access_token_types;
    }
}
