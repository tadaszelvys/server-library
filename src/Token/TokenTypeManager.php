<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class TokenTypeManager implements TokenTypeManagerInterface
{
    use HasExceptionManager;

    /**
     * @var \OAuth2\Token\TokenTypeInterface[]
     */
    private $token_types = [];

    /**
     * @var null|string
     */
    private $default_token_type = null;

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
     * {@inheritdoc}
     */
    public function addTokenType(TokenTypeInterface $token_type, $default = false)
    {
        if ($this->hasTokenType($token_type->getTokenTypeName())) {
            return;
        }
        $this->token_types[$token_type->getTokenTypeName()] = $token_type;
        if (null === $this->default_token_type || true === $default) {
            $this->default_token_type = $token_type->getTokenTypeName();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function hasTokenType($token_type_name)
    {
        return array_key_exists($token_type_name, $this->token_types);
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenType($token_type_name)
    {
        if (!$this->hasTokenType($token_type_name)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, sprintf('Unsupported token type "%s".', $token_type_name));
        }

        return $this->token_types[$token_type_name];
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypes()
    {
        return $this->token_types;
    }

    /**
     * {@inheritdoc}
     */
    public function getDefaultTokenType()
    {
        return $this->getTokenType($this->default_token_type);
    }

    /**
     * {@inheritdoc}
     */
    public function findToken(ServerRequestInterface $request)
    {
        foreach ($this->getTokenTypes() as $type) {
            if (null !== $token = $type->findToken($request)) {
                return ['type' => $type, 'token' => $token];
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeSchemes()
    {
        $schemes = [];
        foreach ($this->getTokenTypes() as $type) {
            $schemes[] = $type->getTokenTypeName();
        }

        return $schemes;
    }
}
