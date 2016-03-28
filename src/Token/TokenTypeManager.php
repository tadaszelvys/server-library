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
    public function findToken(ServerRequestInterface $request, array &$additional_credential_values, TokenTypeInterface &$type = null)
    {
        foreach ($this->getTokenTypes() as $tmp_type) {
            $tmp_additional_credential_values = [];
            $token = $tmp_type->findToken($request, $tmp_additional_credential_values);

            if (null !== $token) {
                $additional_credential_values = $tmp_additional_credential_values;
                $type = $tmp_type;
                return $token;
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
            $schemes[] = $type->getTokenTypeScheme();
        }

        return $schemes;
    }
}
