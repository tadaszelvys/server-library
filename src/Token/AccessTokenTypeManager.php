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
use OAuth2\Client\AccessTokenTypeExtensionInterface;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;

class AccessTokenTypeManager implements AccessTokenTypeManagerInterface
{
    use HasExceptionManager;

    /**
     * @var \OAuth2\Token\AccessTokenTypeInterface[]
     */
    private $access_token_types = [];

    /**
     * @var null|string
     */
    private $default_access_token_type = null;

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
    public function addAccessTokenType(AccessTokenTypeInterface $access_token_type, $default = false)
    {
        if ($this->hasAccessTokenType($access_token_type->getTokenTypeName())) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, sprintf('Access token type "%s" already exist.', $access_token_type->getTokenTypeName()));
        }
        $this->access_token_types[$access_token_type->getTokenTypeName()] = $access_token_type;
        if (null === $this->default_access_token_type || true === $default) {
            $this->default_access_token_type = $access_token_type->getTokenTypeName();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function hasAccessTokenType($token_type_name)
    {
        return array_key_exists($token_type_name, $this->access_token_types);
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenType($token_type_name)
    {
        if (!$this->hasAccessTokenType($token_type_name)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, sprintf('Unsupported access token type "%s".', $token_type_name));
        }

        return $this->access_token_types[$token_type_name];
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenTypeForClient(ClientInterface $client)
    {
        if ($client instanceof AccessTokenTypeExtensionInterface && null !== $type = $client->getPreferredTokenType()) {
            return $this->getAccessTokenType($type);
        }
        if (null === $this->default_access_token_type) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'No access token type defined or invalid access token type.');
        }

        return $this->getAccessTokenType($this->default_access_token_type);
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenTypes()
    {
        return $this->access_token_types;
    }
}
