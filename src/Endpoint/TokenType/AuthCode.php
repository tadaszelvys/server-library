<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\TokenType;

use OAuth2\Behaviour\HasAuthorizationCodeManager;
use OAuth2\Token\AuthCodeInterface;
use OAuth2\Token\AuthCodeManagerInterface;
use OAuth2\Token\TokenInterface;

final class AuthCode implements IntrospectionTokenTypeInterface, RevocationTokenTypeInterface
{
    use HasAuthorizationCodeManager;

    /**
     * AuthCode constructor.
     *
     * @param \OAuth2\Token\AuthCodeManagerInterface $authorization_code_manager
     */
    public function __construct(AuthCodeManagerInterface $authorization_code_manager)
    {
        $this->setAuthorizationCodeManager($authorization_code_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeHint()
    {
        return 'auth_code';
    }

    /**
     * {@inheritdoc}
     */
    public function getToken($token)
    {
        return $this->getAuthorizationCodeManager()->getAuthCode($token);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeToken(TokenInterface $token)
    {
        if ($token instanceof AuthCodeInterface) {
            $this->getAuthorizationCodeManager()->revokeAuthCode($token);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function introspectToken(TokenInterface $token)
    {
        if (!$token instanceof AuthCodeInterface) {
            return [];
        }

        $result = [
            'active'     => !$token->hasExpired(),
            'client_id'  => $token->getClientPublicId(),
            'exp'        => $token->getExpiresAt(),
        ];
        if (!empty($token->getScope())) {
            $result['scp'] = $token->getScope();
        }

        return $result;
    }
}
