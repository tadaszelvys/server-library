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

use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasTokenTypeManager;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\TokenTypeManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

final class Listener implements ListenerInterface
{
    use HasExceptionManager;
    use HasTokenTypeManager;
    use HasAccessTokenManager;

    /**
     * UserInfoEndpoint constructor.
     *
     * @param \OAuth2\Token\TokenTypeManagerInterface     $token_type_manager
     * @param \OAuth2\Token\AccessTokenManagerInterface   $access_token_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(TokenTypeManagerInterface $token_type_manager,
                                AccessTokenManagerInterface $access_token_manager,
                                ExceptionManagerInterface $exception_manager
    ) {
        $this->setTokenTypeManager($token_type_manager);
        $this->setAccessTokenManager($access_token_manager);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function handle(ServerRequestInterface $request)
    {
        $this->checkRequestIsSecured($request);

        $additional_credential_values = [];
        $token = $this->getTokenTypeManager()->findToken($request, $additional_credential_values, $type);
        $this->checkToken($token);
        $access_token = $this->getAccessTokenManager()->getAccessToken($token);
        $this->checkAccessToken($type, $access_token, $request, $additional_credential_values);

        return $access_token;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     */
    private function checkRequestIsSecured(ServerRequestInterface $request)
    {
        $server_params = $request->getServerParams();

        $is_secured = !empty($server_params['HTTPS']) && 'on' === mb_strtolower($server_params['HTTPS'], '8bit');

        if (false === $is_secured) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The request must be secured.');
        }
    }

    /**
     * @param \OAuth2\Token\TokenTypeInterface         $type
     * @param \OAuth2\Token\AccessTokenInterface|null  $access_token
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param array                                    $additional_credential_values
     */
    private function checkAccessToken($type, $access_token, ServerRequestInterface $request, array $additional_credential_values)
    {
        if (null === $access_token || false === $type->isTokenRequestValid($access_token, $request, $additional_credential_values)) {
            throw $this->getExceptionManager()->getAuthenticateException(
                ExceptionManagerInterface::INVALID_TOKEN,
                'Access token does not exist or is not valid.',
                ['schemes' => $this->getTokenTypeManager()->getTokenTypeSchemes()]
            );
        }
    }

    /**
     * @param null|string$token
     */
    private function checkToken($token)
    {
        if (null === $token) {
            throw $this->getExceptionManager()->getAuthenticateException(
                ExceptionManagerInterface::INVALID_TOKEN,
                'Access token required.',
                ['schemes' => $this->getTokenTypeManager()->getTokenTypeSchemes()]
            );
        }
    }
}
