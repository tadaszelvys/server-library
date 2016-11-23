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
use OAuth2\Security\Handler\AccessTokenHandlerInterface;
use OAuth2\TokenType\TokenTypeManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class Listener implements ListenerInterface
{
    use HasExceptionManager;
    use HasTokenTypeManager;

    /**
     * @var \OAuth2\Security\Handler\AccessTokenHandlerInterface
     */
    private $access_token_handler;

    /**
     * Listener constructor.
     *
     * @param \OAuth2\TokenType\TokenTypeManagerInterface          $token_type_manager
     * @param \OAuth2\Security\Handler\AccessTokenHandlerInterface $access_token_handler
     * @param \OAuth2\Exception\ExceptionManagerInterface          $exception_manager
     */
    public function __construct(TokenTypeManagerInterface $token_type_manager, AccessTokenHandlerInterface $access_token_handler, ExceptionManagerInterface $exception_manager)
    {
        $this->setTokenTypeManager($token_type_manager);
        $this->access_token_handler = $access_token_handler;
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function handle(ServerRequestInterface $request, array $additional_authentication_parameters = [])
    {
        $this->checkRequestIsSecured($request);

        $additional_credential_values = [];
        $token = $this->getTokenTypeManager()->findToken($request, $additional_credential_values, $type);
        $this->checkToken($token, $additional_authentication_parameters);
        $access_token = $this->access_token_handler->getAccessToken($token);
        $this->checkAccessToken($type, $access_token, $request, $additional_credential_values);

        return $access_token;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     */
    private function checkRequestIsSecured(ServerRequestInterface $request)
    {
        $server_params = $request->getServerParams();

        $is_secured = !empty($server_params['HTTPS']) && 'on' === mb_strtolower($server_params['HTTPS'], '8bit');

        if (false === $is_secured) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::ERROR_INVALID_REQUEST, 'The request must be secured.');
        }
    }

    /**
     * @param \OAuth2\TokenType\TokenTypeInterface         $type
     * @param \OAuth2\Token\AccessTokenInterface|null  $access_token
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param array                                    $additional_credential_values
     *
     * @throws \OAuth2\Exception\AuthenticateExceptionInterface
     */
    private function checkAccessToken($type, $access_token, ServerRequestInterface $request, array $additional_credential_values)
    {
        if (null === $access_token) {
            $schemes = ['schemes' => $this->getTokenTypeManager()->getTokenTypeSchemes(['all' => ['error' => sprintf('"%s"', ExceptionManagerInterface::ERROR_INVALID_TOKEN), 'error_description' => '"Access token does not exist or is not valid."']])];
            throw $this->getExceptionManager()->getAuthenticateException(ExceptionManagerInterface::ERROR_INVALID_TOKEN, 'Access token does not exist or is not valid.', $schemes);
        }
        if (false === $type->isTokenRequestValid($access_token, $request, $additional_credential_values)) {
            $schemes = ['schemes' => $this->getTokenTypeManager()->getTokenTypeSchemes([$type->getTokenTypeName() => ['error' => sprintf('"%s"', ExceptionManagerInterface::ERROR_INVALID_TOKEN), 'error_description' => '"Access token does not exist or is not valid."']])];
            throw $this->getExceptionManager()->getAuthenticateException(ExceptionManagerInterface::ERROR_INVALID_TOKEN, 'Access token does not exist or is not valid.', $schemes);
        }
    }

    /**
     * @param null|string $token
     * @param array       $additional_authentication_parameters
     *
     * @throws \OAuth2\Exception\AuthenticateExceptionInterface
     */
    private function checkToken($token, array $additional_authentication_parameters)
    {
        if (null === $token) {
            $this->mergeAdditionalAuthenticationParameters('all', $additional_authentication_parameters, ['error' => sprintf('"%s"', ExceptionManagerInterface::ERROR_INVALID_TOKEN), 'error_description' => '"Access token required."']);
            throw $this->getExceptionManager()->getAuthenticateException(ExceptionManagerInterface::ERROR_INVALID_TOKEN, 'Access token required.', ['schemes' => $this->getTokenTypeManager()->getTokenTypeSchemes($additional_authentication_parameters)]);
        }
    }

    /**
     * @param string $key
     * @param array  $current
     * @param array  $custom
     */
    private function mergeAdditionalAuthenticationParameters($key, array &$current, array $custom)
    {
        if (array_key_exists($key, $current)) {
            $current[$key] = array_unique(array_merge($current[$key], $custom));
        } else {
            $current[$key] = $custom;
        }
    }
}
