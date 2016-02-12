<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIDConnect;

use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasEndUserManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasTokenTypeManager;
use OAuth2\EndUser\EndUserManagerInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\TokenTypeManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class UserInfoEndpoint implements UserInfoEndpointInterface
{
    use HasExceptionManager;
    use HasTokenTypeManager;
    use HasAccessTokenManager;
    use HasEndUserManager;

    /**
     * UserInfoEndpoint constructor.
     *
     * @param \OAuth2\Token\TokenTypeManagerInterface     $token_type_manager
     * @param \OAuth2\Token\AccessTokenManagerInterface   $access_token_manager
     * @param \OAuth2\EndUser\EndUserManagerInterface     $end_user_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(
        TokenTypeManagerInterface $token_type_manager,
        AccessTokenManagerInterface $access_token_manager,
        EndUserManagerInterface $end_user_manager,
        ExceptionManagerInterface $exception_manager
    ) {
        $this->setTokenTypeManager($token_type_manager);
        $this->setAccessTokenManager($access_token_manager);
        $this->setEndUserManager($end_user_manager);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getUserInfo(ServerRequestInterface $request, ResponseInterface &$response)
    {
        if (!$this->isRequestSecured($request)) {
            $exception = $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Request must be secured');
            $exception->getHttpResponse($response);

            return;
        }

        $token = $this->getTokenTypeManager()->findToken($request);

        if (null === $token) {
            $exception = $this->getExceptionManager()->getAuthenticateException(
                ExceptionManagerInterface::INVALID_TOKEN,
                'Access token required.',
                ['schemes' => $this->getTokenTypeManager()->getTokenTypeSchemes()]
            );
            $exception->getHttpResponse($response);

            return;
        }

        $access_token = $this->getAccessTokenManager()->getAccessToken($token['token']);
        if (null === $access_token || false === $token['type']->isTokenRequestValid($access_token, $request, $token['additional_credential_values'])) {
            $exception = $this->getExceptionManager()->getAuthenticateException(
                ExceptionManagerInterface::INVALID_TOKEN,
                'Access token does not exist or is not valid.',
                ['schemes' => $this->getTokenTypeManager()->getTokenTypeSchemes()]
            );
            $exception->getHttpResponse($response);

            return;
        }

        $end_user = $this->getEndUserManager()->getEndUser($access_token->getResourceOwnerPublicId());
        if (null === $end_user) {
            $exception = $this->getExceptionManager()->getAuthenticateException(
                ExceptionManagerInterface::INVALID_TOKEN,
                'Access token does not exist or is not valid.',
                ['schemes' => $this->getTokenTypeManager()->getTokenTypeSchemes()]
            );
            $exception->getHttpResponse($response);

            return;
        }

        $this->populateResponse($response, $end_user->getUserInfo($access_token));
    }

    /**
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param array                               $data
     */
    private function populateResponse(ResponseInterface &$response, array $data)
    {
        $response = $response->withHeader('Content-Type', 'application/json');
        $response = $response->withHeader('Cache-Control', 'no-store');
        $response = $response->withHeader('Pragma', 'no-cache');
        $response = $response->withStatus(200);
        $response->getBody()->write(json_encode($data));
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return bool
     */
    private function isRequestSecured(ServerRequestInterface $request)
    {
        $server_params = $request->getServerParams();

        return !empty($server_params['HTTPS']) && 'on' === strtolower($server_params['HTTPS']);
    }
}
