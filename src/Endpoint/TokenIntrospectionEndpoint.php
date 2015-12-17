<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint;

use Jose\Object\JWTInterface;
use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasClientManagerSupervisor;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasRefreshTokenManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerSupervisorInterface;
use OAuth2\Client\ConfidentialClientInterface;
use OAuth2\Exception\AuthenticateExceptionInterface;
use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Exception\InternalServerErrorExceptionInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\RefreshTokenManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class TokenIntrospectionEndpoint implements TokenIntrospectionEndpointInterface
{
    use HasExceptionManager;
    use HasClientManagerSupervisor;
    use HasAccessTokenManager;
    use HasRefreshTokenManager;

    /**
     * RevocationEndpoint constructor.
     *
     * @param \OAuth2\Token\AccessTokenManagerInterface       $access_token_manager
     * @param \OAuth2\Token\RefreshTokenManagerInterface      $refresh_token_manager
     * @param \OAuth2\Client\ClientManagerSupervisorInterface $client_manager_supervisor
     * @param \OAuth2\Exception\ExceptionManagerInterface     $exception_manager
     */
    public function __construct(
        AccessTokenManagerInterface $access_token_manager,
        RefreshTokenManagerInterface $refresh_token_manager,
        ClientManagerSupervisorInterface $client_manager_supervisor,
        ExceptionManagerInterface $exception_manager
    ) {
        $this->setAccessTokenManager($access_token_manager);
        $this->setRefreshTokenManager($refresh_token_manager);
        $this->setClientManagerSupervisor($client_manager_supervisor);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * @var \OAuth2\Endpoint\TokenIntrospectionEndpointExtensionInterface[]
     */
    private $extensions = [];

    /**
     * {@inheritdoc}
     */
    public function addExtension(TokenIntrospectionEndpointExtensionInterface $extension)
    {
        $this->extensions[] = $extension;
    }

    /**
     * {@inheritdoc}
     */
    public function introspect(ServerRequestInterface $request, ResponseInterface &$response)
    {
        if (!$this->isRequestSecured($request)) {
            $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Request must be secured');
            $exception->getHttpResponse($response);

            return;
        }

        $this->getParameters($request, $token, $token_type_hint);

        if (null === $token) {
            $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "token" is missing');
            $exception->getHttpResponse($response);

            return;
        }

        if (null !== $token_type_hint && !in_array($token_type_hint, ['access_token', 'refresh_token'])) {
            $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Unsupported token type hint');
            $exception->getHttpResponse($response);

            return;
        }

        $client = null;
        try {
            $client = $this->getClientManagerSupervisor()->findClient($request);
        } catch (BaseExceptionInterface $e) {
            if ($e instanceof InternalServerErrorExceptionInterface) {
                throw $e;
            }
            if ($e instanceof AuthenticateExceptionInterface) {
                $e->getHttpResponse($response);

                return;
            }
            $client = null;
        }

        $this->getTokenInformation($response, $token, $token_type_hint, $client);
    }

    /**
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param string                              $token
     * @param string|null                         $token_type_hint
     * @param \OAuth2\Client\ClientInterface|null $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function getTokenInformation(ResponseInterface &$response, $token, $token_type_hint = null, ClientInterface $client = null)
    {
        if ('access_token' === $token_type_hint) {
            $this->findAccessTokenAndGetInformation($response, $token, $client);
        } elseif ('refresh_token' === $token_type_hint) {
            $this->findRefreshTokenAndGetInformation($response, $token, $client);
        } else {
            if ($this->findAccessTokenAndGetInformation($response, $token, $client)) {
                return;
            } elseif ($this->findRefreshTokenAndGetInformation($response, $token, $client)) {
                return;
            }
        }
    }

    /**
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param string                              $token
     * @param \OAuth2\Client\ClientInterface      $client
     *
     * @return bool
     */
    private function findAccessTokenAndGetInformation(ResponseInterface &$response, $token, ClientInterface $client = null)
    {
        $access_token = $this->getAccessTokenManager()->getAccessToken($token);
        if (null === $access_token || !$this->isClientVerified($access_token, $client)) {
            $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Unable to find token or client not authenticated.');
            $exception->getHttpResponse($response);

            return true;
        }

        $result = [
            'active'     => !$access_token->hasExpired(),
            'client_id'  => $access_token->getClientPublicId(),
            'token_type' => 'access_token',
        ];
        if (!empty($access_token->getScope())) {
            $result['scope'] = $access_token->getScope();
        }
        if ($access_token instanceof JWTInterface) {
            $result = array_merge($result, $this->getJWTInformation($access_token));
        }
        foreach ($this->extensions as $extension) {
            $result = array_merge($result, $extension->getTokenInformation($access_token));
        }

        $this->populateResponse($response, $result);

        return true;
    }

    /**
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param string                              $token
     * @param \OAuth2\Client\ClientInterface      $client
     *
     * @return bool
     */
    private function findRefreshTokenAndGetInformation(ResponseInterface &$response, $token, ClientInterface $client = null)
    {
        $refresh_token = $this->getRefreshTokenManager()->getRefreshToken($token);
        if (null === $refresh_token || !$this->isClientVerified($refresh_token, $client)) {
            $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Unable to find token or client not authenticated.');
            $exception->getHttpResponse($response);

            return true;
        }

        $result = [
            'active'     => !$refresh_token->hasExpired() && !$refresh_token->isUsed(),
            'client_id'  => $refresh_token->getClientPublicId(),
            'token_type' => 'refresh_token',
        ];
        if (!empty($refresh_token->getScope())) {
            $result['scope'] = $refresh_token->getScope();
        }
        if ($refresh_token instanceof JWTInterface) {
            $result = array_merge($result, $this->getJWTInformation($refresh_token));
        }
        foreach ($this->extensions as $extension) {
            $result = array_merge($result, $extension->getTokenInformation($refresh_token));
        }

        $this->populateResponse($response, $result);

        return true;
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
     * @param \Jose\Object\JWTInterface $token
     *
     * @return array
     */
    private function getJWTInformation(JWTInterface $token)
    {
        $result = [];
        foreach (['exp', 'iat', 'nbf', 'sub', 'aud', 'iss', 'jti'] as $key) {
            if ($token->hasClaim($key)) {
                $result[$key] = $token->getClaim($key);
            }
        }

        return $result;
    }

    /**
     * @param \OAuth2\Token\AccessTokenInterface|\OAuth2\Token\RefreshTokenInterface $token
     * @param \OAuth2\Client\ClientInterface|null                                    $client
     *
     * @return bool
     */
    private function isClientVerified($token, ClientInterface $client = null)
    {
        if (null !== $client) {
            // The client ID of the token is the same as client authenticated
            return $token->getClientPublicId() === $client->getPublicId();
        } else {
            // We try to get the client
            $client = $this->getClientManagerSupervisor()->getClient($token->getClientPublicId());

            // Return false if the client is a confidential client (confidential client must be authenticated)
            return !$client instanceof ConfidentialClientInterface;
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return bool
     */
    private function isRequestSecured(ServerRequestInterface $request)
    {
        $server_params = $request->getServerParams();

        return !empty($server_params['HTTPS']) && 'off' !== strtolower($server_params['HTTPS']);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param string|null                              $token
     * @param string|null                              $token_type_hint
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function getParameters(ServerRequestInterface $request, &$token, &$token_type_hint)
    {
        $query_params = $request->getQueryParams();
        $body_params = RequestBody::getParameters($request);
        $token = array_key_exists('token', $query_params) ? $query_params['token'] : (array_key_exists('token', $body_params) ? $body_params['token'] : null);
        $token_type_hint = array_key_exists('token_type_hint', $query_params) ? $query_params['token_type_hint'] : (array_key_exists('token_type_hint', $body_params) ? $body_params['token_type_hint'] : null);
    }
}
