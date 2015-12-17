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

use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasClientManagerSupervisor;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasRefreshTokenManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerSupervisorInterface;
use OAuth2\Client\ConfidentialClientInterface;
use OAuth2\Endpoint\TokenType\IntrospectionTokenTypeInterface;
use OAuth2\Exception\AuthenticateExceptionInterface;
use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Exception\InternalServerErrorExceptionInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\RefreshTokenManagerInterface;
use OAuth2\Token\TokenInterface;
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
     * @var \OAuth2\Endpoint\TokenType\IntrospectionTokenTypeInterface[]
     */
    private $token_types = [];

    /**
     * TokenIntrospectionEndpoint constructor.
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
     * @param \OAuth2\Endpoint\TokenType\IntrospectionTokenTypeInterface $token_type
     */
    public function addIntrospectionTokenType(IntrospectionTokenTypeInterface $token_type)
    {
        if (!array_key_exists($token_type->getTokenTypeHint(), $this->token_types)) {
            $this->token_types[$token_type->getTokenTypeHint()] = $token_type;
        }
    }

    /**
     * @return \OAuth2\Endpoint\TokenType\IntrospectionTokenTypeInterface[]
     */
    private function getTokenTypes()
    {
        return $this->token_types;
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
        $token_types = $this->getTokenTypes();
        if (null === $token_type_hint) {
            foreach ($token_types as $token_type) {
                if (true === $this->tryIntrospectToken($response, $token_type, $token, $client)) {
                    return;
                }
            }
            $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Unable to find token or client not authenticated.');
            $exception->getHttpResponse($response);
        } elseif (array_key_exists($token_type_hint, $token_types)) {
            $token_type = $token_types[$token_type_hint];
            if (false === $this->tryIntrospectToken($response, $token_type, $token, $client)) {
                $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Unable to find token or client not authenticated.');
                $exception->getHttpResponse($response);
            }
        } else {
            $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Unsupported token type hint');
            $exception->getHttpResponse($response);
        }
    }

    /**
     * @param \Psr\Http\Message\ResponseInterface                        $response
     * @param \OAuth2\Endpoint\TokenType\IntrospectionTokenTypeInterface $token_type
     * @param string                                                     $token
     * @param \OAuth2\Client\ClientInterface|null                        $client
     *
     * @return bool
     */
    private function tryIntrospectToken(ResponseInterface &$response, IntrospectionTokenTypeInterface $token_type, $token, ClientInterface $client = null)
    {
        $result = $token_type->getToken($token);
        if ($result instanceof TokenInterface) {
            if ($this->isClientVerified($result, $client)) {
                $data = $token_type->introspectToken($result);
                $this->populateResponse($response, $data);

                return true;
            }
        }

        return false;
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
     * @param \OAuth2\Token\TokenInterface        $token
     * @param \OAuth2\Client\ClientInterface|null $client
     *
     * @return bool
     */
    private function isClientVerified($token, ClientInterface $client = null)
    {
        if (null !== $client) {
            // The client ID of the token is the same as authenticated client
            return $token->getClientPublicId() === $client->getPublicId();
        } else {
            // We try to get the client associated with the token
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
