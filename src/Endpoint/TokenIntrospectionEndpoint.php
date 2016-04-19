<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint;

use OAuth2\Behaviour\HasClientManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerInterface;
use OAuth2\Endpoint\TokenType\IntrospectionTokenTypeInterface;
use OAuth2\Exception\AuthenticateExceptionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\ResourceServer\ResourceServerInterface;
use OAuth2\Token\TokenInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class TokenIntrospectionEndpoint implements TokenIntrospectionEndpointInterface
{
    use HasExceptionManager;
    use HasClientManager;

    /**
     * @var \OAuth2\Endpoint\TokenType\IntrospectionTokenTypeInterface[]
     */
    private $token_types = [];

    /**
     * TokenIntrospectionEndpoint constructor.
     *
     * @param \OAuth2\Client\ClientManagerInterface $client_manager_supervisor
     * @param \OAuth2\Exception\ExceptionManagerInterface     $exception_manager
     */
    public function __construct(
        ClientManagerInterface $client_manager_supervisor,
        ExceptionManagerInterface $exception_manager
    ) {
        $this->setClientManager($client_manager_supervisor);
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
    public function introspection(ServerRequestInterface $request, ResponseInterface &$response)
    {
        if (!$this->isRequestSecured($request)) {
            $exception = $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The request must be secured.');
            $exception->getHttpResponse($response);

            return;
        }

        $this->getParameters($request, $token, $token_type_hint);

        if (null === $token) {
            $exception = $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "token" is missing');
            $exception->getHttpResponse($response);

            return;
        }

        $client = null;
        try {
            $client = $this->getClientManager()->findClient($request);
        } catch (AuthenticateExceptionInterface $e) {
            $e->getHttpResponse($response);

            return;
        }

        $this->getTokenInformation($response, $token, $client, $token_type_hint);
    }

    /**
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param string                              $token
     * @param \OAuth2\Client\ClientInterface      $client
     * @param string|null                         $token_type_hint
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function getTokenInformation(ResponseInterface &$response, $token, ClientInterface $client, $token_type_hint = null)
    {
        $token_types = $this->getTokenTypes();
        if (null === $token_type_hint) {
            foreach ($token_types as $token_type) {
                if (true === $this->tryIntrospectToken($response, $token_type, $token, $client)) {
                    return;
                }
            }
            $exception = $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Unable to find token or client not authenticated.');
            $exception->getHttpResponse($response);
        } elseif (array_key_exists($token_type_hint, $token_types)) {
            $token_type = $token_types[$token_type_hint];
            if (false === $this->tryIntrospectToken($response, $token_type, $token, $client)) {
                $exception = $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Unable to find token or client not authenticated.');
                $exception->getHttpResponse($response);
            }
        } else {
            $exception = $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Unsupported token type hint');
            $exception->getHttpResponse($response);
        }
    }

    /**
     * @param \Psr\Http\Message\ResponseInterface                        $response
     * @param \OAuth2\Endpoint\TokenType\IntrospectionTokenTypeInterface $token_type
     * @param string                                                     $token
     * @param \OAuth2\Client\ClientInterface                             $client
     *
     * @return bool
     */
    private function tryIntrospectToken(ResponseInterface &$response, IntrospectionTokenTypeInterface $token_type, $token, ClientInterface $client)
    {
        $result = $token_type->getToken($token);
        if ($result instanceof TokenInterface) {
            if ($result->getClientPublicId() === $client->getPublicId() || $client instanceof ResourceServerInterface) {
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
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return bool
     */
    private function isRequestSecured(ServerRequestInterface $request)
    {
        $server_params = $request->getServerParams();

        return !empty($server_params['HTTPS']) && 'on' === mb_strtolower($server_params['HTTPS'], '8bit');
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
