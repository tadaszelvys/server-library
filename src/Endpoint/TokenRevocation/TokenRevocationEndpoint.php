<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\TokenRevocation;

use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleBus\Message\Bus\MessageBus;
use Zend\Diactoros\Response;

final class TokenRevocationEndpoint implements MiddlewareInterface
{
    /**
     * @var RevocationTokenTypeInterface[]
     */
    private $tokenTypes = [];

    /**
     * @var MessageBus
     */
    private $messageBus;

    /**
     * ClientConfigurationEndpoint constructor.
     * @param MessageBus                $messageBus
     */
    public function __construct(MessageBus $messageBus)
    {
        $this->messageBus = $messageBus;
    }

    /**
     * @param RevocationTokenTypeInterface $tokenType
     */
    public function addRevocationTokenType(RevocationTokenTypeInterface $tokenType)
    {
        $this->tokenTypes[$tokenType->getTokenTypeHint()] = $tokenType;
    }

    /**
     * @return RevocationTokenTypeInterface[]
     */
    private function getTokenTypes()
    {
        return $this->tokenTypes;
    }

    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        $this->getParameters($request, $token, $tokenType_hint, $callback);

        try {
            if (null === $token) {
                $data = ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'Parameter \'token\' is missing'];
                throw new OAuth2Exception(400, $data);
            }
            $client = $this->tokenEndpointAuthManager->findClient($request);

            if ($client instanceof Client) {
                throw new OAuth2Exception($this->revokeToken($token, $client, $tokenType_hint, $callback));
            }

            return $this->getResponse(200, '', $callback);
        } catch (OAuth2Exception $e) {
            return $this->getResponse($e->getCode(), json_encode($e->getOAuth2Response()->getData()), $callback);
        } catch (\Exception $e) {
            $data = ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'Parameter \'token\' is missing'];
            $oauth2_response = $this->getResponseFactoryManager()->getResponse(400, $data);

            return $this->getResponse($oauth2_response->getCode(), json_encode($oauth2_response->getCode()), $callback);
        }
    }

    /**
     * @param int         $code
     * @param string      $data
     * @param null|string $callback
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    private function getResponse($code, $data, $callback)
    {
        if (null !== ($callback)) {
            $data = sprintf('%s(%s)', $callback, $data);
        }

        $response = new Response('php://memory', $code, []);
        $response->getBody()->write($data);

        return $response;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param string                                   $token
     * @param string|null                              $tokenType_hint
     * @param string|null                              $callback
     */
    private function getParameters(ServerRequestInterface $request, &$token, &$tokenType_hint, &$callback)
    {
        if ('GET' === $request->getMethod()) {
            $params = $request->getQueryParams();
        } elseif ('POST' === $request->getMethod()) {
            $params = RequestBody::getParameters($request);
        } else {
            return;
        }
        foreach (['token', 'tokenType_hint', 'callback'] as $key) {
            $$key = array_key_exists($key, $params) ? $params[$key] : null;
        }
    }

    /**
     * @param string                              $token
     * @param Client      $client
     * @param string|null                         $tokenType_hint
     * @param string|null                         $callback
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    private function revokeToken($token, Client $client, $tokenType_hint = null, $callback = null)
    {
        $tokenTypes = $this->getTokenTypes();
        if (null === $tokenType_hint) {
            foreach ($tokenTypes as $tokenType) {
                if (true === $this->tryRevokeToken($tokenType, $token, $client)) {
                    break;
                }
            }
        } elseif (array_key_exists($tokenType_hint, $tokenTypes)) {
            $tokenType = $tokenTypes[$tokenType_hint];
            $this->tryRevokeToken($tokenType, $token, $client);
        } else {
            $data = ['error' => 'unsupported_tokenType', 'error_description' => sprintf('Token type \'%s\' not supported', $tokenType_hint)];

            return $this->getResponse(501, json_encode($data), $callback);
        }
        return $this->getResponse(200, '', $callback);
    }

    /**
     * @param RevocationTokenTypeInterface $tokenType
     * @param string                                                  $token
     * @param Client                          $client
     *
     * @return bool
     */
    private function tryRevokeToken(RevocationTokenTypeInterface $tokenType, $token, Client $client)
    {
        $result = $tokenType->getToken($token);
        if ($result instanceof OAuth2TokenInterface) {
            if ($result->getClientPublicId() === $client->getPublicId()) {
                $tokenType->revokeToken($result);

                return true;
            }
        }

        return false;
    }
}
