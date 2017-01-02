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
use OAuth2\TokenTypeHint\TokenTypeHintInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response;

abstract class TokenRevocationEndpoint implements MiddlewareInterface
{
    /**
     * @var TokenTypeHintInterface[]
     */
    private $tokenTypeHints = [];

    /**
     * @param TokenTypeHintInterface $tokenTypeHint
     */
    public function addTokenTypeHint(TokenTypeHintInterface $tokenTypeHint)
    {
        $this->tokenTypeHints[$tokenTypeHint->getTokenTypeHint()] = $tokenTypeHint;
    }

    /**
     * @return TokenTypeHintInterface[]
     */
    protected function getTokenTypeHints()
    {
        return $this->tokenTypeHints;
    }

    /**
     * @param string $tokenTypeHint
     * @return TokenTypeHintInterface
     * @throws OAuth2Exception
     */
    protected function getTokenTypeHint(string $tokenTypeHint): TokenTypeHintInterface
    {
        if (!array_key_exists($tokenTypeHint, $this->getTokenTypeHints())) {
            throw new OAuth2Exception(
                400,
                [
                    'error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'error_description' => sprintf('The token type hint \'%s\' is not supported. Please use one of the following values:  %s', $tokenTypeHint, implode(' ', array_keys($this->getTokenTypeHints()))),
                ]
            );
        }

        return $this->tokenTypeHints[$tokenTypeHint];
    }

    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        $callback = $this->getCallback($request);
        try{
            $client = $this->getClient($request);
            $token = $this->getToken($request);
            $hints = $this->getHints($request);

            foreach ($hints as $hint) {
                $token = $hint->find($token);
                if (null !== $token) {
                    if ($client->getId()->getValue() === $token->getClient()->getId()->getValue()) {
                        $hint->revoke($token);

                        return $this->getResponse(200, '', $callback);
                    } else {
                        throw new OAuth2Exception(
                            400,
                            [
                                'error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                                'error_description' => 'The parameter \'token\' is invalid.',
                            ]
                        );
                    }

                }
            }

            throw new OAuth2Exception(
                400,
                [
                    'error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'error_description' => 'The parameter \'token\' is invalid.',
                ]
            );
        } catch (OAuth2Exception $e) {
            return $this->getResponse($e->getCode(), json_encode($e->getData()), $callback);
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
        if (null !== $callback) {
            $data = sprintf('%s(%s)', $callback, $data);
        }

        $response = new Response('php://memory', $code);
        $response->getBody()->write($data);

        return $response;
    }

    /**
     * @param ServerRequestInterface $request
     * @return Client
     * @throws OAuth2Exception
     */
    private function getClient(ServerRequestInterface $request): Client
    {
        $client = $request->getAttribute('client');
        if (null === $client) {
            throw new OAuth2Exception(
                401,
                [
                    'error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_CLIENT,
                    'error_description' => 'Client not authenticated.',
                ]
            );
        }

        return $client;
    }

    /**
     * @param ServerRequestInterface $request
     * @return string
     * @throws OAuth2Exception
     */
    protected function getToken(ServerRequestInterface $request): string
    {
        $params = $this->getRequestParameters($request);
        if (!array_key_exists('token', $params)) {
            throw new OAuth2Exception(
                400,
                [
                    'error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'error_description' => 'The parameter \'token\' is missing.',
                ]
            );
        }

        return $params['token'];
    }

    /**
     * @param ServerRequestInterface $request
     * @return TokenTypeHintInterface[]
     */
    protected function getHints(ServerRequestInterface $request): array
    {
        $params = $request->getParsedBody();
        if (array_key_exists('token_type_hint', $params)) {
            return [$this->getTokenTypeHint($params['token_type_hint'])];
        }

        return $this->getTokenTypeHints();
    }

    /**
     * @param ServerRequestInterface $request
     * @return null|string
     */
    protected function getCallback(ServerRequestInterface $request)
    {
        $params = $request->getParsedBody();
        if (array_key_exists('callback', $params)) {
            return $params['callback'];
        }
    }

    /**
     * @param ServerRequestInterface $request
     * @return array
     */
    abstract protected function getRequestParameters(ServerRequestInterface $request): array;
}
