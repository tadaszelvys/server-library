<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\TokenIntrospection;

use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\TokenTypeHint\TokenTypeHintInterface;
use OAuth2\TokenTypeHint\TokenTypeHintManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

final class TokenIntrospectionEndpoint implements MiddlewareInterface
{
    /**
     * @var TokenTypeHintManagerInterface
     */
    private $tokenTypeHintManager;

    /**
     * TokenIntrospectionEndpoint constructor.
     * @param TokenTypeHintManagerInterface $tokenTypeHintManager
     */
    public function __construct(TokenTypeHintManagerInterface $tokenTypeHintManager)
    {
        $this->tokenTypeHintManager = $tokenTypeHintManager;
    }

    /**
     * @return TokenTypeHintManagerInterface
     */
    protected function getTokenTypeHintManager(): TokenTypeHintManagerInterface
    {
        return $this->tokenTypeHintManager;
    }

    /**
     * @param string $tokenTypeHint
     * @return TokenTypeHintInterface[]
     * @throws OAuth2Exception
     */
    protected function getTokenTypeHint(string $tokenTypeHint): array
    {
        $tokenTypeHints = $this->getTokenTypeHintManager()->getTokenTypeHints();
        if (!array_key_exists($tokenTypeHint, $tokenTypeHints)) {
            throw new OAuth2Exception(
                400,
                [
                    'error' => 'unsupported_token_type',
                    'error_description' => sprintf('The token type hint \'%s\' is not supported. Please use one of the following values: %s.', $tokenTypeHint, implode(', ', array_keys($tokenTypeHints))),
                ]
            );
        }

        $key = array_search($tokenTypeHint, $tokenTypeHints);
        unset($tokenTypeHints[$key]);
        array_unshift($tokenTypeHints, $tokenTypeHint);

        return $tokenTypeHints;
    }

    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        $client = $this->getClient($request);
        $token = $this->getToken($request);
        $hints = $this->getTokenTypeHints($request);

        foreach ($hints as $hint) {
            $result = $hint->find($token);
            if (null !== $result) {
                if ($client->getId()->getValue() === $result->getClient()->getId()->getValue()) {
                    $data = $hint->introspect($result);

                    throw new OAuth2Exception(200, json_encode($data));
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
        throw new OAuth2Exception(200, json_encode(['active' => false]));
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
     * @throws OAuth2Exception
     */
    protected function getTokenTypeHints(ServerRequestInterface $request): array
    {
        $params = $this->getRequestParameters($request);
        $tokenTypeHints = $this->getTokenTypeHintManager()->getTokenTypeHints();

        if (array_key_exists('token_type_hint', $params)) {
            $tokenTypeHint = $params['token_type_hint'];
            if (!array_key_exists($params['token_type_hint'], $tokenTypeHints)) {
                throw new OAuth2Exception(
                    400,
                    [
                        'error' => 'unsupported_token_type',
                        'error_description' => sprintf('The token type hint \'%s\' is not supported. Please use one of the following values: %s.', $params['token_type_hint'], implode(', ', array_keys($tokenTypeHints))),
                    ]
                );
            }

            $hint = $tokenTypeHints[$tokenTypeHint];
            unset($tokenTypeHints[$tokenTypeHint]);
            $tokenTypeHints = [$tokenTypeHint => $hint]+$tokenTypeHints;
        }

        return $tokenTypeHints;
    }

    /**
     * @param ServerRequestInterface $request
     * @return array
     */
    protected function getRequestParameters(ServerRequestInterface $request): array
    {
        $parameters = $request->getParsedBody() ?? [];

        return array_intersect_key($parameters, array_flip(['token', 'token_type_hint']));
    }
}
