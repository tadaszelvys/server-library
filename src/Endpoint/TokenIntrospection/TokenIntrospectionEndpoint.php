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

use Assert\Assertion;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use OAuth2\Endpoint\TokenType\IntrospectionTokenTypeInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

abstract class TokenIntrospectionEndpoint implements MiddlewareInterface
{
    /**
     * @var IntrospectionTokenTypeInterface[]
     */
    private $tokenTypes = [];

    /**
     * @param IntrospectionTokenTypeInterface $tokenType
     */
    public function addIntrospectionTokenType(IntrospectionTokenTypeInterface $tokenType)
    {
        $this->tokenTypes[$tokenType->getTokenTypeHint()] = $tokenType;
    }

    /**
     * @return IntrospectionTokenTypeInterface[]
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
        $this->getParameters($request, $token, $tokenTypeHint);
        try {
            Assertion::notNull($token, 'Parameter \'token\' is missing.');
            $client = $request->getAttribute('client');
            Assertion::notNull($client, 'Unable to find token or client not authenticated.');

            $this->getTokenInformation($token, $client, $tokenTypeHint);
        } catch (\InvalidArgumentException $e) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => $e->getMessage()]);
        }
    }

    /**
     * @param string      $token
     * @param Client      $client
     * @param string|null $tokenTypeHint
     *
     * @throws OAuth2Exception
     */
    private function getTokenInformation(string $token, Client $client, string $tokenTypeHint = null)
    {
        $tokenTypes = $this->getTokenTypes();
        if (null === $tokenTypeHint) {
            foreach ($tokenTypes as $tokenType) {
                $this->tryIntrospectToken($tokenType, $token, $client);
            }
            throw new \InvalidArgumentException('Unable to find token or client not authenticated.');
        } elseif (array_key_exists($tokenTypeHint, $tokenTypes)) {
            $tokenType = $tokenTypes[$tokenTypeHint];
            $this->tryIntrospectToken($tokenType, $token, $client);
            throw new \InvalidArgumentException('Unable to find token or client not authenticated.');
        }
        throw new OAuth2Exception(501, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'Unsupported token type hint.']);
    }

    /**
     * @param IntrospectionTokenTypeInterface $tokenType
     * @param string                          $token
     * @param Client                          $client
     *
     * @throws OAuth2Exception
     */
    private function tryIntrospectToken(IntrospectionTokenTypeInterface $tokenType, string $token, Client $client)
    {
        $result = $tokenType->getToken($token);
        if (null !== $result) {
            if ($result->getClientPublicId() === $client->getPublicId()) {
                $data = $tokenType->introspectToken($result, $client);
                return $this->getResponseFactoryManager()->getResponse(200, $data)->getResponse();
            }
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param string|null                              $token
     * @param string|null                              $tokenTypeHint
     */
    abstract protected function getParameters(ServerRequestInterface $request, &$token, &$tokenTypeHint);
}
