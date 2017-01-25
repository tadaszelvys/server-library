<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\ClientRegistration;

use Assert\Assertion;
use Interop\Http\Factory\ResponseFactoryInterface;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use OAuth2\Command\Client\CreateClientCommand;
use OAuth2\DataTransporter;
use OAuth2\Model\Client\Client;
use OAuth2\Model\InitialAccessToken\InitialAccessToken;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManager;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleBus\Message\Bus\MessageBus;
use Webmozart\Json\JsonEncoder;

final class ClientRegistrationEndpoint implements MiddlewareInterface
{
    /**
     * @var MessageBus
     */
    private $messageBus;

    /**
     * @var ResponseFactoryInterface
     */
    private $responseFactory;

    /**
     * @var JsonEncoder
     */
    private $encoder;

    /**
     * ClientRegistrationEndpoint constructor.
     *
     * @param ResponseFactoryInterface $responseFactory
     * @param MessageBus               $messageBus
     * @param JsonEncoder              $encoder
     */
    public function __construct(ResponseFactoryInterface $responseFactory, MessageBus $messageBus, JsonEncoder $encoder)
    {
        $this->responseFactory = $responseFactory;
        $this->messageBus = $messageBus;
        $this->encoder = $encoder;
    }

    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate = null): ResponseInterface
    {
        $this->checkRequest($request);
        $data = new DataTransporter();
        $initial_access_token = $request->getAttribute('initial_access_token');
        Assertion::isInstanceOf($initial_access_token, InitialAccessToken::class);
        $command_parameters = is_array($request->getParsedBody()) ? $request->getParsedBody() : [];
        $command = CreateClientCommand::create($initial_access_token->getUserAccountId(), $command_parameters, $data);
        $this->messageBus->handle($command);

        return $this->createResponse($data->getData());
    }

    /**
     * @param ServerRequestInterface $request
     *
     * @throws OAuth2Exception
     */
    private function checkRequest(ServerRequestInterface $request)
    {
        if ('POST' !== $request->getMethod()) {
            throw new OAuth2Exception(
                405,
                [
                    'error'             => OAuth2ResponseFactoryManager::ERROR_INVALID_REQUEST,
                    'error_description' => 'Unsupported method.',
                ]
            );
        }
    }

    /**
     * @param Client $client
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    private function createResponse(Client $client): ResponseInterface
    {
        $response = $this->responseFactory->createResponse(201);
        foreach (['Content-Type' => 'application/json', 'Cache-Control' => 'no-store', 'Pragma' => 'no-cache'] as $k => $v) {
            $response = $response->withHeader($k, $v);
        }
        $response->getBody()->write($this->encoder->encode($client->all()));

        return $response;
    }
}
