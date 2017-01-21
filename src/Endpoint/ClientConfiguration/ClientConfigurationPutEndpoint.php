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

namespace OAuth2\Endpoint\ClientConfiguration;

use Interop\Http\Factory\ResponseFactoryInterface;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use OAuth2\Command\Client\UpdateClientCommand;
use OAuth2\DataTransporter;
use Psr\Http\Message\ServerRequestInterface;
use SimpleBus\Message\Bus\MessageBus;
use Webmozart\Json\JsonEncoder;

final class ClientConfigurationPutEndpoint implements MiddlewareInterface
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
     * ClientConfigurationPutEndpoint constructor.
     *
     * @param MessageBus               $messageBus
     * @param ResponseFactoryInterface $responseFactory
     * @param JsonEncoder              $encoder
     */
    public function __construct(MessageBus $messageBus, ResponseFactoryInterface $responseFactory, JsonEncoder $encoder)
    {
        $this->messageBus = $messageBus;
        $this->responseFactory = $responseFactory;
        $this->encoder = $encoder;
    }

    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, DelegateInterface $next)
    {
        $client = $request->getAttribute('client');

        $data = new DataTransporter();
        $command_parameters = is_array($request->getParsedBody()) ? $request->getParsedBody() : [];
        $command = UpdateClientCommand::create($client, $command_parameters, $data);
        $this->messageBus->handle($command);

        $response = $this->responseFactory->createResponse();
        $response->getBody()->write($this->encoder->encode($data->getData()));
        $headers = ['Content-Type' => 'application/json; charset=UTF-8', 'Cache-Control' => 'no-cache, no-store, max-age=0, must-revalidate, private', 'Pragma' => 'no-cache'];
        foreach ($headers as $k => $v) {
            $response = $response->withHeader($k, $v);
        }

        return $response;
    }
}
