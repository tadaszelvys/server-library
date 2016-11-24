<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\ClientConfiguration;

use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use OAuth2\Command\Client\UpdateClientCommand;
use OAuth2\DataTransporter;
use OAuth2\Response\OAuth2Exception;
use Psr\Http\Message\ServerRequestInterface;
use SimpleBus\Message\Bus\MessageBus;

final class ClientConfigurationPutEndpoint implements MiddlewareInterface
{
    /**
     * @var MessageBus
     */
    private $messageBus;

    /**
     * ClientConfigurationPutEndpoint constructor.
     * @param MessageBus $messageBus
     */
    public function __construct(MessageBus $messageBus)
    {
        $this->messageBus = $messageBus;
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

        throw new OAuth2Exception(200, $data->getData()->jsonSerialize());
    }
}
