<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\ClientRegistration;

use OAuth2\Behaviour\HasClientManager;
use OAuth2\Behaviour\HasClientRegistrationRuleManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerInterface;
use OAuth2\Endpoint\ClientRegistration\Rule\ClientRegistrationRuleManagerInterface;
use OAuth2\Exception\BaseException;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class ClientRegistrationEndpoint implements ClientRegistrationEndpointInterface
{
    use HasExceptionManager;
    use HasClientManager;
    use HasClientRegistrationRuleManager;

    /**
     * ClientRegistrationEndpoint constructor.
     *
     * @param \OAuth2\Client\ClientManagerInterface                                           $client_manager
     * @param \OAuth2\Endpoint\ClientRegistration\Rule\ClientRegistrationRuleManagerInterface $client_registration_rule_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface                                     $exception_manager
     */
    public function __construct(ClientManagerInterface $client_manager,
                                ClientRegistrationRuleManagerInterface $client_registration_rule_manager,
                                ExceptionManagerInterface $exception_manager
    ) {
        $this->setClientManager($client_manager);
        $this->setClientRegistrationRuleManager($client_registration_rule_manager);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function register(ServerRequestInterface $request, ResponseInterface &$response)
    {
        try {
            if (false === $this->isRequestSecured($request)) {
                throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The request must be secured.');
            }
            if ('POST' !== $request->getMethod()) {
                throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Method must be POST.');
            }

            // Add Initial Access Token check here

            $this->handleRequest($request, $response);
        } catch (BaseException $e) {
            $e->getHttpResponse($response);

            return;
        } catch (\InvalidArgumentException $e) {
            $e = $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
            $e->getHttpResponse($response);

            return;
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface      $response
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function handleRequest(ServerRequestInterface $request, ResponseInterface &$response)
    {
        $request_parameters = RequestBody::getParameters($request);
        $metadatas = [];

        foreach ($this->getClientRegistrationRuleManager()->getClientRegistrationRules() as $rule) {
            $rule->checkRegistrationParameters($request_parameters, $metadatas);
        }

        $client = $this->getClientManager()->createClient();
        foreach ($metadatas as $metadata => $value) {
            $client->set($metadata, $value);
        }
        $this->getClientManager()->saveClient($client);

        $this->processResponse($response, $client);
    }

    /**
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param \OAuth2\Client\ClientInterface      $client
     */
    private function processResponse(ResponseInterface &$response, ClientInterface $client)
    {
        $response->getBody()->write(json_encode($client));
        $headers = [
            'Content-Type'  => 'application/json',
            'Cache-Control' => 'no-store, private',
            'Pragma'        => 'no-cache',
        ];
        foreach ($headers as $key => $value) {
            $response = $response->withHeader($key, $value);
        }
        $response = $response->withStatus(200);
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
}
