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

use Assert\Assertion;
use Jose\JWTLoaderInterface;
use Jose\Object\JWKSetInterface;
use OAuth2\Behaviour\HasClientManager;
use OAuth2\Behaviour\HasClientRegistrationRuleManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerInterface;
use OAuth2\Endpoint\ClientRegistration\Rule\ClientRegistrationRuleManagerInterface;
use OAuth2\Exception\BaseException;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class ClientRegistrationEndpoint implements ClientRegistrationEndpointInterface
{
    use HasExceptionManager;
    use HasClientManager;
    use HasClientRegistrationRuleManager;
    use HasJWTLoader;

    /**
     * @var bool
     */
    private $is_software_statement_required = false;

    /**
     * @var \Jose\Object\JWKSetInterface
     */
    private $signature_key_set;
    /**
     * @var bool
     */
    private $isInitialAccessTokenRequired = false;

    /**
     * ClientRegistrationEndpoint constructor.
     *
     * @param \OAuth2\Client\ClientManagerInterface                                           $client_manager
     * @param \OAuth2\Endpoint\ClientRegistration\Rule\ClientRegistrationRuleManagerInterface $client_registration_rule_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface                                     $exception_manager
     */
    public function __construct(ClientManagerInterface $client_manager, ClientRegistrationRuleManagerInterface $client_registration_rule_manager, ExceptionManagerInterface $exception_manager)
    {
        $this->setClientManager($client_manager);
        $this->setClientRegistrationRuleManager($client_registration_rule_manager);
        $this->setExceptionManager($exception_manager);
    }

    public function allowRegistrationWithoutInitialAccessToken()
    {
        $this->isInitialAccessTokenRequired = false;
    }

    public function disallowRegistrationWithoutInitialAccessToken()
    {
        $this->isInitialAccessTokenRequired = true;
    }

    /**
     * {@inheritdoc}
     */
    public function isSoftwareStatementSupported()
    {
        return null !== $this->signature_key_set;
    }

    /**
     * {@inheritdoc}
     */
    public function enableSoftwareStatementSupport(JWTLoaderInterface $jwt_loader, JWKSetInterface $signature_key_set)
    {
        $this->setJWTLoader($jwt_loader);
        $this->signature_key_set = $signature_key_set;
    }

    public function allowRegistrationWithoutSoftwareStatement()
    {
        Assertion::true($this->isSoftwareStatementSupported(), 'Software Statement not supported.');
        $this->is_software_statement_required = false;
    }

    public function disallowRegistrationWithoutSoftwareStatement()
    {
        Assertion::true($this->isSoftwareStatementSupported(), 'Software Statement not supported.');
        $this->is_software_statement_required = true;
    }

    /**
     * {@inheritdoc}
     */
    public function register(ServerRequestInterface $request, ResponseInterface &$response, AccessTokenInterface $access_token = null)
    {
        try {
            Assertion::true($this->isRequestSecured($request), 'The request must be secured.');
            Assertion::eq('POST', $request->getMethod(), 'Method must be POST.');
            Assertion::false(null === $access_token && true === $this->isInitialAccessTokenRequired, 'Initial access token required.');

            $this->handleRequest($request, $response, $access_token);
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
     * @param \OAuth2\Token\AccessTokenInterface|null  $access_token
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function handleRequest(ServerRequestInterface $request, ResponseInterface &$response, AccessTokenInterface $access_token = null)
    {
        $request_parameters = RequestBody::getParameters($request);
        $this->checkSoftwareStatement($request_parameters);
        $metadatas = [];

        foreach ($this->getClientRegistrationRuleManager()->getClientRegistrationRules() as $rule) {
            $rule->checkRegistrationParameters($request_parameters, $metadatas);
        }

        $client = $this->createAndSaveClient($metadatas, $access_token);

        $this->processResponse($response, $client);
    }

    /**
     * @param array $request_parameters
     */
    private function checkSoftwareStatement(array &$request_parameters)
    {
        if ($this->isSoftwareStatementSupported()) {
            Assertion::false(false === array_key_exists('software_statement', $request_parameters) && true === $this->is_software_statement_required, 'Software Statement required.');

            if (array_key_exists('software_statement', $request_parameters)) {
                $this->updateRequestParametersWithSoftwareStatement($request_parameters);
            }

        } elseif (array_key_exists('software_statement', $request_parameters)) {
            throw new \InvalidArgumentException('Software Statement parameter not supported.');
        }
    }

    /**
     * @param array $request_parameters
     */
    private function updateRequestParametersWithSoftwareStatement(array &$request_parameters)
    {
        $jws = $this->getJWTLoader()->load($request_parameters['software_statement']);
        $this->getJWTLoader()->verify($jws, $this->signature_key_set);

        $request_parameters = array_merge(
            $request_parameters,
            $jws->getClaims()
        );
    }

    /**
     * @param array                                   $metadatas
     * @param \OAuth2\Token\AccessTokenInterface|null $access_token
     *
     * @return \OAuth2\Client\ClientInterface
     */
    private function createAndSaveClient(array $metadatas, AccessTokenInterface $access_token = null)
    {
        $client = $this->getClientManager()->createClient();
        foreach ($metadatas as $metadata => $value) {
            $client->set($metadata, $value);
        }
        if (null !== $access_token) {
            $client->setResourceOwnerPublicId($access_token->getResourceOwnerPublicId());
        }
        $this->getClientManager()->saveClient($client);

        return $client;
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
