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
use OAuth2\Behaviour\HasParameterRuleManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerInterface;
use OAuth2\Endpoint\ClientRegistration\Rule\ParameterRuleManagerInterface;
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
    use HasParameterRuleManager;
    use HasJWTLoader;

    /**
     * @var bool
     */
    private $is_software_statement_required = false;

    /**
     * @var \Jose\Object\JWKSetInterface
     */
    private $software_statement_signature_key_set;

    /**
     * @var bool
     */
    private $is_initial_access_token_required = false;

    /**
     * ClientRegistrationEndpoint constructor.
     *
     * @param \OAuth2\Client\ClientManagerInterface                                           $client_manager
     * @param \OAuth2\Endpoint\ClientRegistration\Rule\ParameterRuleManagerInterface $client_registration_rule_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface                                     $exception_manager
     */
    public function __construct(ClientManagerInterface $client_manager, ParameterRuleManagerInterface $client_registration_rule_manager, ExceptionManagerInterface $exception_manager)
    {
        $this->setClientManager($client_manager);
        $this->setParameterRuleManager($client_registration_rule_manager);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function isInitialAccessTokenRequired()
    {
        return $this->is_initial_access_token_required;
    }

    public function allowRegistrationWithoutInitialAccessToken()
    {
        $this->is_initial_access_token_required = false;
    }

    public function disallowRegistrationWithoutInitialAccessToken()
    {
        $this->is_initial_access_token_required = true;
    }

    /**
     * {@inheritdoc}
     */
    public function isSoftwareStatementSupported()
    {
        return null !== $this->software_statement_signature_key_set;
    }

    /**
     * {@inheritdoc}
     */
    public function isSoftwareStatementRequired()
    {
        return $this->is_software_statement_required;
    }

    /**
     * {@inheritdoc}
     */
    public function enableSoftwareStatementSupport(JWTLoaderInterface $jwt_loader, JWKSetInterface $signature_key_set)
    {
        $this->setJWTLoader($jwt_loader);
        $this->software_statement_signature_key_set = $signature_key_set;
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
            $this->checkRequest($request, $access_token);
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
     * @param \OAuth2\Token\AccessTokenInterface|null  $access_token
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkRequest(ServerRequestInterface $request, AccessTokenInterface $access_token = null)
    {
        Assertion::true($this->isRequestSecured($request), 'The request must be secured.');
        Assertion::eq('POST', $request->getMethod(), 'Method must be POST.');
        Assertion::false(null === $access_token && true === $this->is_initial_access_token_required, 'Initial access token required.');
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
        $client = $this->getClientManager()->createClient();

        $metadatas = [];
        foreach ($this->getParameterRuleManager()->getParameterRules() as $rule) {
            $rule->checkParameters($client, $request_parameters, $metadatas);
        }

        $this->updateClient($client, $metadatas, $access_token);
        $this->getClientManager()->saveClient($client);
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
        try {
            $jws = $this->getJWTLoader()->load($request_parameters['software_statement']);
            $this->getJWTLoader()->verify($jws, $this->software_statement_signature_key_set);
        } catch (\Exception $e) {
            throw new \InvalidArgumentException('Invalid Software Statement', $e->getCode(), $e);
        }
        $request_parameters = array_merge(
            $request_parameters,
            $jws->getClaims()
        );
    }

    /**
     * @param \OAuth2\Client\ClientInterface          $client
     * @param array                                   $metadatas
     * @param \OAuth2\Token\AccessTokenInterface|null $access_token
     */
    private function updateClient(ClientInterface $client, array $metadatas, AccessTokenInterface $access_token = null)
    {
        foreach ($metadatas as $metadata => $value) {
            $client->set($metadata, $value);
        }
        if (null !== $access_token) {
            $client->setResourceOwnerPublicId($access_token->getResourceOwnerPublicId());
        }
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
