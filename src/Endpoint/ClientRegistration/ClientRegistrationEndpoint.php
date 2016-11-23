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
use OAuth2\Behaviour\HasClientRuleManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerInterface;
use OAuth2\Client\Rule\RuleManagerInterface;
use OAuth2\Exception\BaseException;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\TokenType\BearerToken;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class ClientRegistrationEndpoint implements ClientRegistrationEndpointInterface
{
    use HasExceptionManager;
    use HasClientManager;
    use HasClientRuleManager;
    use HasJWTLoader;

    /**
     * @var \OAuth2\TokenType\BearerToken
     */
    private $bearer_token;

    /**
     * @var bool
     */
    private $is_software_statement_required = false;

    /**
     * @var null|\Jose\Object\JWKSetInterface
     */
    private $software_statement_signature_key_set = null;

    /**
     * @var bool
     */
    private $is_initial_access_token_required = false;

    /**
     * @var null|\OAuth2\Endpoint\ClientRegistration\InitialAccessTokenManagerInterface
     */
    private $initial_access_token_manager = null;

    /**
     * ClientRegistrationEndpoint constructor.
     *
     * @param \OAuth2\TokenType\BearerToken                   $bearer_token
     * @param \OAuth2\Client\ClientManagerInterface       $client_manager
     * @param \OAuth2\Client\Rule\RuleManagerInterface    $client_rule_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(BearerToken $bearer_token, ClientManagerInterface $client_manager, RuleManagerInterface $client_rule_manager, ExceptionManagerInterface $exception_manager)
    {
        $this->bearer_token = $bearer_token;
        $this->setClientManager($client_manager);
        $this->setClientRuleManager($client_rule_manager);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function isInitialAccessTokenRequired()
    {
        return $this->is_initial_access_token_required;
    }

    /**
     * {@inheritdoc}
     */
    public function allowRegistrationWithoutInitialAccessToken()
    {
        $this->is_initial_access_token_required = false;
    }

    /**
     * {@inheritdoc}
     */
    public function disallowRegistrationWithoutInitialAccessToken()
    {
        Assertion::true($this->isInitialAccessTokenSupported(), 'Initial Access Token not supported.');
        $this->is_initial_access_token_required = true;
    }

    /**
     * {@inheritdoc}
     */
    public function isInitialAccessTokenSupported()
    {
        return null !== $this->initial_access_token_manager;
    }

    /**
     * {@inheritdoc}
     */
    public function enableInitialAccessTokenSupport(InitialAccessTokenManagerInterface $initial_access_token_manage)
    {
        $this->initial_access_token_manager = $initial_access_token_manage;
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
    public function register(ServerRequestInterface $request, ResponseInterface &$response)
    {
        try {
            $this->checkRequest($request);
            $this->handleRequest($request, $response);
        } catch (BaseException $e) {
            $e->getHttpResponse($response);
        } catch (\InvalidArgumentException $e) {
            $e = $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::ERROR_INVALID_REQUEST, $e->getMessage());
            $e->getHttpResponse($response);
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @throws \InvalidArgumentException
     *
     * @return \OAuth2\Endpoint\ClientRegistration\InitialAccessTokenInterface|null
     */
    private function findInitialAccessToken(ServerRequestInterface $request)
    {
        if (false === $this->isInitialAccessTokenSupported()) {
            return;
        }
        $values = [];
        $token = $this->bearer_token->findToken($request, $values);
        if (true === $this->isInitialAccessTokenRequired()) {
            Assertion::notNull($token, 'Initial Access Token is missing or invalid.');
        }
        if (null === $token) {
            return;
        }

        $initial_access_token = $this->initial_access_token_manager->getInitialAccessToken($token);
        Assertion::notNull($initial_access_token, 'Initial Access Token is missing or invalid.');
        Assertion::false($initial_access_token->hasExpired(), 'Initial Access Token expired.');

        return $initial_access_token;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkRequest(ServerRequestInterface $request)
    {
        Assertion::true($this->isRequestSecured($request), 'The request must be secured.');
        Assertion::eq('POST', $request->getMethod(), 'Method must be POST.');
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface      $response
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function handleRequest(ServerRequestInterface $request, ResponseInterface &$response)
    {
        $initial_access_token = $this->findInitialAccessToken($request);
        $request_parameters = RequestBody::getParameters($request);
        $this->checkSoftwareStatement($request_parameters);
        $client = $this->getClientManager()->createClient();
        $this->getClientRuleManager()->processParametersForClient($client, $request_parameters);
        if (null !== $initial_access_token) {
            $client->setResourceOwnerPublicId($initial_access_token->getUserAccountPublicId());
        }
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
