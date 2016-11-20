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
use OAuth2\Token\BearerToken;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class ClientConfigurationEndpoint implements ClientConfigurationEndpointInterface
{
    use HasExceptionManager;
    use HasClientManager;
    use HasClientRuleManager;
    use HasJWTLoader;

    /**
     * @var \OAuth2\Token\BearerToken
     */
    private $bearer_token;

    /**
     * @var bool
     */
    private $is_software_statement_required = false;

    /**
     * @var \Jose\Object\JWKSetInterface
     */
    private $software_statement_signature_key_set;

    /**
     * ClientConfigurationEndpoint constructor.
     *
     * @param \OAuth2\Token\BearerToken                   $bearer_token
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
    public function handle(ServerRequestInterface $request, ResponseInterface &$response, ClientInterface $client)
    {
        try {
            $this->checkRequestAndClient($request, $client);
            switch ($request->getMethod()) {
                case 'GET':
                    $this->handleGet($response, $client);
                    break;
                case 'PUT':
                    $this->handlePut($request, $response, $client);
                    break;
                case 'DELETE':
                    $this->handleDelete($response, $client);
                    break;
                default:
                    throw new \InvalidArgumentException('Unsupported method.');
            }
        } catch (BaseException $e) {
            $e->getHttpResponse($response);
        } catch (\InvalidArgumentException $e) {
            $e = $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
            $e->getHttpResponse($response);
        }
    }

    private function checkRequestAndClient(ServerRequestInterface $request, ClientInterface $client)
    {
        Assertion::true($this->isRequestSecured($request), 'The request must be secured.');
        Assertion::true($client->has('registration_access_token'), 'Invalid client.');
        $values = [];
        $token = $this->bearer_token->findToken($request, $values);
        Assertion::notNull($token, '');
        Assertion::eq($token, $client->get('registration_access_token'), 'Invalid access token.');
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

    /**
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param \OAuth2\Client\ClientInterface      $client
     */
    private function handleGet(ResponseInterface &$response, ClientInterface $client)
    {
        $this->processResponseWithClient($response, $client);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface      $response
     * @param \OAuth2\Client\ClientInterface           $client
     */
    private function handlePut(ServerRequestInterface $request, ResponseInterface &$response, ClientInterface $client)
    {
        $request_parameters = RequestBody::getParameters($request);
        $this->checkPreservedParameters($request_parameters);
        $this->checkSoftwareStatement($request_parameters);

        $client_data = $client->all();
        foreach (['registration_access_token', 'registration_client_uri', 'client_secret_expires_at', 'client_id_issued_at'] as $k) {
            if (array_key_exists($k, $client_data)) {
                unset($client_data[$k]);
            }
        }
        $diff_data = array_diff_key($client_data, $request_parameters);

        Assertion::true(empty($diff_data), 'The request must include all client metadata fields.');
        Assertion::eq($request_parameters['client_id'], $client->getPublicId(), 'Inconsistent "client_id" parameter.');
        unset($request_parameters['client_id']);
        $request_parameters = array_merge(
            $request_parameters,
            ['registration_access_token' => null, 'registration_client_uri' => null, 'client_secret_expires_at' => null]
        );

        foreach ($request_parameters as $k => $v) {
            if (empty($v)) {
                $client->remove($k);
                unset($request_parameters[$k]);
            }
        }
        $this->getClientRuleManager()->processParametersForClient($client, $request_parameters);
        $this->getClientManager()->saveClient($client);
        $this->processResponseWithClient($response, $client);
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
    private function checkPreservedParameters(array $request_parameters)
    {
        $preserved_parameters = $this->getClientRuleManager()->getPreserverParameters();
        foreach ($preserved_parameters as $preserved_parameter) {
            Assertion::keyNotExists($request_parameters, $preserved_parameter, sprintf('The parameters "%s" is not allowed.', $preserved_parameter));
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
    private function handleDelete(ResponseInterface &$response, ClientInterface $client)
    {
        $this->getClientManager()->deleteClient($client);
        $response->getBody()->write(json_encode($client));
        $headers = [
            'Cache-Control' => 'no-store, private',
            'Pragma'        => 'no-cache',
        ];
        foreach ($headers as $key => $value) {
            $response = $response->withHeader($key, $value);
        }
        $response = $response->withStatus(204);
    }

    /**
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param \OAuth2\Client\ClientInterface      $client
     */
    private function processResponseWithClient(ResponseInterface &$response, ClientInterface $client)
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
}
