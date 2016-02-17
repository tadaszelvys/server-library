<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint;

use Assert\Assertion;
use Jose\Object\JWKSetInterface;
use OAuth2\Behaviour\HasClientManagerSupervisor;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerSupervisorInterface;
use OAuth2\EndUser\EndUserInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Scope\ScopeManagerInterface;
use OAuth2\Util\JWTLoader;
use Psr\Http\Message\ServerRequestInterface;

final class AuthorizationFactory
{
    use HasJWTLoader;
    use HasScopeManager;
    use HasClientManagerSupervisor;
    use HasExceptionManager;

    /**
     * @var \Jose\Object\JWKSetInterface|null
     */
    private $signature_key_set = null;

    /**
     * @var string[]
     */
    private $allowed_signature_algorithms = [];

    /**
     * @var bool
     */
    private $encryption_required = false;

    /**
     * @var \Jose\Object\JWKSetInterface|null
     */
    private $key_encryption_key_set = null;

    /**
     * @var string[]
     */
    private $allowed_key_encryption_algorithms = [];

    /**
     * @var string[]
     */
    private $allowed_content_encryption_algorithms = [];

    /**
     * @var bool
     */
    private $request_parameter_supported = false;

    /**
     * @var bool
     */
    private $request_uri_parameter_supported = false;

    /**
     * AuthorizationFactory constructor.
     *
     * @param \OAuth2\Scope\ScopeManagerInterface             $scope_manager
     * @param \OAuth2\Client\ClientManagerSupervisorInterface $client_manager_supervisor
     * @param \OAuth2\Exception\ExceptionManagerInterface     $exception_manager
     */
    public function __construct(
        ScopeManagerInterface $scope_manager,
        ClientManagerSupervisorInterface $client_manager_supervisor,
        ExceptionManagerInterface $exception_manager
    ) {
        $this->setScopeManager($scope_manager);
        $this->setExceptionManager($exception_manager);
        $this->setClientManagerSupervisor($client_manager_supervisor);
    }

    /**
     * {@inheritdoc}
     */
    public function getSignatureAlgorithms()
    {
        return $this->allowed_signature_algorithms;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyEncryptionAlgorithms()
    {
        return $this->allowed_key_encryption_algorithms;
    }

    /**
     * {@inheritdoc}
     */
    public function getContentEncryptionAlgorithms()
    {
        return $this->allowed_content_encryption_algorithms;
    }

    /**
     * @param \OAuth2\Util\JWTLoader       $jwt_loader
     * @param array                        $allowed_signature_algorithms
     * @param \Jose\Object\JWKSetInterface $signature_key_set
     */
    public function enableSignedRequestsSupport(JWTLoader $jwt_loader,
                                                array $allowed_signature_algorithms,
                                                JWKSetInterface $signature_key_set
    ) {
        Assertion::notEmpty($allowed_signature_algorithms);
        Assertion::true(empty(array_diff($allowed_signature_algorithms, $jwt_loader->getSupportedSignatureAlgorithms())));
        $this->setJWTLoader($jwt_loader);

        $this->signature_key_set = $signature_key_set;
        $this->allowed_signature_algorithms = $allowed_signature_algorithms;
    }

    public function isSignedRequestsSupportEnabled()
    {
        return null !== $this->getJWTLoader() && null !== $this->signature_key_set && !empty($this->allowed_signature_algorithms);
    }

    /**
     * @param bool                         $encryption_required
     * @param string[]                     $allowed_key_encryption_algorithms
     * @param string[]                     $allowed_content_encryption_algorithms
     * @param \Jose\Object\JWKSetInterface $key_encryption_key_set
     */
    public function enableEncryptedRequestsSupport($encryption_required,
                                              array $allowed_key_encryption_algorithms,
                                              array $allowed_content_encryption_algorithms,
                                              JWKSetInterface $key_encryption_key_set)
    {
        Assertion::boolean($encryption_required);
        Assertion::notEmpty($allowed_key_encryption_algorithms);
        Assertion::notEmpty($allowed_content_encryption_algorithms);
        Assertion::true(empty(array_diff($allowed_key_encryption_algorithms, $this->getJWTLoader()->getSupportedKeyEncryptionAlgorithms())));
        Assertion::true(empty(array_diff($allowed_content_encryption_algorithms, $this->getJWTLoader()->getSupportedContentEncryptionAlgorithms())));

        $this->encryption_required = $encryption_required;
        $this->allowed_key_encryption_algorithms = $allowed_key_encryption_algorithms;
        $this->allowed_content_encryption_algorithms = $allowed_content_encryption_algorithms;
        $this->key_encryption_key_set = $key_encryption_key_set;
    }

    /**
     * @return bool
     */
    public function isRequestParameterSupported()
    {
        return $this->request_parameter_supported;
    }

    /**
     *
     */
    public function enableRequestParameterSupport()
    {
        Assertion::true($this->isSignedRequestsSupportEnabled(), 'Signed requests support must be enable to support request parameters');
        $this->request_parameter_supported = true;
    }

    /**
     *
     */
    public function disableRequestParameterSupport()
    {
        $this->request_parameter_supported = false;
    }

    /**
     * @return bool
     */
    public function isRequestUriParameterSupported()
    {
        return $this->request_uri_parameter_supported;
    }

    /**
     *
     */
    public function enableRequestUriParameterSupport()
    {
        Assertion::true($this->isSignedRequestsSupportEnabled(), 'Signed requests support must be enable to support request parameters');
        $this->request_uri_parameter_supported = true;
    }

    /**
     *
     */
    public function disableRequestUriParameterSupport()
    {
        $this->request_uri_parameter_supported = false;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \OAuth2\EndUser\EndUserInterface         $end_user
     * @param bool                                     $is_authorized
     *
     * @return \OAuth2\Endpoint\Authorization
     */
    public function createFromRequest(ServerRequestInterface $request, EndUserInterface $end_user, $is_authorized)
    {
        $params = $request->getQueryParams();
        if (array_key_exists('request', $params)) {
            $this->createFromRequestParameter();
        } elseif (array_key_exists('request_uri', $params)) {
            $this->createFromRequestUriParameter();
        }

        return $this->createFromStandardRequest($params, $end_user, $is_authorized);
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function createFromRequestParameter()
    {
        if (false === $this->isRequestParameterSupported()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The parameter "request" is not supported');
        }
        throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Not supported');
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function createFromRequestUriParameter()
    {
        if (false === $this->isRequestUriParameterSupported()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The parameter "request_uri" is not supported');
        }
        throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Not supported');
    }

    /**
     * @param array                            $params
     * @param \OAuth2\EndUser\EndUserInterface $end_user
     * @param bool                             $is_authorized
     *
     * @return \OAuth2\Endpoint\Authorization
     */
    private function createFromStandardRequest(array $params, EndUserInterface $end_user, $is_authorized)
    {
        $client = $this->getClient($params);
        $scopes = $this->getScope($params);
        $authorization = new Authorization($params, $end_user, $is_authorized, $client, $scopes);

        return $authorization;
    }

    /**
     * @param array $params
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Client\ClientInterface
     */
    private function getClient(array $params)
    {
        $client = array_key_exists('client_id', $params) ? $this->getClientManagerSupervisor()->getClient($params['client_id']) : null;
        if (!$client instanceof ClientInterface) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "client_id" missing or invalid.');
        }

        return $client;
    }

    /**
     * @param array $params
     *
     * @return \string[]
     */
    private function getScope(array $params)
    {
        if (array_key_exists('scope', $params)) {
            return $this->getScopeManager()->convertToArray($params['scope']);
        }

        return [];
    }
}
