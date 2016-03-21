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
use Jose\Checker\CheckerManagerInterface;
use Jose\Factory\DecrypterFactory;
use Jose\Factory\VerifierFactory;
use Jose\Loader;
use Jose\Object\JWEInterface;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use OAuth2\Behaviour\HasClientManagerSupervisor;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerSupervisorInterface;
use OAuth2\EndUser\EndUserInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Scope\ScopeManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

final class AuthorizationFactory
{
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
     * @var \Jose\Checker\CheckerManagerInterface
     */
    private $checker_manager;

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
        if ($this->isSignedRequestsSupportEnabled()) {
            return $this->allowed_signature_algorithms;
        }
        
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyEncryptionAlgorithms()
    {
        if ($this->isEncryptedRequestsSupportEnabled()) {
            return $this->allowed_key_encryption_algorithms;
        }

        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function getContentEncryptionAlgorithms()
    {
        if ($this->isEncryptedRequestsSupportEnabled()) {
            return $this->allowed_content_encryption_algorithms;
        }

        return [];
    }

    /**
     * @param array                                 $allowed_signature_algorithms
     * @param \Jose\Object\JWKSetInterface          $signature_key_set
     * @param \Jose\Checker\CheckerManagerInterface $checker_manager
     */
    public function enableSignedRequestsSupport(array $allowed_signature_algorithms,
                                                JWKSetInterface $signature_key_set,
                                                CheckerManagerInterface $checker_manager
    ) {
        Assertion::notEmpty($allowed_signature_algorithms);

        $this->signature_key_set = $signature_key_set;
        $this->allowed_signature_algorithms = $allowed_signature_algorithms;
        $this->checker_manager = $checker_manager;
    }

    public function isSignedRequestsSupportEnabled()
    {
        return null !== $this->signature_key_set && !empty($this->allowed_signature_algorithms);
    }

    /**
     * @param string[]                     $allowed_key_encryption_algorithms
     * @param string[]                     $allowed_content_encryption_algorithms
     * @param \Jose\Object\JWKSetInterface $key_encryption_key_set
     */
    public function enableEncryptedRequestsSupport(array $allowed_key_encryption_algorithms,
                                                   array $allowed_content_encryption_algorithms,
                                                   JWKSetInterface $key_encryption_key_set)
    {
        Assertion::true($this->isSignedRequestsSupportEnabled(), 'Signed requests support must be enable to support encrypted requests.');
        Assertion::notEmpty($allowed_key_encryption_algorithms);
        Assertion::notEmpty($allowed_content_encryption_algorithms);

        $this->allowed_key_encryption_algorithms = $allowed_key_encryption_algorithms;
        $this->allowed_content_encryption_algorithms = $allowed_content_encryption_algorithms;
        $this->key_encryption_key_set = $key_encryption_key_set;
    }

    /**
     * @return bool
     */
    public function isEncryptedRequestsSupportEnabled()
    {
        return $this->isSignedRequestsSupportEnabled() &&
               null !== $this->key_encryption_key_set &&
               !empty($this->allowed_content_encryption_algorithms) &&
               !empty($this->allowed_key_encryption_algorithms);
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
            return $this->createFromRequestParameter($params['request'], $end_user, $is_authorized);
        } elseif (array_key_exists('request_uri', $params)) {
            return $this->createFromRequestUriParameter($params['request_uri'], $end_user, $is_authorized);
        }

        return $this->createFromStandardRequest($params, $end_user, $is_authorized);
    }

    /**
     * @param string                           $request
     * @param \OAuth2\EndUser\EndUserInterface $end_user
     * @param bool                             $is_authorized
     *
     * @return \OAuth2\Endpoint\Authorization
     */
    private function createFromRequestParameter($request, EndUserInterface $end_user, $is_authorized)
    {
        if (false === $this->isSignedRequestsSupportEnabled()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The parameter "request" is not supported.');
        }
        Assertion::string($request);

        $jws = $this->loadRequest($request);

        return $this->createFromStandardRequest($jws->getClaims(), $end_user, $is_authorized);
    }

    /**
     * @param string $request
     *
     * @return \Jose\Object\JWSInterface
     */
    private function loadRequest($request)
    {
        $jwt = Loader::load($request);
        if ($jwt instanceof JWEInterface) {
            $jwt = $this->decryptRequest($jwt);
        }

        if (!$jwt instanceof JWSInterface) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The parameter "request" must contain a JWS or an encrypted JWS.');
        }

        $verifier = VerifierFactory::createVerifier($this->allowed_signature_algorithms);
        $verifier->verifyWithKeySet($jwt, $this->signature_key_set, null, $index);
        try {
            $this->checker_manager->checkJWS($jwt, $index);
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
        }

        return $jwt;
    }

    /**
     * @param \Jose\Object\JWEInterface $jwt
     *
     * @return \Jose\Object\JWEInterface|\Jose\Object\JWSInterface
     */
    private function decryptRequest(JWEInterface $jwt)
    {
        if (false === $this->isEncryptedRequestsSupportEnabled()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Encrypted requests are not supported.');
        }
        $decrypter = DecrypterFactory::createDecrypter(array_merge(
            $this->getKeyEncryptionAlgorithms(),
            $this->getContentEncryptionAlgorithms()
        ));
        try {
            $decrypter->decryptUsingKeySet($jwt, $this->key_encryption_key_set);
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
        }

        return Loader::load($jwt->getPayload());
    }

    /**
     * @param string                           $request_uri
     * @param \OAuth2\EndUser\EndUserInterface $end_user
     * @param bool                             $is_authorized
     *
     * @return \OAuth2\Endpoint\Authorization
     */
    private function createFromRequestUriParameter($request_uri, EndUserInterface $end_user, $is_authorized)
    {
        if (false === $this->isSignedRequestsSupportEnabled()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The parameter "request" is not supported.');
        }
        Assertion::url($request_uri, 'Invalid URL.');
        
        $content = $this->downloadContent($request_uri);
        $jws = $this->loadRequest($content);

        return $this->createFromStandardRequest($jws->getClaims(), $end_user, $is_authorized);
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

    /**
     * @param string $url
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function downloadContent($url)
    {
        // The URL must be a valid URL and scheme must be https
        Assertion::false(
            false === filter_var($url, FILTER_VALIDATE_URL, FILTER_FLAG_SCHEME_REQUIRED | FILTER_FLAG_HOST_REQUIRED),
            'Invalid URL.'
        );
        Assertion::false('https://' !==  mb_substr($url, 0, 8, '8bit'), 'Unsecured connection.');

        $params = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_URL            => $url,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ];

        $ch = curl_init();
        curl_setopt_array($ch, $params);
        $content = curl_exec($ch);
        curl_close($ch);

        Assertion::notEmpty($content, 'Unable to get content.');

        return $content;
    }
}
