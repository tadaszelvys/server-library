<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization;

use Assert\Assertion;
use Jose\JWTLoader;
use Jose\Object\JWKSetInterface;
use OAuth2\Behaviour\HasClientManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\Uri;
use Psr\Http\Message\ServerRequestInterface;

final class AuthorizationRequestLoader implements AuthorizationRequestLoaderInterface
{
    use HasJWTLoader;
    use HasClientManager;
    use HasExceptionManager;

    /**
     * @var bool
     */
    private $request_object_allowed = false;

    /**
     * @var bool
     */
    private $request_object_reference_allowed = false;

    /**
     * @var \Jose\Object\JWKSetInterface|null
     */
    private $key_encryption_key_set = null;

    /**
     * @var bool
     */
    private $require_request_uri_registration = true;

    /**
     * AuthorizationRequestLoader constructor.
     *
     * @param \OAuth2\Client\ClientManagerInterface       $client_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(ClientManagerInterface $client_manager, ExceptionManagerInterface $exception_manager)
    {
        $this->setClientManager($client_manager);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * @return bool
     */
    public function isRequestUriRegistrationRequired()
    {
        return $this->require_request_uri_registration;
    }


    public function enableRequestUriRegistrationRequirement()
    {
        $this->require_request_uri_registration = true;
    }


    public function disableRequestUriRegistrationRequirement()
    {
        $this->require_request_uri_registration = false;
    }

    /**
     * {@inheritdoc}
     */
    public function isRequestObjectSupportEnabled()
    {
        return $this->request_object_allowed;
    }

    /**
     * {@inheritdoc}
     */
    public function isRequestObjectReferenceSupportEnabled()
    {
        return $this->request_object_reference_allowed;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedSignatureAlgorithms()
    {
        return null === $this->getJWTLoader() ? [] : $this->getJWTLoader()->getSupportedSignatureAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedKeyEncryptionAlgorithms()
    {
        return null === $this->getJWTLoader() ? [] : $this->getJWTLoader()->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return null === $this->getJWTLoader() ? [] : $this->getJWTLoader()->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * @param \Jose\JWTLoader $jwt_loader
     */
    public function enableRequestObjectSupport(JWTLoader $jwt_loader)
    {
        $this->setJWTLoader($jwt_loader);
        $this->request_object_allowed = true;
    }

    public function enableRequestObjectReferenceSupport()
    {
        Assertion::true($this->isRequestObjectSupportEnabled(), 'Request object support must be enabled first.');
        $this->request_object_reference_allowed = true;
    }

    /**
     * @param \Jose\Object\JWKSetInterface $key_encryption_key_set
     */
    public function enableEncryptedRequestObjectSupport(JWKSetInterface $key_encryption_key_set)
    {
        Assertion::true($this->isRequestObjectSupportEnabled(), 'Request object support must be enabled first.');

        $this->key_encryption_key_set = $key_encryption_key_set;
    }

    /**
     * @return bool
     */
    public function isEncryptedRequestsSupportEnabled()
    {
        return null !== $this->key_encryption_key_set;
    }

    /**
     * {@inheritdoc}
     */
    public function loadParametersFromRequest(ServerRequestInterface $request)
    {
        $params = $request->getQueryParams();
        if (array_key_exists('request', $params)) {
            $params = $this->createFromRequestParameter($params);
        } elseif (array_key_exists('request_uri', $params)) {
            $params = $this->createFromRequestUriParameter($params);
        } else {
            $params = $this->createFromStandardRequest($params);
        }
        $this->prepareScope($params);
        $this->preparePrompt($params);

        return $params;
    }

    /**
     * @param array $params
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     *
     * @return array
     */
    private function createFromRequestParameter(array $params)
    {
        if (false === $this->isRequestObjectSupportEnabled()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::REQUEST_NOT_SUPPORTED, 'The parameter "request" is not supported.');
        }
        $request = $params['request'];
        Assertion::string($request);

        $jws = $this->loadRequest($params, $request, $client);
        $params = array_merge($params, $jws->getClaims(), ['client' => $client]);

        return $params;
    }

    /**
     * @param array $params
     *
     * @return array
     */
    private function createFromStandardRequest(array $params)
    {
        $client = $this->getClient($params);

        return array_merge($params, ['client' => $client]);
    }

    /**
     * @param array $params
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     *
     * @return array
     */
    private function createFromRequestUriParameter(array $params)
    {
        if (false === $this->isRequestObjectReferenceSupportEnabled()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::REQUEST_URI_NOT_SUPPORTED, 'The parameter "request_uri" is not supported.');
        }
        $request_uri = $params['request_uri'];
        Assertion::url($request_uri, 'Invalid URL.');

        $content = $this->downloadContent($request_uri);
        $jws = $this->loadRequest($params, $content, $client);
        if (true === $this->isRequestUriRegistrationRequired()) {
            $this->checkRequestUri($client, $request_uri);
        }
        $params = array_merge($params, $jws->getClaims(), ['client' => $client]);

        return $params;
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param string                         $request_uri
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     */
    private function checkRequestUri(ClientInterface $client, $request_uri)
    {
        $this->checkRequestUriPathTraversal($request_uri);
        $stored_request_uris = $this->getClientRequestUris($client);

        foreach ($stored_request_uris as $stored_request_uri) {
            if (strcasecmp(mb_substr($request_uri, 0, mb_strlen($stored_request_uri, '8bit'), '8bit'), $stored_request_uri) === 0) {
                return;
            }
        }
        throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST_URI, 'The request Uri is not allowed.');
    }

    /**
     * @param string $request_uri
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     */
    private function checkRequestUriPathTraversal($request_uri)
    {
        if (false === Uri::checkUrl($request_uri, false)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_CLIENT, 'The request Uri must not contain path traversal.');
        }
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     *
     * @return string[]
     */
    private function getClientRequestUris(ClientInterface $client)
    {
        if (false === $client->has('request_uris') || empty($request_uris = $client->get('request_uris'))) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_CLIENT, 'The client must register at least one request Uri.');
        }

        return $request_uris;
    }

    /**
     * @param array                               $params
     * @param string                              $request
     * @param \OAuth2\Client\ClientInterface|null $client
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     *
     * @return \Jose\Object\JWSInterface
     */
    private function loadRequest(array $params, $request, ClientInterface &$client = null)
    {
        $jwt = $this->getJWTLoader()->load($request, $this->key_encryption_key_set, false);

        try {
            Assertion::true($jwt->hasClaims(), 'The request object does not contain claims.');
            $client = $this->getClient(array_merge($params, $jwt->getClaims()));

            $public_key_set = $client->getPublicKeySet();

            Assertion::notNull($public_key_set, 'The client does not have signature capabilities.');

            $this->getJWTLoader()->verify($jwt, $public_key_set);
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST_OBJECT, $e->getMessage());
        }

        return $jwt;
    }

    /**
     * @param string $url
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     *
     * @return string
     */
    private function downloadContent($url)
    {
        // The URL must be a valid URL and scheme must be https
        Assertion::false(
            false === filter_var($url, FILTER_VALIDATE_URL, FILTER_FLAG_SCHEME_REQUIRED | FILTER_FLAG_HOST_REQUIRED),
            'Invalid URL.'
        );
        Assertion::false('https://' !==  mb_substr($url, 0, 8, '8bit'), 'Unsecured connection.');

        $curl_params = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_URL            => $url,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ];

        $ch = curl_init();
        curl_setopt_array($ch, $curl_params);
        $content = curl_exec($ch);
        curl_close($ch);

        if (!is_string($content)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST_URI, 'Unable to get content.');
        }

        return $content;
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
        $client = array_key_exists('client_id', $params) ? $this->getClientManager()->getClient($params['client_id']) : null;
        if (!$client instanceof ClientInterface) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "client_id" missing or invalid.');
        }

        return $client;
    }

    /**
     * @param array $params
     */
    private function prepareScope(array &$params)
    {
        if (array_key_exists('scope', $params)) {
            $params['scope'] = explode(' ', $params['scope']);
        } else {
            $params['scope'] = [];
        }
    }

    /**
     * @param array $params
     */
    private function preparePrompt(array &$params)
    {
        if (array_key_exists('prompt', $params)) {
            $params['prompt'] = explode(' ', $params['prompt']);
        }
    }
}
