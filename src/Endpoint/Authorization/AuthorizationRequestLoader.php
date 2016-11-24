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
use Http\Client\HttpClient;
use Jose\JWTLoaderInterface;
use Jose\Object\JWKSetInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\Util\Uri;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Request;

class AuthorizationRequestLoader implements AuthorizationRequestLoaderInterface
{
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
     * @var bool
     */
    private $require_encryption = false;

    /**
     * @var string[]
     */
    private $mandatory_claims = [];

    /**
     * @var null|\Http\Client\HttpClient
     */
    private $client = null;

    /**
     * AuthorizationRequestLoader constructor.
     *
     * @param \OAuth2\Client\ClientManagerInterface       $client_manager
     * @param \OAuth2\Response\OAuth2ResponseFactoryManagerInterface $response_factory_manager
     */
    public function __construct(ClientManagerInterface $client_manager, OAuth2ResponseFactoryManagerInterface $response_factory_manager)
    {
        $this->setClientManager($client_manager);
        $this->setResponsefactoryManager($response_factory_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function enableRequestUriRegistrationRequirement()
    {
        $this->require_request_uri_registration = true;
    }

    /**
     * {@inheritdoc}
     */
    public function disableRequestUriRegistrationRequirement()
    {
        $this->require_request_uri_registration = false;
    }

    /**
     * {@inheritdoc}
     */
    public function isRequestUriRegistrationRequired()
    {
        return $this->require_request_uri_registration;
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
        return false === $this->hasJWTLoader() ? [] : $this->getJWTLoader()->getSupportedSignatureAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedKeyEncryptionAlgorithms()
    {
        return false === $this->hasJWTLoader() ? [] : $this->getJWTLoader()->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return false === $this->hasJWTLoader() ? [] : $this->getJWTLoader()->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function enableRequestObjectSupport(JWTLoaderInterface $jwt_loader, array $mandatory_claims = [])
    {
        Assertion::allString($mandatory_claims, 'The mandatory claims array should contain only claims.');
        $this->setJWTLoader($jwt_loader);
        $this->request_object_allowed = true;
        $this->mandatory_claims = $mandatory_claims;
    }

    /**
     * {@inheritdoc}
     */
    public function enableRequestObjectReferenceSupport(HttpClient $client)
    {
        Assertion::true($this->isRequestObjectSupportEnabled(), 'Request object support must be enabled first.');
        $this->request_object_reference_allowed = true;
        $this->client = $client;
    }

    /**
     * {@inheritdoc}
     */
    public function enableEncryptedRequestObjectSupport(JWKSetInterface $key_encryption_key_set, $require_encryption)
    {
        Assertion::boolean($require_encryption);
        Assertion::true($this->isRequestObjectSupportEnabled(), 'Request object support must be enabled first.');
        Assertion::greaterThan($key_encryption_key_set->countKeys(), 0, 'The encryption key set must have at least one key.');
        $this->require_encryption = $require_encryption;
        $this->key_encryption_key_set = $key_encryption_key_set;
    }

    /**
     * {@inheritdoc}
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
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return array
     */
    private function createFromRequestParameter(array $params)
    {
        if (false === $this->isRequestObjectSupportEnabled()) {
            throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_REQUEST_NOT_SUPPORTED, 'error_description' => 'The parameter \'request\' is not supported.']));
        }
        $request = $params['request'];
        Assertion::string($request);

        $jws = $this->loadRequest($params, $request, $client);
        $params = array_merge($params, $jws->getClaims(), ['client' => $client]);
        $this->checkIssuerAndClientId($params);

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
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return array
     */
    private function createFromRequestUriParameter(array $params)
    {
        if (false === $this->isRequestObjectReferenceSupportEnabled()) {
            throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_REQUEST_URI_NOT_SUPPORTED, 'error_description' => 'The parameter \'request_uri\' is not supported.']));
        }
        $request_uri = $params['request_uri'];

        $content = $this->downloadContent($request_uri);
        $jws = $this->loadRequest($params, $content, $client);
        if (true === $this->isRequestUriRegistrationRequired()) {
            $this->checkRequestUri($client, $request_uri);
        }
        $params = array_merge($params, $jws->getClaims(), ['client' => $client]);
        $this->checkIssuerAndClientId($params);

        return $params;
    }

    /**
     * @param array $params
     *
     * @throws \OAuth2\Response\OAuth2Exception
     */
    private function checkIssuerAndClientId(array $params)
    {
        if (array_key_exists('iss', $params) && array_key_exists('client_id', $params)) {
            Assertion::eq($params['iss'], $params['client_id'], 'The issuer of the request object is not the client who requests the authorization.');
        }
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param string                         $request_uri
     *
     * @throws \OAuth2\Response\OAuth2Exception
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
        throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST_URI, 'error_description' => 'The request Uri is not allowed.']));
    }

    /**
     * @param string $request_uri
     *
     * @throws \OAuth2\Response\OAuth2Exception
     */
    private function checkRequestUriPathTraversal($request_uri)
    {
        if (false === Uri::checkUrl($request_uri, false)) {
            throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_CLIENT, 'error_description' => 'The request Uri must not contain path traversal.']));
        }
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return string[]
     */
    private function getClientRequestUris(ClientInterface $client)
    {
        if (false === $client->has('request_uris') || empty($request_uris = $client->get('request_uris'))) {
            throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_CLIENT, 'error_description' => 'The client must register at least one request Uri.']));
        }

        return $request_uris;
    }

    /**
     * @param array                               $params
     * @param string                              $request
     * @param \OAuth2\Client\ClientInterface|null $client
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return \Jose\Object\JWSInterface
     */
    private function loadRequest(array $params, $request, ClientInterface &$client = null)
    {
        $jwt = $this->getJWTLoader()->load($request, $this->key_encryption_key_set, $this->require_encryption);

        try {
            Assertion::true($jwt->hasClaims(), 'The request object does not contain claims.');
            $client = $this->getClient(array_merge($params, $jwt->getClaims()));

            $public_key_set = $client->getPublicKeySet();

            Assertion::notNull($public_key_set, 'The client does not have signature capabilities.');

            $this->getJWTLoader()->verify($jwt, $public_key_set);
            $missing_claims = array_keys(array_diff_key(array_flip($this->mandatory_claims), $jwt->getClaims()));
            Assertion::true(0 === count($missing_claims), 'The following mandatory claims are missing: %s.', implode(', ', $missing_claims));
        } catch (\Exception $e) {
            throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST_OBJECT, 'error_description' => $e->getMessage()]));
        }

        return $jwt;
    }

    /**
     * @param string $url
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return string
     */
    private function downloadContent($url)
    {
        $request = new Request($url, 'GET');
        $response = $this->client->sendRequest($request);
        Assertion::eq(200, $response->getStatusCode());

        $content = $response->getBody()->getContents();
        if (!is_string($content)) {
            throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST_URI, 'error_description' => 'Unable to get content.']));
        }

        return $content;
    }

    /**
     * @param array $params
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return \OAuth2\Client\ClientInterface
     */
    private function getClient(array $params)
    {
        $client = array_key_exists('client_id', $params) ? $this->getClientManager()->getClient($params['client_id']) : null;
        if (!$client instanceof ClientInterface) {
            throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'Parameter \'client_id\' missing or invalid.']));
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
