<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization;

use Assert\Assertion;
use Http\Client\HttpClient;
use Jose\JWTLoaderInterface;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\Client\ClientRepositoryInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManager;
use OAuth2\Util\Uri;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Request;

final class AuthorizationRequestLoader
{
    /**
     * @var ClientRepositoryInterface
     */
    private $clientRepository;

    /**
     * @var bool
     */
    private $requestObjectAllowed = false;

    /**
     * @var bool
     */
    private $requestObjectReferenceAllowed = false;

    /**
     * @var JWKSetInterface|null
     */
    private $keyEncryptionKeySet = null;

    /**
     * @var bool
     */
    private $requireRequestUriRegistration = true;

    /**
     * @var bool
     */
    private $requireEncryption = false;

    /**
     * @var string[]
     */
    private $mandatoryClaims = [];

    /**
     * @var null|HttpClient
     */
    private $client = null;

    /**
     * @var null|JWTLoaderInterface
     */
    private $jwtLoader = null;

    /**
     * AuthorizationRequestLoader constructor.
     *
     * @param ClientRepositoryInterface $clientRepository
     */
    public function __construct(ClientRepositoryInterface $clientRepository)
    {
        $this->clientRepository = $clientRepository;
    }

    public function enableRequestUriRegistrationRequirement()
    {
        $this->requireRequestUriRegistration = true;
    }

    public function disableRequestUriRegistrationRequirement()
    {
        $this->requireRequestUriRegistration = false;
    }

    /**
     * @return bool
     */
    public function isRequestUriRegistrationRequired(): bool
    {
        return $this->requireRequestUriRegistration;
    }

    /**
     * {@inheritdoc}
     */
    public function isRequestObjectSupportEnabled()
    {
        return $this->requestObjectAllowed;
    }

    /**
     * {@inheritdoc}
     */
    public function isRequestObjectReferenceSupportEnabled()
    {
        return $this->requestObjectReferenceAllowed;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedSignatureAlgorithms()
    {
        return null === $this->jwtLoader ? [] : $this->jwtLoader->getSupportedSignatureAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedKeyEncryptionAlgorithms()
    {
        return null === $this->jwtLoader ? [] : $this->jwtLoader->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return null === $this->jwtLoader ? [] : $this->jwtLoader->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * @param JWTLoaderInterface $jwtLoader
     * @param string[]          $mandatoryClaims
     */
    public function enableRequestObjectSupport(JWTLoaderInterface $jwtLoader, array $mandatoryClaims = [])
    {
        Assertion::allString($mandatoryClaims, 'The mandatory claims array should contain only claims.');
        $this->jwtLoader = $jwtLoader;
        $this->requestObjectAllowed = true;
        $this->mandatoryClaims = $mandatoryClaims;
    }

    /**
     * @param HttpClient $client
     */
    public function enableRequestObjectReferenceSupport(HttpClient $client)
    {
        Assertion::true($this->isRequestObjectSupportEnabled(), 'Request object support must be enabled first.');
        $this->requestObjectReferenceAllowed = true;
        $this->client = $client;
    }

    /**
     * @param JWKSetInterface $keyEncryptionKeySet
     * @param bool            $requireEncryption
     */
    public function enableEncryptedRequestObjectSupport(JWKSetInterface $keyEncryptionKeySet, bool $requireEncryption)
    {
        Assertion::true($this->isRequestObjectSupportEnabled(), 'Request object support must be enabled first.');
        Assertion::greaterThan($keyEncryptionKeySet->countKeys(), 0, 'The encryption key set must have at least one key.');
        $this->requireEncryption = $requireEncryption;
        $this->keyEncryptionKeySet = $keyEncryptionKeySet;
    }

    /**
     * {@inheritdoc}
     */
    public function isEncryptedRequestsSupportEnabled()
    {
        return null !== $this->keyEncryptionKeySet;
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
     * @throws OAuth2Exception
     *
     * @return array
     */
    private function createFromRequestParameter(array $params)
    {
        if (false === $this->isRequestObjectSupportEnabled()) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManager::ERROR_REQUEST_NOT_SUPPORTED, 'error_description' => 'The parameter \'request\' is not supported.']);
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
     * @throws OAuth2Exception
     *
     * @return array
     */
    private function createFromRequestUriParameter(array $params)
    {
        if (false === $this->isRequestObjectReferenceSupportEnabled()) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManager::ERROR_REQUEST_URI_NOT_SUPPORTED, 'error_description' => 'The parameter \'request_uri\' is not supported.']);
        }
        $requestUri = $params['request_uri'];

        $content = $this->downloadContent($requestUri);
        $jws = $this->loadRequest($params, $content, $client);
        if (true === $this->isRequestUriRegistrationRequired()) {
            $this->checkRequestUri($client, $requestUri);
        }
        $params = array_merge($params, $jws->getClaims(), ['client' => $client]);
        $this->checkIssuerAndClientId($params);

        return $params;
    }

    /**
     * @param array $params
     *
     * @throws OAuth2Exception
     */
    private function checkIssuerAndClientId(array $params)
    {
        if (array_key_exists('iss', $params) && array_key_exists('client_id', $params)) {
            Assertion::eq($params['iss'], $params['client_id'], 'The issuer of the request object is not the client who requests the authorization.');
        }
    }

    /**
     * @param Client $client
     * @param string $requestUri
     *
     * @throws OAuth2Exception
     */
    private function checkRequestUri(Client $client, $requestUri)
    {
        $this->checkRequestUriPathTraversal($requestUri);
        $stored_request_uris = $this->getClientRequestUris($client);

        foreach ($stored_request_uris as $stored_request_uri) {
            if (strcasecmp(mb_substr($requestUri, 0, mb_strlen($stored_request_uri, '8bit'), '8bit'), $stored_request_uri) === 0) {
                return;
            }
        }
        throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManager::ERROR_INVALID_REQUEST_URI, 'error_description' => 'The request Uri is not allowed.']);
    }

    /**
     * @param string $requestUri
     *
     * @throws OAuth2Exception
     */
    private function checkRequestUriPathTraversal($requestUri)
    {
        if (false === Uri::checkUrl($requestUri, false)) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManager::ERROR_INVALID_CLIENT, 'error_description' => 'The request Uri must not contain path traversal.']);
        }
    }

    /**
     * @param Client $client
     *
     * @throws OAuth2Exception
     *
     * @return string[]
     */
    private function getClientRequestUris(Client $client)
    {
        if (false === $client->has('request_uris') || empty($requestUris = $client->get('request_uris'))) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManager::ERROR_INVALID_CLIENT, 'error_description' => 'The client must register at least one request Uri.']);
        }

        return $requestUris;
    }

    /**
     * @param array       $params
     * @param string      $request
     * @param Client|null $client
     *
     * @throws OAuth2Exception
     *
     * @return JWSInterface
     */
    private function loadRequest(array $params, string $request, Client &$client = null): JWSInterface
    {
        $jwt = $this->jwtLoader->load($request, $this->keyEncryptionKeySet, $this->requireEncryption);

        try {
            Assertion::true($jwt->hasClaims(), 'The request object does not contain claims.');
            $client = $this->getClient(array_merge($params, $jwt->getClaims()));

            $public_key_set = $client->getPublicKeySet();

            Assertion::notNull($public_key_set, 'The client does not have signature capabilities.');

            $this->jwtLoader->verify($jwt, $public_key_set);
            $missing_claims = array_keys(array_diff_key(array_flip($this->mandatoryClaims), $jwt->getClaims()));
            Assertion::true(0 === count($missing_claims), 'The following mandatory claims are missing: %s.', implode(', ', $missing_claims));
        } catch (\Exception $e) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManager::ERROR_INVALID_REQUEST_OBJECT, 'error_description' => $e->getMessage()]);
        }

        return $jwt;
    }

    /**
     * @param string $url
     *
     * @throws OAuth2Exception
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
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManager::ERROR_INVALID_REQUEST_URI, 'error_description' => 'Unable to get content.']);
        }

        return $content;
    }

    /**
     * @param array $params
     *
     * @throws OAuth2Exception
     *
     * @return Client
     */
    private function getClient(array $params): Client
    {
        $client = array_key_exists('client_id', $params) ? $this->clientRepository->find(ClientId::create($params['client_id'])) : null;
        if (!$client instanceof Client) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManager::ERROR_INVALID_REQUEST, 'error_description' => 'Parameter \'client_id\' missing or invalid.']);
        }

        return $client;
    }

    /**
     * @param array $params
     */
    private function prepareScope(array &$params)
    {
        // Check chars
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
