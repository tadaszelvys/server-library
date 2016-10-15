<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization\ParameterChecker;

use Assert\Assertion;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\Uri;

final class RedirectUriParameterChecker implements ParameterCheckerInterface
{
    /**
     * @var bool
     */
    private $secured_redirect_uri_enforced;

    /**
     * @var bool
     */
    private $redirect_uri_storage_enforced;

    /**
     * RedirectUriParameterChecker constructor.
     *
     * @param bool $secured_redirect_uri_enforced
     * @param bool $redirect_uri_storage_enforced
     */
    public function __construct($secured_redirect_uri_enforced, $redirect_uri_storage_enforced)
    {
        Assertion::boolean($secured_redirect_uri_enforced);
        Assertion::boolean($redirect_uri_storage_enforced);
        $this->secured_redirect_uri_enforced = $secured_redirect_uri_enforced;
        $this->redirect_uri_storage_enforced = $redirect_uri_storage_enforced;
    }

    /**
     * {@inheritdoc}
     */
    public function checkerParameter(ClientInterface $client, array &$parameters)
    {
        $this->checkRedirectUriIsSet($parameters);
        $redirect_uri = $parameters['redirect_uri'];

        $this->checkRedirectUriHasNoFragment($redirect_uri);
        $this->checkIfRedirectUriIsSecuredIfNeeded($redirect_uri);
        $this->checkRedirectUriForTheClient($client, $redirect_uri, $parameters);
    }

    /**
     * {@inheritdoc}
     */
    public function getError()
    {
        return ExceptionManagerInterface::INVALID_REQUEST;
    }

    /**
     * @param array $parameters
     *
     * @throws \InvalidArgumentException
     */
    private function checkRedirectUriIsSet(array $parameters)
    {
        Assertion::keyExists($parameters, 'redirect_uri', 'The parameter "redirect_uri" is mandatory.');
    }

    /**
     * Check if a fragment is in the URI.
     *
     * @param string $redirect_uri
     *
     * @see http://tools.ietf.org/html/rfc6749#section-3.1.2
     *
     * @throws \InvalidArgumentException
     */
    private function checkRedirectUriHasNoFragment($redirect_uri)
    {
        $uri = parse_url($redirect_uri);
        Assertion::false(isset($uri['fragment']), 'The parameter "redirect_uri" must not contain fragment');
    }

    /**
     * Check if the redirect URI is secured if the configuration requires it.
     *
     * @param string $redirect_uri
     *
     * @see http://tools.ietf.org/html/rfc6749#section-3.1.2.1
     *
     * @throws \InvalidArgumentException
     */
    private function checkIfRedirectUriIsSecuredIfNeeded($redirect_uri)
    {
        if (false === $this->isSecuredRedirectUriEnforced()) {
            return;
        }
        if (true === $this->isSecuredRedirectUriEnforced() && 'https' !== mb_substr($redirect_uri, 0, 5, '8bit')) {
            Assertion::true($this->isALocalUriOrAnUrn($redirect_uri), 'The parameter "redirect_uri" must be a secured URI.');
        }
    }

    /**
     * Redirection to an URN or a local host is allowed if the https is required.
     *
     * @param string $redirect_uri
     *
     * @return bool
     */
    private function isALocalUriOrAnUrn($redirect_uri)
    {
        $parsed = parse_url($redirect_uri);

        return array_key_exists('scheme', $parsed) && array_key_exists('host', $parsed) && 'http' === $parsed['scheme'] && in_array($parsed['host'], ['[::1]', '127.0.0.1']);
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param string                         $redirect_uri
     * @param array                          $parameters
     */
    public function checkRedirectUriForTheClient(ClientInterface $client, $redirect_uri, array $parameters)
    {
        $client_redirect_uris = $this->getClientRedirectUris($client, $parameters);

        Assertion::false(!empty($client_redirect_uris) && false === Uri::isRedirectUriAllowed($redirect_uri, $client_redirect_uris), 'The specified redirect URI is not valid.');
    }

    /**
     * Check if the redirect URIs stored by the client.
     *
     * @param \OAuth2\Client\ClientInterface $client
     * @param array                          $parameters
     *
     * @throws \InvalidArgumentException
     *
     * @return array
     *
     * @see http://tools.ietf.org/html/rfc6749#section-3.1.2.2
     */
    private function getClientRedirectUris(ClientInterface $client, array $parameters)
    {
        if (!$client->has('redirect_uris') || empty($redirect_uris = $client->get('redirect_uris'))) {
            $this->checkRedirectUriForAllClient();
            $this->checkRedirectUriForNonConfidentialClient($client);
            $this->checkRedirectUriForConfidentialClient($client, $parameters);

            return [];
        }

        return $redirect_uris;
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @throws \InvalidArgumentException
     */
    private function checkRedirectUriForNonConfidentialClient(ClientInterface $client)
    {
        Assertion::false($client->isPublic(), 'Non-confidential clients must register at least one redirect URI.');
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param array                          $parameters
     *
     * @throws \InvalidArgumentException
     */
    private function checkRedirectUriForConfidentialClient(ClientInterface $client, array $parameters)
    {
        Assertion::false(!$client->isPublic() && array_key_exists('response_type', $parameters) && $parameters['response_type'] === 'token', 'Confidential clients must register at least one redirect URI when using "token" response type.');
    }

    /**
     * @throws \InvalidArgumentException
     */
    private function checkRedirectUriForAllClient()
    {
        Assertion::false($this->isRedirectUriStorageEnforced(), 'Clients must register at least one redirect URI.');
    }

    /**
     * @return bool
     */
    private function isSecuredRedirectUriEnforced()
    {
        return $this->secured_redirect_uri_enforced;
    }

    /**
     * @return bool
     */
    private function isRedirectUriStorageEnforced()
    {
        return $this->redirect_uri_storage_enforced;
    }
}
