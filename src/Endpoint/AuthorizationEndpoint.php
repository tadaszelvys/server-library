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

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasResponseModeSupport;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Grant\ResponseTypeSupportInterface;
use OAuth2\Scope\ScopeManagerInterface;
use OAuth2\Util\Uri;
use Psr\Http\Message\ResponseInterface;

final class AuthorizationEndpoint implements AuthorizationEndpointInterface
{
    use HasExceptionManager;
    use HasScopeManager;
    use HasResponseModeSupport;

    /**
     * @var \OAuth2\Grant\ResponseTypeSupportInterface[]
     */
    private $response_types = [];

    /**
     * @var bool
     */
    private $secured_redirect_uri_enforced = false;

    /**
     * @var bool
     */
    private $state_parameter_enforced = false;

    /**
     * AuthorizationEndpoint constructor.
     *
     * @param \OAuth2\Scope\ScopeManagerInterface         $scope_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(
        ScopeManagerInterface $scope_manager,
        ExceptionManagerInterface $exception_manager
    ) {
        $this->setExceptionManager($exception_manager);
        $this->setScopeManager($scope_manager);
    }

    /**
     * @param \OAuth2\Grant\ResponseTypeSupportInterface $response_type
     */
    public function addResponseType(ResponseTypeSupportInterface $response_type)
    {
        $type = $response_type->getResponseType();
        if (!array_key_exists($type, $this->response_types)) {
            $this->response_types[$type] = $response_type;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseTypesSupported()
    {
        $types = array_keys($this->response_types);
        if (in_array('id_token', $types)) {
            if (in_array('code', $types)) {
                $types[] = 'code id_token';
            }
            if (in_array('token', $types)) {
                $types[] = 'id_token token';
            }
            if (in_array('code', $types) && in_array('token', $types)) {
                $types[] = 'code id_token token';
            }
        } else {
            if (in_array('code', $types) && in_array('token', $types)) {
                $types[] = 'code token';
            }
        }

        return $types;
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseModesSupported()
    {
        return array_keys($this->getResponseModes());
    }

    /**
     * {@inheritdoc}
     */
    public function authorize(Authorization $authorization, ResponseInterface &$response)
    {
        $this->checkHasResponseType($authorization);
        $redirect_uri = $this->getRedirectUri($authorization);

        $this->checkState($authorization);
        $this->checkScope($authorization);

        $types = $this->getResponseTypes($authorization);

        $response_mode = $this->getResponseMode($types, $authorization);

        if ($authorization->isAuthorized() === false) {
            $params = [
                'transport_mode' => $response_mode->getName(),
                'redirect_uri'   => $redirect_uri,
            ];
            if (true === $authorization->has('state')) {
                $params['state'] = $authorization->get('state');
            }
            $exception = $this->getExceptionManager()->getRedirectException(ExceptionManagerInterface::ACCESS_DENIED, 'The resource owner denied access to your client', $params);
            $exception->getHttpResponse($response);

            return;
        }

        $response_parameters = [];
        foreach ($types as $type) {
            $response_parameters = array_merge(
                $response_parameters,
                $type->prepareAuthorization($authorization)
            );
        }
        if ($authorization->has('state')) {
            $response_parameters['state'] = $authorization->get('state');
        }
        foreach ($types as $type) {
            $type->finalizeAuthorization($response_parameters, $authorization, $redirect_uri);
        }

        $response_mode->prepareResponse($redirect_uri, $response_parameters, $response);
    }

    /**
     * @param \OAuth2\Endpoint\Authorization $authorization An array with mixed values
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    private function checkHasResponseType(Authorization $authorization)
    {
        /*
         * @see http://tools.ietf.org/html/rfc6749#section-3.1.1
         */
        if (false === $authorization->has('response_type')) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The "response_type" parameter is mandatory.');
        }
    }

    /**
     * @param \OAuth2\Endpoint\Authorization $authorization An array with mixed values
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    private function getRedirectUri(Authorization $authorization)
    {
        $this->checkRedirectUriIsSet($authorization);
        $redirect_uri = $authorization->get('redirect_uri');
        $this->checkRedirectUriHasNoFragment($redirect_uri);
        $this->checkIfRedirectUriIsSecuredIfNeeded($redirect_uri);

        $client_redirect_uris = $this->getClientRedirectUris($authorization);

        if (!empty($client_redirect_uris) && false === Uri::isRedirectUriAllowed($redirect_uri, $client_redirect_uris)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The specified redirect URI is not valid');
        }

        return $redirect_uri;
    }

    /**
     * @param \OAuth2\Endpoint\Authorization $authorization
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkRedirectUriIsSet(Authorization $authorization)
    {
        //If the redirect URI is not set, throws an exception
        if (false === $authorization->has('redirect_uri')) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The "redirect_uri" parameter is mandatory.');
        }
    }

    /**
     * Check if a fragment is in the URI.
     *
     * @param string $redirect_uri
     *
     * @see http://tools.ietf.org/html/rfc6749#section-3.1.2
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkRedirectUriHasNoFragment($redirect_uri)
    {
        $uri = parse_url($redirect_uri);
        if (isset($uri['fragment'])) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The "redirect_uri" must not contain fragment');
        }
    }

    /**
     * Check if the redirect URI is secured if the configuration requires it.
     *
     * @param string $redirect_uri
     *
     * @see http://tools.ietf.org/html/rfc6749#section-3.1.2.1
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkIfRedirectUriIsSecuredIfNeeded($redirect_uri)
    {
        if (true === $this->isSecuredRedirectUriEnforced() && 'https' !== mb_substr($redirect_uri, 0, 5, '8bit')) {
            if (!$this->isALocalUriOrAnUrn($redirect_uri)) {
                throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The "redirect_uri" must be secured');
            }
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
        if (array_key_exists('scheme', $parsed) && array_key_exists('host', $parsed) &&
            'http' === $parsed['scheme'] && in_array($parsed['host'], ['[::1]', '127.0.0.1'])
        ) {
            return true;
        }

        return false;
    }

    /**
     * Check if the redirect URIs stored by the client.
     *
     * @param \OAuth2\Endpoint\Authorization $authorization An array with mixed values
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return array
     */
    private function getClientRedirectUris(Authorization $authorization)
    {
        $client = $authorization->getClient();

        $redirect_uris = $client->get('redirect_uris');
        /*
         * @see http://tools.ietf.org/html/rfc6749#section-3.1.2.2
         */
        if (!empty($redirect_uris)) {
            return $redirect_uris;
        }

        $this->checkRedirectUriForNonConfidentialClient($client);
        $this->checkRedirectUriForConfidentialClient($client, $authorization);

        return [];
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkRedirectUriForNonConfidentialClient(ClientInterface $client)
    {
        if (true === $client->isPublic()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_CLIENT, 'Non-confidential clients must register at least one redirect URI');
        }
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param \OAuth2\Endpoint\Authorization $authorization
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkRedirectUriForConfidentialClient(ClientInterface $client, Authorization $authorization)
    {
        if (!$client->isPublic() && $authorization->get('response_type') === 'token') {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_CLIENT, 'Confidential clients must register at least one redirect URI when using "token" response type');
        }
    }

    /**
     * @param \OAuth2\Endpoint\Authorization $authorization An array with mixed values
     *
     * @see http://tools.ietf.org/html/rfc6749#section-3.1.2
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkState(Authorization $authorization)
    {
        if (!$authorization->has('state') && $this->isStateParameterEnforced()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The "state" parameter is mandatory.');
        }
    }

    private function checkScope(Authorization &$authorization)
    {
        try {
            $scope = $this->getScopeManager()->checkScopePolicy($authorization->getScopes(), $authorization->getClient());
            $authorization->setScopes($scope);
        } catch (BaseExceptionInterface $e) {
            throw $e;
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getBadRequestException($e->getMessage());
        }

        $availableScopes = $this->getScopeManager()->getAvailableScopesForClient($authorization->getClient());
        if (!$this->getScopeManager()->checkScopes($scope, $availableScopes)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_SCOPE, 'An unsupported scope was requested. Available scopes for the client are ['.implode(',', $availableScopes).']');
        }
    }

    /**
     * @param \OAuth2\Endpoint\Authorization $authorization
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Grant\ResponseTypeSupportInterface[]
     */
    private function getResponseTypes(Authorization $authorization)
    {
        $response_types = explode(' ', $authorization->get('response_type'));
        if (count($response_types) > count(array_unique($response_types))) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Invalid "response_type" parameter or parameter is missing.');
        }

        $types = [];
        foreach ($response_types as $response_type) {
            if (!array_key_exists($response_type, $this->response_types)) {
                throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, sprintf('Response type "%s" is not supported by this server', $response_type));
            }
            $type = $this->response_types[$response_type];
            if (!$authorization->getClient()->isResponseTypeAllowed($type->getResponseType())) {
                throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::UNAUTHORIZED_CLIENT, 'The response type "'.$authorization->get('response_type').'" is unauthorized for this client.');
            }
            $types[] = $type;
        }

        return $types;
    }

    /**
     * @return bool
     */
    public function isSecuredRedirectUriEnforced()
    {
        return $this->secured_redirect_uri_enforced;
    }

    public function enableSecuredRedirectUriEnforcement()
    {
        $this->secured_redirect_uri_enforced = true;
    }

    public function disableSecuredRedirectUriEnforcement()
    {
        $this->secured_redirect_uri_enforced = false;
    }

    /**
     * @return bool
     */
    public function isStateParameterEnforced()
    {
        return $this->state_parameter_enforced;
    }

    public function enableStateParameterEnforcement()
    {
        $this->state_parameter_enforced = true;
    }

    public function disableStateParameterEnforcement()
    {
        $this->state_parameter_enforced = false;
    }
}
