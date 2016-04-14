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
    private $redirect_uri_enforced = false;

    /**
     * @var bool
     */
    private $secured_redirect_uri_enforced = false;

    /**
     * @var bool
     */
    private $state_parameter_enforced = false;

    /**
     * @var bool
     */
    private $redirect_uri_required_for_registered_client = false;

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
        $redirect_uri = $this->checkRedirectUri($authorization);
        $this->checkRedirectUriFragment($redirect_uri);
        $this->checkSecuredRedirectUri($redirect_uri);

        $this->checkState($authorization);
        $this->checkScope($authorization);

        $types = $this->getResponseTypes($authorization);

        $response_mode = $this->getResponseMode($types, $authorization);

        if ($authorization->isAuthorized() === false) {
            $params = [
                'transport_mode' => $response_mode->getName(),
                'redirect_uri'   => $authorization->get('redirect_uri'),
            ];
            if (true === $authorization->has('state')) {
                $params['state'] = $authorization->get('state');
            }
            $exception = $this->getExceptionManager()->getRedirectException(ExceptionManagerInterface::ACCESS_DENIED, 'The resource owner denied access to your client', $params);
            $exception->getHttpResponse($response);

            return;
        }

        $result = [];
        foreach ($types as $type) {
            $result = array_merge(
                $result,
                $type->prepareAuthorization($authorization)
            );
        }
        if ($authorization->has('state')) {
            $result['state'] = $authorization->get('state');
        }
        foreach ($types as $type) {
            $type->finalizeAuthorization($result, $authorization, $redirect_uri);
        }

        $response_mode->prepareResponse($redirect_uri, $result, $response);
    }

    /**
     * @param \OAuth2\Endpoint\Authorization $authorization An array with mixed values
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    private function checkRedirectUri(Authorization $authorization)
    {
        $this->checkRedirectUriIfRequired($authorization);

        $redirect_uri = $authorization->has('redirect_uri') ? $authorization->get('redirect_uri') : null;
        $redirect_uris = $this->getClientRedirectUris($authorization);

        if (empty($redirect_uri) && empty($redirect_uris)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The "redirect_uri" parameter is missing. Add "redirect_uri" parameter or store redirect URIs to your client');
        }
        if (!empty($redirect_uri) && !empty($redirect_uris) && false === Uri::isRedirectUriAllowed($redirect_uri, $redirect_uris)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The specified redirect URI is not valid');
        }
        if (!empty($redirect_uri)) {
            return $redirect_uri;
        }

        return $redirect_uris[0];
    }

    /**
     * @param \OAuth2\Endpoint\Authorization $authorization
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkRedirectUriIfRequired(Authorization $authorization)
    {
        //If the redirect URI is not set and the configuration requires it, throws an exception
        if (true === $this->isRedirectUriEnforced() && false === $authorization->has('redirect_uri')) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The "redirect_uri" parameter is mandatory');
        }
    }

    /**
     * Check if a fragment is in the URI.
     *
     * @param string $redirect_uri An array with mixed values
     *
     * @see http://tools.ietf.org/html/rfc6749#section-3.1.2
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkRedirectUriFragment($redirect_uri)
    {
        $uri = parse_url($redirect_uri);
        if (isset($uri['fragment'])) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The "redirect_uri" must not contain fragment');
        }
    }

    /**
     * Check if the redirect URI is secured if the configuration requires it.
     *
     * @param string $redirect_uri The redirect uri to check
     *
     * @see http://tools.ietf.org/html/rfc6749#section-3.1.2.1
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkSecuredRedirectUri($redirect_uri)
    {
        if (true === $this->isSecuredRedirectUriEnforced() && 'https' !== mb_substr($redirect_uri, 0, 5, '8bit')) {
            if (!$this->isALocalUriOrAnUrn($redirect_uri)) {
                throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The "redirect_uri" must be secured');
            }
        }
    }

    /**
     * Redirection to an URN or a local host is allowed.
     *
     * @param string $redirect_uri
     *
     * @return bool
     */
    private function isALocalUriOrAnUrn($redirect_uri)
    {
        $parsed = parse_url($redirect_uri);
        if (array_key_exists('scheme', $parsed) && array_key_exists('host', $parsed) &&
            'http' === $parsed['scheme'] && in_array($parsed['host'], ['localhost', '127.0.0.1'])
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

        $redirect_uris = $client->getRedirectUris();
        /*
         * @see http://tools.ietf.org/html/rfc6749#section-3.1.2.2
         */
        if (!empty($redirect_uris)) {
            return $redirect_uris;
        }

        $this->checkRedirectUriIfRequiredForRegisteredClients();
        $this->checkRedirectUriForNonConfidentialClient($client);
        $this->checkRedirectUriForConfidentialClient($client, $authorization);

        return [];
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkRedirectUriIfRequiredForRegisteredClients()
    {
        if (true === $this->isRedirectUriRequiredForRegisteredClients()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_CLIENT, 'Registered clients must register at least one redirect URI');
        }
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
     * @param \OAuth2\Endpoint\Authorization           $authorization
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkRedirectUriForConfidentialClient(ClientInterface $client, Authorization $authorization)
    {
        if (!$client->isPublic() && $authorization->has('response_type') && $authorization->get('response_type') === 'token') {
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
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The "state" parameter is mandatory');
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
        /*
         * @see http://tools.ietf.org/html/rfc6749#section-3.1.1
         */
        if (!$authorization->has('response_type')) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Invalid "response_type" parameter or parameter is missing.');
        }

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
    public function isRedirectUriEnforced()
    {
        return $this->redirect_uri_enforced;
    }

    public function enabledRedirectUriEnforcement()
    {
        $this->redirect_uri_enforced = true;
    }

    public function disableRedirectUriEnforcement()
    {
        $this->redirect_uri_enforced = false;
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
    public function isRedirectUriRequiredForRegisteredClients()
    {
        return $this->redirect_uri_required_for_registered_client;
    }

    public function enableRedirectUriForRegisteredClientsRequirement()
    {
        $this->redirect_uri_required_for_registered_client = true;
    }

    public function disableRedirectUriForRegisteredClientsRequirement()
    {
        $this->redirect_uri_required_for_registered_client = false;
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
