<?php

namespace OAuth2\Endpoint;

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasResponseModeSupport;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Client\ConfidentialClientInterface;
use OAuth2\Client\RegisteredClientInterface;
use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Grant\ResponseTypeSupportInterface;
use OAuth2\Util\Uri;
use Psr\Http\Message\ResponseInterface;

class AuthorizationEndpoint implements AuthorizationEndpointInterface
{
    use HasConfiguration;
    use HasExceptionManager;
    use HasScopeManager;
    use HasResponseModeSupport;

    /**
     * @var \OAuth2\Grant\ResponseTypeSupportInterface[]
     */
    protected $response_types = [];

    public function addResponseType(ResponseTypeSupportInterface $response_type)
    {
        $type = $response_type->getResponseType();
        if (array_key_exists($type, $this->response_types)) {
            return $this;
        }
        $this->response_types[$type] = $response_type;

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     * @throws \OAuth2\Exception\InternalServerErrorExceptionInterface
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
            $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::REDIRECT, ExceptionManagerInterface::ACCESS_DENIED, 'The resource owner denied access to your client', ['transport_mode' => $response_mode->getName(), 'redirect_uri' => $authorization->getRedirectUri(), 'state' => $authorization->getState()]);
            $exception->getHttpResponse($response);

            return;
        }

        $result = [];
        foreach ($types as $type) {
            $temp = $type->grantAuthorization($authorization);
            $result = array_merge($result, $temp);
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
    protected function checkRedirectUri(Authorization $authorization)
    {
        $this->checkRedirectUriIfRequired($authorization);

        $redirect_uri = $authorization->getRedirectUri();
        $redirect_uris = $this->getClientRedirectUris($authorization);

        if (empty($redirect_uri) && empty($redirect_uris)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The "redirect_uri" parameter is missing. Add "redirect_uri" parameter or store redirect URIs to your client');
        }
        if (!empty($redirect_uri) && !empty($redirect_uris) && false === Uri::isRedirectUriAllowed($redirect_uri, $redirect_uris)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The specified redirect URI is not valid');
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
    protected function checkRedirectUriIfRequired(Authorization $authorization)
    {
        //If the redirect URI is not set and the configuration requires it, throws an exception
        if (true === $this->getConfiguration()->get('enforce_redirect_uri', false) && null === $authorization->getRedirectUri()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The "redirect_uri" parameter is mandatory');
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
    protected function checkRedirectUriFragment($redirect_uri)
    {
        $uri = parse_url($redirect_uri);
        if (isset($uri['fragment'])) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The "redirect_uri" must not contain fragment');
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
    protected function checkSecuredRedirectUri($redirect_uri)
    {
        if (true === $this->getConfiguration()->get('enforce_secured_redirect_uri', false) && 'https' !== substr($redirect_uri, 0, 5)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The "redirect_uri" must be secured');
        }
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
    protected function getClientRedirectUris(Authorization $authorization)
    {
        $client = $authorization->getClient();
        if (!$client instanceof RegisteredClientInterface) {
            return [];
        }

        $redirect_uris = $client->getRedirectUris();
        /*
         * @see http://tools.ietf.org/html/rfc6749#section-3.1.2.2
         */
        if (!empty($redirect_uris)) {
            return $redirect_uris;
        }

        $this->checkRedirectUriIfRequiredForRegisteredClients();
        $this->checkRedirectUriForNonConfidentialClient($client);
        $this->checkRedirectUriForConfidentialClient($client, $authorization->getResponseType());

        return [];
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function checkRedirectUriIfRequiredForRegisteredClients()
    {
        if (true === $this->getConfiguration()->get('enforce_registered_client_redirect_uris', false)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_CLIENT, 'Registered clients must register at least one redirect URI');
        }
    }

    /**
     * @param \OAuth2\Client\RegisteredClientInterface $client
     * 
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function checkRedirectUriForNonConfidentialClient(RegisteredClientInterface $client)
    {
        if (!$client instanceof ConfidentialClientInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_CLIENT, 'Non-confidential clients must register at least one redirect URI');
        }
    }

    /**
     * @param \OAuth2\Client\RegisteredClientInterface $client
     * @param string                                   $response_type
     * 
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function checkRedirectUriForConfidentialClient(RegisteredClientInterface $client, $response_type)
    {
        if ($client instanceof ConfidentialClientInterface && $response_type === 'token') {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_CLIENT, 'Confidential clients must register at least one redirect URI when using "token" response type');
        }
    }

    /**
     * @param \OAuth2\Endpoint\Authorization $authorization An array with mixed values
     *
     * @see http://tools.ietf.org/html/rfc6749#section-3.1.2
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function checkState(Authorization $authorization)
    {
        if (null === $authorization->getState() && $this->getConfiguration()->get('enforce_state', false)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The "state" parameter is mandatory');
        }
    }

    protected function checkScope(Authorization &$authorization)
    {
        try {
            $scope = $this->getScopeManager()->checkScopePolicy($authorization->getClient(), $authorization->getScope());
            $authorization->setScope($scope);
        } catch (BaseExceptionInterface $e) {
            throw $e;
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, $e->getMessage());
        }

        $availableScopes = $this->getScopeManager()->getAvailableScopes($authorization->getClient());
        if (!$this->getScopeManager()->checkScopes($scope, $availableScopes)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_SCOPE, 'An unsupported scope was requested. Available scopes for the client are ['.implode(',', $availableScopes).']');
        }
    }

    /**
     * @param \OAuth2\Endpoint\Authorization $authorization
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Grant\ResponseTypeSupportInterface[]
     */
    protected function getResponseTypes(Authorization $authorization)
    {
        /*
         * @see http://tools.ietf.org/html/rfc6749#section-3.1.1
         */
        if (null === $authorization->getResponseType()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Invalid "response_type" parameter or parameter is missing');
        }

        $types = explode(' ', $authorization->getResponseType());
        $response_types = [];

        foreach ($types as $type) {
            if (1 < count(array_keys($types, $type))) {
                throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'A response type appears more than once.');
            }
            if (array_key_exists($type, $this->response_types)) {
                $response_types[] = $this->response_types[$type];
            } else {
                throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Response type "'.$type.'" is not supported by this server');
            }

            if (!$authorization->getClient()->isAllowedGrantType($type)) {
                throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::UNAUTHORIZED_CLIENT, 'The response type "'.$authorization->getResponseType().'" is unauthorized for this client.');
            }
        }

        return $response_types;
    }
}
