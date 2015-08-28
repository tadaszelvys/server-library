<?php

namespace OAuth2\Endpoint;

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Client\ConfidentialClientInterface;
use OAuth2\Client\RegisteredClientInterface;
use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Grant\ResponseTypeSupportInterface;
use Symfony\Component\HttpFoundation\Response;
use Util\Uri;

class AuthorizationEndpoint implements AuthorizationEndpointInterface
{
    const RESPONSE_MODE_QUERY = 'query';
    const RESPONSE_MODE_FRAGMENT = 'fragment';

    use HasConfiguration;
    use HasExceptionManager;
    use HasScopeManager;

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
    public function authorize(AuthorizationInterface $authorization)
    {
        $redirect_uri = $this->checkRedirectUri($authorization);
        $this->checkRedirectUriFragment($redirect_uri);
        $this->checkSecuredRedirectUri($redirect_uri);

        $this->checkState($authorization);
        $this->checkScope($authorization);

        //Open ID Connect introduce the possibility of combination of response type (id_token+code...)
        //This library must handle these combinations or must be designed to support Open ID Connect in the future
        $type = $this->getResponseType($authorization);
        $response_mode = $type->getResponseMode();

        if ($authorization->isAuthorized() === false) {
            $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::REDIRECT, ExceptionManagerInterface::ACCESS_DENIED, 'The resource owner denied access to your client', ['transport_mode' => $response_mode, 'redirect_uri' => $authorization->getRedirectUri(), 'state' => $authorization->getState()]);

            return $exception->getHttpResponse();
        }

        $result = $type->grantAuthorization($authorization);

        switch ($response_mode) {
            case self::RESPONSE_MODE_QUERY:
            case self::RESPONSE_MODE_FRAGMENT:
                $result = [$response_mode => $result];
                break;
            default:
                throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, 'invalid_response_mode', sprintf('The response mode "%s" is not supported.', $response_mode));
        }

        return new Response('', 302, [
            'Location' => Uri::buildUri($redirect_uri, $result),
        ]);
    }

    /**
     * @param \OAuth2\Endpoint\AuthorizationInterface $authorization An array with mixed values
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    protected function checkRedirectUri(AuthorizationInterface $authorization)
    {
        //If the redirect URI is not set and the configuration requires it, throws an exception
        if (true === $this->getConfiguration()->get('enforce_redirect_uri', false) && is_null($authorization->getRedirectUri())) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The "redirect_uri" parameter is mandatory');
        }

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
     * @param \OAuth2\Endpoint\AuthorizationInterface $authorization An array with mixed values
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return array
     */
    protected function getClientRedirectUris(AuthorizationInterface $authorization)
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

        if (true === $this->getConfiguration()->get('enforce_registered_client_redirect_uris', false)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_CLIENT, 'Registered clients must register at least one redirect URI');
        }

        if (!$authorization->getClient() instanceof ConfidentialClientInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_CLIENT, 'Non-confidential clients must register at least one redirect URI');
        }

        if ($authorization->getClient() instanceof ConfidentialClientInterface && $authorization->getResponseType() === 'token') {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_CLIENT, 'Confidential clients must register at least one redirect URI when using "token" response type');
        }

        return [];
    }

    /**
     * @param \OAuth2\Endpoint\AuthorizationInterface $authorization An array with mixed values
     *
     * @see http://tools.ietf.org/html/rfc6749#section-3.1.2
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function checkState(AuthorizationInterface $authorization)
    {
        if (is_null($authorization->getState()) && $this->getConfiguration()->get('enforce_state', false)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The "state" parameter is mandatory');
        }
    }

    protected function checkScope(AuthorizationInterface &$authorization)
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

    protected function getResponseType(AuthorizationInterface $authorization)
    {
        /*
         * @see http://tools.ietf.org/html/rfc6749#section-3.1.1
         */
        if (is_null($authorization->getResponseType())) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Invalid "response_type" parameter or parameter is missing');
        }

        $type = $authorization->getResponseType();
        if (array_key_exists($type, $this->response_types)) {
            $type = $this->response_types[$type];
        } else {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Response type "'.$authorization->getResponseType().'" is not supported by this server');
        }

        if (!$authorization->getClient()->isAllowedGrantType($authorization->getResponseType())) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::UNAUTHORIZED_CLIENT, 'The response type "'.$authorization->getResponseType().'" is unauthorized for this client.');
        }

        return $type;
    }
}
