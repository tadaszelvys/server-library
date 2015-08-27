<?php

namespace OAuth2\Endpoint;

use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasAccessTokenType;
use OAuth2\Behaviour\HasClientManagerSupervisor;
use OAuth2\Behaviour\HasEndUserManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasRefreshTokenManager;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Token\RefreshTokenInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Util\RequestBody;
use OAuth2\Grant\GrantTypeSupportInterface;

class TokenEndpoint implements TokenEndpointInterface
{
    use HasEndUserManager;
    use HasAccessTokenType;
    use HasScopeManager;
    use HasExceptionManager;
    use HasClientManagerSupervisor;
    use HasAccessTokenManager;
    use HasRefreshTokenManager;

    /**
     * @var \OAuth2\Grant\GrantTypeSupportInterface[]
     */
    protected $grant_types = array();

    /**
     * @param \OAuth2\Grant\GrantTypeSupportInterface $grant_type
     *
     * @return self
     */
    public function addGrantType(GrantTypeSupportInterface $grant_type)
    {
        $type = $grant_type->getGrantType();
        if (array_key_exists($type, $this->grant_types)) {
            return $this;
        }
        $this->grant_types[$type] = $grant_type;

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     * @throws \OAuth2\Exception\NotImplementedExceptionInterface
     */
    public function getAccessToken(Request $request)
    {
        if (!$request->isSecure()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The request must be secured.');
        }

        if (Request::METHOD_POST !== $request->getMethod()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Method must be POST.');
        }

        if (is_null(RequestBody::getParameter($request, 'grant_type'))) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The parameter "grant_type" parameter is missing.');
        }

        return $this->handleRequest($request);
    }

    protected function handleRequest(Request $request)
    {
        $client = $this->getClientManagerSupervisor()->findClient($request);
        $grant_type = RequestBody::getParameter($request, 'grant_type');
        $type = $this->getGrantType($grant_type);
        $this->checkGrantType($client, $grant_type);
        $grant_type_response = $type->grantAccessToken($request, $client);

        $result = array(
            'requested_scope' => $grant_type_response->getRequestedScope() ?: $this->getScopeManager()->getDefaultScopes($client),
            'available_scope' => $grant_type_response->getAvailableScope() ?: $this->getScopeManager()->getAvailableScopes($client),
            'resource_owner_public_id' => $grant_type_response->getResourceOwnerPublicid(),
            'refresh_token' => array(
                'issued' => $grant_type_response->isRefreshTokenIssued(),
                'scope' => $grant_type_response->getRefreshTokenScope(),
                'used' => $grant_type_response->getRefreshTokenRevoked(),
            ),
        );

        foreach (array('requested_scope', 'available_scope') as $key) {
            $result[$key] = $this->getScopeManager()->convertToScope($result[$key]);
        }

        //Modify the scope according to the scope policy
        $result['requested_scope'] = $this->getScopeManager()->checkScopePolicy($client, $result['requested_scope'], $request);

        //Check if scope requested are within the available scope
        if (!$this->getScopeManager()->checkScopes($result['requested_scope'], $result['available_scope'])) {
            throw $this->getExceptionManager()->getException('BadRequest', 'invalid_scope', 'An unsupported scope was requested. Available scopes are ['.implode(',', $result['available_scope']).']');
        }

        //Create and return access token (with refresh token if asked) as an array
        $token = $this->createAccessToken($client, $result);

        $prepared = $this->getAccessTokenType()->prepareAccessToken($token);

        return new Response(json_encode($prepared), 200, array(
            'Content-Type' => 'application/json',
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ));
    }

    protected function createAccessToken(ClientInterface $client, array $values)
    {
        $refresh_token = null;
        $resource_owner = $this->getResourceOwner($values['resource_owner_public_id']);
        if (!is_null($this->getRefreshTokenManager())) {
            if (true === $values['refresh_token']['issued']) {
                $values['refresh_token']['scope'] = $this->getScopeManager()->convertToScope($values['refresh_token']['scope']);
                $refresh_token = $this->getRefreshTokenManager()->createRefreshToken($client, $values['refresh_token']['scope'], $resource_owner);
            }
            if ($values['refresh_token']['used'] instanceof RefreshTokenInterface) {
                $this->getRefreshTokenManager()->markRefreshTokenAsUsed($values['refresh_token']['used']);
            }
        }

        $access_token = $this->getAccessTokenManager()->createAccessToken($client, $values['requested_scope'], $resource_owner, $refresh_token);

        return $access_token;
    }

    /**
     * @param $grant_type
     *
     * @return \OAuth2\Grant\GrantTypeSupportInterface
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function getGrantType($grant_type)
    {
        if (array_key_exists($grant_type, $this->grant_types)) {
            return $this->grant_types[$grant_type];
        }
        throw $this->getExceptionManager()->getException(ExceptionManagerInterface::NOT_IMPLEMENTED, ExceptionManagerInterface::UNSUPPORTED_GRANT_TYPE, 'The grant type "'.$grant_type.'" is not supported by this server');
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param                                $grant_type
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function checkGrantType(ClientInterface $client, $grant_type)
    {
        if (!$client->isAllowedGrantType($grant_type)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::UNAUTHORIZED_CLIENT, 'The grant type "'.$grant_type.'" is unauthorized for this client_id');
        }
    }

    /**
     * @param string $resource_owner_public_id
     *
     * @return \OAuth2\ResourceOwner\ResourceOwnerInterface
     */
    protected function getResourceOwner($resource_owner_public_id)
    {
        $client = $this->getClientManagerSupervisor()->getClient($resource_owner_public_id);
        if (!is_null($client)) {
            return $client;
        }
        $end_user = $this->getEndUserManager()->getEndUser($resource_owner_public_id);

        return is_null($end_user) ? null : $end_user;
    }
}
