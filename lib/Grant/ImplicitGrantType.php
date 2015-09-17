<?php

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasAccessTokenTypeManager;
use OAuth2\Endpoint\AuthorizationEndpoint;
use OAuth2\Endpoint\AuthorizationInterface;

class ImplicitGrantType implements ResponseTypeSupportInterface
{
    use HasAccessTokenTypeManager;
    use HasAccessTokenManager;

    /**
     * {@inheritdoc}
     */
    public function getResponseType()
    {
        return 'token';
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode()
    {
        return AuthorizationEndpoint::RESPONSE_MODE_FRAGMENT;
    }

    /**
     * {@inheritdoc}
     */
    public function grantAuthorization(AuthorizationInterface $authorization)
    {
        $token = $this->getAccessTokenManager()->createAccessToken($authorization->getClient(), $authorization->getScope(), $authorization->getResourceOwner());
        $params = $this->getAccessTokenTypeManager()->getDefaultAccessTokenType()->prepareAccessToken($token);

        $state = $authorization->getState();
        if (!empty($state)) {
            $params['state'] = $state;
        }

        return $params;
    }
}
