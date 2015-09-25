<?php

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Endpoint\AuthorizationInterface;
use OAuth2\Token\AccessTokenInterface;

/**
 * This response type has been introduced by OpenID Connect
 * It creates an access token, but does not returns anything.
 *
 * At this time, this response type is not complete, because it always redirect the client.
 * But if no redirect URI is specified, no redirection should occurred as per OpenID Connect specification.
 *
 * @see http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none
 */
class NoneResponseType implements ResponseTypeSupportInterface
{
    use HasAccessTokenManager;

    /**
     * {@inheritdoc}
     */
    public function getResponseType()
    {
        return 'none';
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode()
    {
        return 'query';
    }

    /**
     * {@inheritdoc}
     */
    public function grantAuthorization(AuthorizationInterface $authorization)
    {
        $token = $this->getAccessTokenManager()->createAccessToken($authorization->getClient(), $authorization->getScope(), $authorization->getResourceOwner());
        $this->finishAccessTokenCreation($token);

        $params = [];
        $state = $authorization->getState();
        if (!empty($state)) {
            $params['state'] = $state;
        }

        return $params;
    }

    protected function finishAccessTokenCreation(AccessTokenInterface $access_token)
    {
    }
}
