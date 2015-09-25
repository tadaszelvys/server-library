<?php

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasIdTokenManager;
use OAuth2\Endpoint\AuthorizationInterface;

class IdTokenResponseType implements ResponseTypeSupportInterface
{
    use HasIdTokenManager;

    /**
     * {@inheritdoc}
     */
    public function getResponseType()
    {
        return 'id_token';
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode()
    {
        return 'fragment';
    }

    /**
     * {@inheritdoc}
     */
    public function grantAuthorization(AuthorizationInterface $authorization)
    {
        $id_token = $this->getIdTokenManager()->createIdToken($authorization->getClient(), $authorization->getScope(), $authorization->getResourceOwner());

        $params = [
            'id_token' => $id_token,
        ];
        $state = $authorization->getState();
        if (!empty($state)) {
            $params['state'] = $state;
        }

        return $params;
    }
}
