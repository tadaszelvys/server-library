<?php

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasIdTokenManager;
use OAuth2\Endpoint\Authorization;
use OAuth2\Token\IdTokenManagerInterface;

final class IdTokenResponseType implements ResponseTypeSupportInterface
{
    use HasIdTokenManager;

    /**
     * IdTokenResponseType constructor.
     *
     * @param \OAuth2\Token\IdTokenManagerInterface $id_token_manager
     */
    public function __construct(IdTokenManagerInterface $id_token_manager)
    {
        $this->setIdTokenManager($id_token_manager);
    }

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
    public function grantAuthorization(Authorization $authorization)
    {
        $id_token = $this->getIdTokenManager()->createIdToken($authorization->getClient(), $authorization->getEndUser(), $authorization->getScope());

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
