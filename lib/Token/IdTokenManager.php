<?php

namespace OAuth2\Token;

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasJWTFactory;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\TokenLifetimeExtensionInterface;
use OAuth2\EndUser\EndUserInterface;

class  IdTokenManager implements IdTokenManagerInterface
{
    use HasConfiguration;
    use HasJWTFactory;

    /**
     * {@inheritdoc}
     */
    public function createIdToken(ClientInterface $client, EndUserInterface $end_user, array $scope = [], RefreshTokenInterface $refresh_token = null)
    {
        $claims = [
            'iss' => '',
            'sub' => $end_user->getPublicId(),
            'aud' => $client->getPublicId(),
            'exp' => time() + $this->getLifetime($client),
            'iat' => time(),
            'auth_time' => $end_user->getLastLoginAt(),
            /*'nonce',
            'acr',
            'amr',
            'azp',*/
        ];
        $this->getJWTFactory()->
    }

    public function revokeIdToken(IdTokenInterface $token)
    {

    }

    public function getIdToken($access_token)
    {

    }

    public function isIdTokenValid(IdTokenInterface $token)
    {

    }

    /**
     * @param \OAuth2\Client\ClientInterface $client Client
     *
     * @return int
     */
    protected function getLifetime(ClientInterface $client)
    {
        $lifetime = $this->getConfiguration()->get('id_token_token_lifetime', 3600);
        if ($client instanceof TokenLifetimeExtensionInterface && is_int($_lifetime = $client->getTokenLifetime('id_token'))) {
            return $_lifetime;
        }

        return $lifetime;
    }
}
