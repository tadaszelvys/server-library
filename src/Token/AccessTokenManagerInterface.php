<?php

namespace OAuth2\Token;

use OAuth2\Client\ClientInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;

interface AccessTokenManagerInterface
{
    /**
     * Stores the supplied access token values to storage.
     *
     * We need to store access token data as we create and verify tokens.
     *
     * @param \OAuth2\Client\ClientInterface               $client         The client associated with this access token.
     * @param \OAuth2\ResourceOwner\ResourceOwnerInterface $resource_owner Resource owner associated with the access token.
     * @param string[]                                     $scope          (optional) Scopes of the access token.
     * @param \OAuth2\Token\RefreshTokenInterface|null     $refresh_token  (optional) Refresh token associated with the access token.
     *
     * @return \OAuth2\Token\AccessTokenInterface
     */
    public function createAccessToken(ClientInterface $client, ResourceOwnerInterface $resource_owner, array $scope = [], RefreshTokenInterface $refresh_token = null);

    /**
     * This function revoke an access token.
     *
     * @param \OAuth2\Token\AccessTokenInterface $token The access token to revoke
     */
    public function revokeAccessToken(AccessTokenInterface $token);

    /**
     * This function verifies the request and validate or not the access token.
     * MUST return null if the access token is not valid (expired, revoked...).
     *
     * @param string $access_token The access token
     *
     * @return \OAuth2\Token\AccessTokenInterface|null Return the access token or null if the argument is not a valid access token
     */
    public function getAccessToken($access_token);

    /**
     * @param \OAuth2\Token\AccessTokenInterface $token
     *
     * @return bool True if the access token is valid, else false
     */
    public function isAccessTokenValid(AccessTokenInterface $token);
}
