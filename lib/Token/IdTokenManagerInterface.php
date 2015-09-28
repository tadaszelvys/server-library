<?php

namespace OAuth2\Token;

use OAuth2\Client\ClientInterface;
use OAuth2\EndUser\EndUserInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;

interface IdTokenManagerInterface
{
    /**
     * @param \OAuth2\Client\ClientInterface                    $client         The client associated with this access token.
     * @param \OAuth2\EndUser\EndUserInterface                  $end_user       Resource owner associated with the access token.
     * @param string[]                                          $scope          (optional) Scopes of the access token.
     * @param \OAuth2\Token\RefreshTokenInterface|null          $refresh_token  (optional) Refresh token associated with the access token.
     *
     * @return \OAuth2\Token\AccessTokenInterface
     */
    public function createIdToken(ClientInterface $client, EndUserInterface $end_user, array $scope = [], RefreshTokenInterface $refresh_token = null);

    /**
     * @param \OAuth2\Token\IdTokenInterface $token The ID token to revoke
     *
     * @return self
     */
    public function revokeIdToken(IdTokenInterface $token);

    /**
     * This function verifies the request and validate or not the access token.
     * MUST return null if the access token is not valid (expired, revoked...).
     *
     * @param string $access_token The access token
     *
     * @return \OAuth2\Token\IdTokenInterface|null Return the access token or null if the argument is not a valid access token
     */
    public function getIdToken($access_token);

    /**
     * @param \OAuth2\Token\IdTokenInterface $token
     *
     * @return bool True if the access token is valid, else false
     */
    public function isIdTokenValid(IdTokenInterface $token);
}
