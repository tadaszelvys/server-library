<?php

namespace OAuth2\Token;

interface TokenInterface
{
    /**
     * @return string
     */
    public function getToken();

    /**
     * @param string $token
     *
     * @return self
     */
    public function setToken($token);

    /**
     * @return string The public ID of the client associated with the token
     */
    public function getClientPublicId();

    /**
     * @param string $client_public_id
     *
     * @return self
     */
    public function setClientPublicId($client_public_id);

    /**
     * @return int
     */
    public function getExpiresAt();

    /**
     * @param int $expires_at
     *
     * @return self
     */
    public function setExpiresAt($expires_at);

    /**
     * @return bool true if the token has expired
     */
    public function hasExpired();

    /**
     * @return int Seconds before the token expiration date
     */
    public function getExpiresIn();

    /**
     * The scopes associated with the token.
     *
     * @return string[] An array of scope
     */
    public function getScope();

    /**
     * @param array $scope
     *
     * @return self
     */
    public function setScope(array $scope);

    /**
     * The resource owner associated to the token.
     *
     * @return string|null The public ID of the resource owner associated with the token
     */
    public function getResourceOwnerPublicId();

    /**
     * @param string|null $resource_owner_public_id
     *
     * @return self
     */
    public function setResourceOwnerPublicId($resource_owner_public_id);
}
