<?php

namespace OAuth2\Grant;

interface GrantTypeResponseInterface
{
    /**
     * @param string $key
     *
     * @return mixed
     */
    public function getAdditionalData($key);

    /**
     * @param string $key
     * @param mixed  $data
     *
     * @return self
     */
    public function setAdditionalData($key, $data);

    /**
     * The scope requested.
     *
     * @return string[]|string|null
     */
    public function getRequestedScope();

    /**
     * @param string[]|string|null $requested_scope
     *
     * @return self
     */
    public function setRequestedScope($requested_scope = null);

    /**
     * The scope available.
     *
     * @return string[]|string|null
     */
    public function getAvailableScope();

    /**
     * @param string[]|string|null $available_scope
     *
     * @return self
     */
    public function setAvailableScope($available_scope = null);

    /**
     * @return string
     */
    public function getClientPublicId();

    /**
     * @param string $client_owner_public_id
     *
     * @return self
     */
    public function setClientPublicId($client_owner_public_id);

    /**
     * The resource owner associated with the access token.
     * It could be a user (for Implicit grant type or Resource Owner Password Credentials grant type) or a client_public_id (for Client Credentials grant type).
     *
     * @return string|null
     */
    public function getResourceOwnerPublicId();

    /**
     * @param string|null $resource_owner_public_id
     *
     * @return self
     */
    public function setResourceOwnerPublicId($resource_owner_public_id = null);

    /**
     * @return bool If true, a refresh token is requested
     */
    public function isRefreshTokenIssued();

    /**
     * @param bool $issue_refresh_token
     *
     * @return self
     */
    public function setRefreshTokenIssued($issue_refresh_token = false);

    /**
     * @return string[]|string|null If not null, a refresh token will be issued using the scope returned
     */
    public function getRefreshTokenScope();

    /**
     * @param string[]|string[]|string|null $refresh_token_scope
     *
     * @return self
     */
    public function setRefreshTokenScope($refresh_token_scope = null);

    /**
     * @return string|null If not null, the refresh token will be revoked
     */
    public function getRefreshTokenRevoked();

    /**
     * @param string|null $revoke_refresh_token
     *
     * @return self
     */
    public function setRefreshTokenRevoked($revoke_refresh_token = null);
}
