<?php

namespace OAuth2\Grant;

interface GrantTypeResponseInterface
{
    /**
     * The scope requested.
     *
     * @return string[]|string|null
     */
    public function getRequestedScope();

    /**
     * The scope available.
     *
     * @return string[]|string|null
     */
    public function getAvailableScope();

    /**
     * The resource owner associated with the access token.
     * It could be a user (for Implicit grant type or Resource Owner Password Credentials grant type) or a client (for Client Credentials grant type).
     *
     * @return string
     */
    public function getResourceOwnerPublicId();

    /**
     * @return bool If true, a refresh token is requested
     */
    public function isRefreshTokenIssued();

    /**
     * @return string[]|string|null If not null, a refresh token will be issued using the scope returned
     */
    public function getRefreshTokenScope();

    /**
     * @return \OAuth2\Token\RefreshTokenInterface|null If not null, the refresh token will be revoked
     */
    public function getRefreshTokenRevoked();
}
