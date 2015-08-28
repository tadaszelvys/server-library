<?php

namespace OAuth2\Token;

interface TokenInterface
{
    /**
     * @return string The public ID of the client associated with the token
     */
    public function getClientPublicId();

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
     * The resource owner associated to the token.
     *
     * @return string|null The public ID of the resource owner associated with the token
     */
    public function getResourceOwnerPublicId();
}
