<?php

namespace OAuth2\Client;

/**
 * This interface is for registered clients.
 * These clients have an ID and the server can get the client details.
 *
 * @see http://tools.ietf.org/html/rfc6749#section-2.1
 */
interface RegisteredClientInterface extends ClientInterface
{
    /**
     * Get the redirect URIs where the authorization server directs the resource owner.
     * URIs must be absolute.
     *
     * @return string[] Redirect URIs allowed by the client. If client is 'public' or if 'confidential' clients utilize the implicit grant type, this function MUST return at least on entry
     *
     * @see http://tools.ietf.org/html/rfc6749#section-3.1.2
     * @see http://tools.ietf.org/html/rfc6749#section-3.1.2.2
     */
    public function getRedirectUris();

    /**
     * @param string[] $redirect_uris
     *
     * @return self
     */
    public function setRedirectUris(array $redirect_uris);

    /**
     * @param string $redirect_uri
     *
     * @return bool
     */
    public function hasRedirectUri($redirect_uri);

    /**
     * @param string $redirect_uri
     *
     * @return self
     */
    public function addRedirectUri($redirect_uri);

    /**
     * @param string $redirect_uri
     *
     * @return self
     */
    public function removeRedirectUri($redirect_uri);
}
