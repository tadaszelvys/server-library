<?php

namespace OAuth2\Client;

/**
 * This interface is for registered clients.
 * These clients have an ID and the server can get the client details.
 *
 * @see http://tools.ietf.org/html/rfc6749#section-2.1
 */
class RegisteredClient extends Client implements RegisteredClientInterface
{
    /**
     * @var string[]
     */
    protected $redirect_uris = [];
    /**
     * {@inheritdoc}
     */
    public function getRedirectUris()
    {
        return $this->redirect_uris;
    }

    /**
     * @param string[] $redirect_uris
     *
     * @return self
     */
    public function setRedirectUris(array $redirect_uris)
    {
        $this->redirect_uris = $redirect_uris;

        return $this;
    }
}
