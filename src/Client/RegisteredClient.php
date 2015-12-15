<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

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
     * {@inheritdoc}
     */
    public function setRedirectUris(array $redirect_uris)
    {
        $this->redirect_uris = $redirect_uris;
    }

    /**
     * {@inheritdoc}
     */
    public function hasRedirectUri($redirect_uri)
    {
        return in_array($redirect_uri, $this->redirect_uris);
    }

    public function addRedirectUri($redirect_uri)
    {
        if (!$this->hasRedirectUri($redirect_uri)) {
            $this->redirect_uris[] = $redirect_uri;
        }
    }

    public function removeRedirectUri($redirect_uri)
    {
        $key = array_search($redirect_uri, $this->redirect_uris);
        if (false !== $key) {
            unset($this->redirect_uris[$key]);
        }
    }
}
