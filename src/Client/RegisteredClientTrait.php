<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
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
trait RegisteredClientTrait
{
    /**
     * @var string[]
     */
    protected $redirect_uris = [];

    /**
     * @var string|null
     */
    protected $sector_identifier_uri = null;

    /**
     * {@inheritdoc}
     */
    public function getSectorIdentifierUri()
    {
        return $this->sector_identifier_uri;
    }

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
    public function hasRedirectUri($redirect_uri)
    {
        return in_array($redirect_uri, $this->redirect_uris);
    }
}
