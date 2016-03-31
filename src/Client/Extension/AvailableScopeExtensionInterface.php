<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client\Extension;

/**
 * This extension will help client to override the available scope.
 */
interface AvailableScopeExtensionInterface
{
    /**
     * Get available scopes.
     *
     * @return string[] The available scopes depending on the client and the server.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.3
     */
    public function getAvailableScopes();
}
