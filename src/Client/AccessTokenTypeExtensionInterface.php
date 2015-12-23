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
 * This extension allow client to set the preferred token type.
 * If set and if available, the token type must be used instead of the default one.
 */
interface AccessTokenTypeExtensionInterface
{
    /**
     * @return null|string
     */
    public function getPreferredTokenType();
}
