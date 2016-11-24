<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect\UserInfo;


use OAuth2\Model\AccessToken\AccessToken;

interface UserInfoEndpointInterface
{
    /**
     * @param AccessToken $access_token
     *
     * @return string|array
     */
    public function handle(AccessToken $access_token);

    /**
     * @return string[]
     */
    public function getSupportedSignatureAlgorithms();

    /**
     * @return string[]
     */
    public function getSupportedKeyEncryptionAlgorithms();

    /**
     * @return string[]
     */
    public function getSupportedContentEncryptionAlgorithms();
}
