<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use Assert\Assertion;
use Base64Url\Base64Url;
use OAuth2\Client\ClientInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;

abstract class RandomStringAccessTokenManager extends AccessTokenManager
{
    /**
     * @var int
     */
    private $min_length;

    /**
     * @var int
     */
    private $max_length;

    /**
     * RandomStringAccessTokenManager constructor.
     *
     * @param int $min_length
     * @param int $max_length
     */
    public function __construct($min_length, $max_length)
    {
        Assertion::integer($min_length);
        Assertion::integer($max_length);
        Assertion::greaterThan($max_length, $min_length);

        $this->min_length = $min_length;
        $this->max_length = $max_length;
    }

    protected function populateAccessToken(AccessTokenInterface &$access_token, ClientInterface $client, ResourceOwnerInterface $resource_owner, RefreshTokenInterface $refresh_token = null, ClientInterface $resource_server = null)
    {
        $length = rand($this->min_length, $this->max_length);
        $token = Base64Url::encode(random_bytes($length));
        $access_token->setToken($token);
    }
}
