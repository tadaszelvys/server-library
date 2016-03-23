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
use Assert\Assertion;

/**
 * This interface is for confidential clients.
 * You can create confidential clients using this interface.
 *
 * @see http://tools.ietf.org/html/rfc6749#section-2.1
 */
class ConfidentialClient extends RegisteredClient implements ConfidentialClientInterface
{
    /**
     * @var int
     */
    private $credentials_expire_at = 0;

    /**
     * @param int $timestamp
     */
    public function setCredentialsExpireAt($timestamp)
    {
        Assertion::integer($timestamp, 'The timestamp must be an integer.');
        Assertion::greaterOrEqualThan($timestamp, 0, 'The timestamp must be a positive value.');

        $this->credentials_expire_at = $timestamp;
    }
    /**
     * {@inheritdoc}
     */
    public function areCredentialsExpired()
    {
        if (0 === $this->credentials_expire_at) {
            return false;
        }
        return time() > $this->credentials_expire_at;
    }
}
