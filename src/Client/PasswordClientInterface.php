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

interface PasswordClientInterface extends ConfidentialClientInterface
{
    /**
     * @return string
     */
    public function getSecret();

    /**
     * @param string $secret
     */
    public function setSecret($secret);

    /**
     * @return string
     */
    public function getSalt();

    /**
     * @param string $salt
     */
    public function setSalt($salt);

    /**
     * @return string
     */
    public function getPlaintextSecret();

    /**
     * @param string $plaintext_secret
     */
    public function setPlaintextSecret($plaintext_secret);

    /**
     */
    public function clearCredentials();
}
