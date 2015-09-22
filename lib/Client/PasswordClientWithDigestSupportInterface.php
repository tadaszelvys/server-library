<?php

namespace OAuth2\Client;

interface PasswordClientWithDigestSupportInterface extends PasswordClientInterface
{
    /**
     * @return string
     */
    public function getA1Hash();

    /**
     * @param string $ha1
     *
     * @return self
     */
    public function setA1Hash($ha1);
}
