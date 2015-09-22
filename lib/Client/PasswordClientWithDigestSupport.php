<?php

namespace OAuth2\Client;

class PasswordClientWithDigestSupport extends PasswordClient implements PasswordClientWithDigestSupportInterface
{
    /**
     * @var string
     */
    private $ha1;

    /**
     * {@inheritdoc}
     */
    public function getA1Hash()
    {
        return $this->ha1;
    }

    /**
     * {@inheritdoc}
     */
    public function setA1Hash($ha1)
    {
        $this->ha1 = $ha1;

        return $this;
    }
}
