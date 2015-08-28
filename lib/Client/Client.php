<?php

namespace OAuth2\Client;

use OAuth2\ResourceOwner\ResourceOwner;

abstract class Client extends ResourceOwner implements ClientInterface
{
    /**
     * @var string[]
     */
    private $grant_types = [];
    /**
     * {@inheritdoc}
     */
    public function isAllowedGrantType($grant_type)
    {
        return in_array($grant_type, $this->grant_types);
    }

    /**
     * @return string[]
     */
    public function getAllowedGrantTypes()
    {
        return $this->grant_types;
    }

    /**
     * @param string[] $grant_types
     *
     * @return self
     */
    public function setAllowedGrantTypes(array $grant_types)
    {
        $this->grant_types = $grant_types;

        return $this;
    }
}
