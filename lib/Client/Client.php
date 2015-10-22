<?php

namespace OAuth2\Client;

use OAuth2\ResourceOwner\ResourceOwner;

class Client extends ResourceOwner implements ClientInterface
{
    /**
     * @var string[]
     */
    protected $grant_types = [];

    /**
     * {@inheritdoc}
     */
    public function isAllowedGrantType($grant_type)
    {
        return in_array($grant_type, $this->grant_types);
    }

    /**
     * {@inheritdoc}
     */
    public function getAllowedGrantTypes()
    {
        return $this->grant_types;
    }

    /**
     * {@inheritdoc}
     */
    public function addAllowedGrantType($grant_type)
    {
        if (!$this->isAllowedGrantType($grant_type)) {
            $this->grant_types[] = $grant_type;
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function setAllowedGrantTypes(array $grant_types)
    {
        $this->grant_types = $grant_types;

        return $this;
    }

    public function removeAllowedGrantType($grant_type)
    {
        if ($this->isAllowedGrantType($grant_type)) {
            unset($this->grant_types[$grant_type]);
        }

        return $this;
    }
}
