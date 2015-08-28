<?php

namespace OAuth2\ResourceOwner;

abstract class ResourceOwner implements ResourceOwnerInterface
{
    /**
     * @var string
     */
    private $public_id;
    /**
     * {@inheritdoc}
     */
    public function getPublicId()
    {
        return $this->public_id;
    }

    /**
     * @param string $public_id
     *
     * @return self
     */
    public function setPublicId($public_id)
    {
        $this->public_id = $public_id;

        return $this;
    }
}
