<?php

namespace OAuth2\ResourceOwner;

class ResourceOwner implements ResourceOwnerInterface
{
    /**
     * @var string
     */
    protected $public_id;

    /**
     * @var string
     */
    protected $type;

    public function __construct()
    {
        $this->setPublicId(base_convert(sha1(uniqid(mt_rand(), true)), 16, 36));
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicId()
    {
        return $this->public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function setPublicId($public_id)
    {
        $this->public_id = $public_id;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * {@inheritdoc}
     */
    public function setType($type)
    {
        $this->type = $type;

        return $this;
    }
}
