<?php

namespace OAuth2\ResourceOwner;

use Base64Url\Base64Url;

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
        $this->setPublicId(trim(chunk_split(Base64Url::encode(uniqid(mt_rand(), true)), 16, '-'), '-'));
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
