<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\ResourceOwner;

use Base64Url\Base64Url;

trait ResourceOwnerTrait
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
    }
}
