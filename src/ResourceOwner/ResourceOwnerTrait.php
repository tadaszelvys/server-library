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
     * ResourceOwnerTrait constructor.
     */
    public function __construct()
    {
        $this->setPublicId(Base64Url::encode(random_bytes(50)));
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
}
