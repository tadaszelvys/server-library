<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIDConnect;


trait HasIdTokenManager
{
    /**
     * @var \OAuth2\OpenIDConnect\IdTokenManagerInterface
     */
    private $id_token_manager;

    /**
     * @return \OAuth2\OpenIDConnect\IdTokenManagerInterface
     */
    protected function getIdTokenManager()
    {
        return $this->id_token_manager;
    }

    /**
     * @param \OAuth2\OpenIDConnect\IdTokenManagerInterface $id_token_manager
     */
    private function setIdTokenManager(IdTokenManagerInterface $id_token_manager)
    {
        $this->id_token_manager = $id_token_manager;
    }
}
