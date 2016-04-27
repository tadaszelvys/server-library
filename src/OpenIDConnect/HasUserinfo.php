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

trait HasUserinfo
{
    /**
     * @var \OAuth2\OpenIDConnect\UserInfoInterface
     */
    private $userinfo;

    /**
     * @return \OAuth2\OpenIDConnect\UserInfoInterface
     */
    protected function getUserinfo()
    {
        return $this->userinfo;
    }

    /**
     * @param \OAuth2\OpenIDConnect\UserInfoInterface $userinfo
     */
    private function setUserinfo(UserInfoInterface $userinfo)
    {
        $this->userinfo = $userinfo;
    }
}
