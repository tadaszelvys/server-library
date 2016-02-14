<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\EndUser;

/**
 * Class Address
 *
 * @see http://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
 */
interface AddressInterface extends \JsonSerializable
{
    /**
     * @return string
     */
    public function getFormatted();

    /**
     * @return string
     */
    public function getStreetAddress();

    /**
     * @return string
     */
    public function getLocality();

    /**
     * @return string
     */
    public function getRegion();

    /**
     * @return string
     */
    public function getPostalCode();

    /**
     * @return string
     */
    public function getCountry();
}
