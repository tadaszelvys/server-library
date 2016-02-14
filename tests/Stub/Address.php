<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use Assert\Assertion;
use OAuth2\EndUser\Address as Base;


class Address extends Base
{
    /**
     * @param string $formatted
     */
    public function setFormatted($formatted)
    {
        Assertion::string($formatted);
        $this->formatted = $formatted;
    }

    /**
     * @param string $street_address
     */
    public function setStreetAddress($street_address)
    {
        Assertion::string($street_address);
        $this->street_address = $street_address;
    }

    /**
     * @param string $locality
     */
    public function setLocality($locality)
    {
        Assertion::string($locality);
        $this->locality = $locality;
    }

    /**
     * @param string $region
     */
    public function setRegion($region)
    {
        Assertion::string($region);
        $this->region = $region;
    }

    /**
     * @param string $postal_code
     */
    public function setPostalCode($postal_code)
    {
        Assertion::string($postal_code);
        $this->postal_code = $postal_code;
    }

    /**
     * @param string $country
     */
    public function setCountry($country)
    {
        Assertion::string($country);
        $this->country = $country;
    }
}
