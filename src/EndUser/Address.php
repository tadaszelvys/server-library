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
 * Class Address.
 *
 * @see http://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
 */
class Address implements AddressInterface
{
    /**
     * @var string
     */
    protected $formatted;

    /**
     * @var string
     */
    protected $street_address;

    /**
     * @var string
     */
    protected $locality;

    /**
     * @var string
     */
    protected $region;

    /**
     * @var string
     */
    protected $postal_code;

    /**
     * @var string
     */
    protected $country;

    /**
     * {@inheritdoc}
     */
    public function getFormatted()
    {
        return $this->formatted;
    }

    /**
     * {@inheritdoc}
     */
    public function getStreetAddress()
    {
        return $this->street_address;
    }

    /**
     * {@inheritdoc}
     */
    public function getLocality()
    {
        return $this->locality;
    }

    /**
     * {@inheritdoc}
     */
    public function getRegion()
    {
        return $this->region;
    }

    /**
     * {@inheritdoc}
     */
    public function getPostalCode()
    {
        return $this->postal_code;
    }

    /**
     * {@inheritdoc}
     */
    public function getCountry()
    {
        return $this->country;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        $claims = [
            'formatted'      => 'getFormatted',
            'street_address' => 'getStreetAddress',
            'locality'       => 'getLocality',
            'region'         => 'getRegion',
            'postal_code'    => 'getPostalCode',
            'country'        => 'getCountry',
        ];

        $result = [];
        foreach ($claims as $key => $method) {
            $claim = $this->$method();
            if (!empty($claim)) {
                $result[$key] = $claim;
            }
        }

        return $result;
    }
}
