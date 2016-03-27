<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\User;

use OAuth2\Token\AccessTokenInterface;

trait UserTrait
{
    /**
     * @var int|null
     */
    protected $last_login_at = null;

    /**
     * @var string|null
     */
    protected $display_name = null;

    /**
     * @var string|null
     */
    protected $given_name = null;

    /**
     * @var string|null
     */
    protected $middle_name = null;

    /**
     * @var string|null
     */
    protected $family_name = null;

    /**
     * @var string|null
     */
    protected $nickname = null;

    /**
     * @var string|null
     */
    protected $preferred_username = null;

    /**
     * @var string|null
     */
    protected $profile = null;

    /**
     * @var string|null
     */
    protected $picture = null;

    /**
     * @var string|null
     */
    protected $website = null;

    /**
     * @var string|null
     */
    protected $gender = null;

    /**
     * @var string|null
     */
    protected $birthdate = null;

    /**
     * @var string|null
     */
    protected $zone_info = null;

    /**
     * @var string|null
     */
    protected $locale = null;

    /**
     * @var int|null
     */
    protected $updated_at = null;

    /**
     * @var string|null
     */
    protected $email = null;

    /**
     * @var bool|null
     */
    protected $email_verified = null;

    /**
     * @var string|null
     */
    protected $phone_number = null;

    /**
     * @var bool|null
     */
    protected $phone_number_verified = null;

    /**
     * @var \OAuth2\User\AddressInterface|null
     */
    protected $address = null;

    /**
     * @var string[]
     */
    protected $authentication_methods_references = [];

    /**
     * @var string[]
     */
    protected $authentication_context_class_reference = [];

    /**
     * @return string
     */
    abstract public function getPublicId();

    /**
     * {@inheritdoc}
     */
    public function getLastLoginAt()
    {
        return $this->last_login_at;
    }

    /**
     * @return array
     */
    protected function getSupportedUserInfoScopes()
    {
        return [
            'profile' => 'getProfileInfo',
            'email'   => 'getEmailInfo',
            'phone'   => 'getPhoneInfo',
            'address' => 'getAddressInfo',
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function getUserInfo(AccessTokenInterface $access_token)
    {
        $claims = [];
        $supported_scopes = $this->getSupportedUserInfoScopes();
        foreach ($supported_scopes as $scope => $method) {
            if ($access_token->hasScope($scope)) {
                $claims = array_merge(
                    $claims,
                    $this->$method()
                );
            }
        }

        foreach ($claims as $key => $value) {
            if (null === $value) {
                unset($claims[$key]);
            }
        }

        return $claims;
    }

    /**
     * @return array
     */
    protected function getProfileInfo()
    {
        return [
            'sub'                => $this->getPublicId(),
            'name'               => $this->getDisplayName(),
            'given_name'         => $this->getGivenName(),
            'middle_name'        => $this->getMiddleName(),
            'family_name'        => $this->getFamilyName(),
            'nickname'           => $this->getNickname(),
            'preferred_username' => $this->getPreferredUsername(),
            'profile'            => $this->getProfile(),
            'picture'            => $this->getPicture(),
            'website'            => $this->getWebsite(),
            'gender'             => $this->getGender(),
            'birthdate'          => $this->getBirthdate(),
            'zoneinfo'           => $this->getZoneInfo(),
            'locale'             => $this->getLocale(),
            'updated_at'         => $this->getUpdatedAt(),
        ];
    }

    /**
     * @return array
     */
    protected function getEmailInfo()
    {
        return [
            'email'          => $this->getEmail(),
            'email_verified' => $this->isEmailVerified(),
        ];
    }

    /**
     * @return array
     */
    protected function getPhoneInfo()
    {
        return [
            'phone_number'          => $this->getPhoneNumber(),
            'phone_number_verified' => $this->isPhoneNumberVerified(),
        ];
    }

    /**
     * @return array
     */
    protected function getAddressInfo()
    {
        return [
            'address' => $this->getAddress(),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function getDisplayName()
    {
        if (null !== $this->display_name) {
            return $this->display_name;
        }
        $name = implode(' ', [
            $this->getGivenName(),
            $this->getMiddleName(),
            $this->getFamilyName(),
        ]);

        return empty(trim($name, ' ')) ? null : $name;
    }

    /**
     * {@inheritdoc}
     */
    public function getGivenName()
    {
        return $this->given_name;
    }

    /**
     * {@inheritdoc}
     */
    public function getMiddleName()
    {
        return $this->middle_name;
    }

    /**
     * {@inheritdoc}
     */
    public function getFamilyName()
    {
        return $this->family_name;
    }

    /**
     * {@inheritdoc}
     */
    public function getNickname()
    {
        return $this->nickname;
    }

    /**
     * {@inheritdoc}
     */
    public function getPreferredUsername()
    {
        return $this->preferred_username;
    }

    /**
     * {@inheritdoc}
     */
    public function getProfile()
    {
        return $this->profile;
    }

    /**
     * {@inheritdoc}
     */
    public function getPicture()
    {
        return $this->picture;
    }

    /**
     * {@inheritdoc}
     */
    public function getWebsite()
    {
        return $this->website;
    }

    /**
     * {@inheritdoc}
     */
    public function getGender()
    {
        return $this->gender;
    }

    /**
     * {@inheritdoc}
     */
    public function getBirthdate()
    {
        return $this->birthdate;
    }

    /**
     * {@inheritdoc}
     */
    public function getZoneInfo()
    {
        return $this->zone_info;
    }

    /**
     * {@inheritdoc}
     */
    public function getLocale()
    {
        return $this->locale;
    }

    /**
     * {@inheritdoc}
     */
    public function getUpdatedAt()
    {
        return $this->updated_at;
    }

    /**
     * {@inheritdoc}
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * {@inheritdoc}
     */
    public function isEmailVerified()
    {
        return $this->email_verified;
    }

    /**
     * {@inheritdoc}
     */
    public function getPhoneNumber()
    {
        return $this->phone_number;
    }

    /**
     * {@inheritdoc}
     */
    public function isPhoneNumberVerified()
    {
        return $this->phone_number_verified;
    }

    /**
     * {@inheritdoc}
     */
    public function getAddress()
    {
        return $this->address;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthenticationMethodsReferences()
    {
        return $this->authentication_methods_references;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthenticationContextClassReference()
    {
        return $this->authentication_context_class_reference;
    }
}
