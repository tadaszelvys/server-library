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

use OAuth2\ResourceOwner\ResourceOwner;
use OAuth2\Token\AccessTokenInterface;

/**
 * This interface must be implemented by end-user classes.
 */
class EndUser extends ResourceOwner implements EndUserInterface
{
    protected $last_login_at = null;

    public function __construct()
    {
        parent::__construct();
        $this->setType('end_user');
    }

    /**
     * {@inheritdoc}
     */
    public function getLastLoginAt()
    {
        return $this->last_login_at;
    }

    public function setLastLoginAt($last_login_at)
    {
        $this->last_login_at = $last_login_at;
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
    }

    /**
     * {@inheritdoc}
     */
    public function getGivenName()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getMiddleName()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getFamilyName()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getNickname()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getPreferredUsername()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getProfile()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getPicture()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getWebsite()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getGender()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getBirthdate()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getZoneInfo()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getLocale()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getUpdatedAt()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getEmail()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function isEmailVerified()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getPhoneNumber()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function isPhoneNumberVerified()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getAddress()
    {
    }
}
