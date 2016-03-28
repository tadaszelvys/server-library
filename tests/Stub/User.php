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
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ConfidentialClientInterface;
use OAuth2\OpenIDConnect\AddressInterface;
use OAuth2\OpenIDConnect\UserInterface;
use OAuth2\ResourceOwner\ResourceOwnerTrait;
use OAuth2\User\IssueRefreshTokenExtensionInterface;
use OAuth2\User\UserTrait;

class User implements UserInterface, IssueRefreshTokenExtensionInterface
{
    use ResourceOwnerTrait;
    use UserTrait;

    /**
     * @var string
     */
    private $username;

    /**
     * @var string
     */
    private $password;

    /**
     * User constructor.
     *
     * @param string $username
     * @param string $password
     */
    public function __construct($username, $password)
    {
        $this->setPublicId($username);
        $this->username = $username;
        $this->password = $password;
    }

    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @return string
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * {@inheritdoc}
     */
    public function isRefreshTokenIssuanceAllowed(ClientInterface $client, $grant_type)
    {
        return $client instanceof ConfidentialClientInterface;
    }

    public function setLastLoginAt($last_login_at)
    {
        Assertion::integer($last_login_at);
        $this->last_login_at = $last_login_at;
    }

    /**
     * @param null|string $display_name
     */
    public function setDisplayName($display_name)
    {
        Assertion::string($display_name);
        $this->display_name = $display_name;
    }

    /**
     * @param null|string $given_name
     */
    public function setGivenName($given_name)
    {
        Assertion::string($given_name);
        $this->given_name = $given_name;
    }

    /**
     * @param null|string $middle_name
     */
    public function setMiddleName($middle_name)
    {
        Assertion::string($middle_name);
        $this->middle_name = $middle_name;
    }

    /**
     * @param null|string $family_name
     */
    public function setFamilyName($family_name)
    {
        Assertion::string($family_name);
        $this->family_name = $family_name;
    }

    /**
     * @param null|string $nickname
     */
    public function setNickname($nickname)
    {
        Assertion::string($nickname);
        $this->nickname = $nickname;
    }

    /**
     * @param null|string $preferred_username
     */
    public function setPreferredUsername($preferred_username)
    {
        Assertion::string($preferred_username);
        $this->preferred_username = $preferred_username;
    }

    /**
     * @param null|string $profile
     */
    public function setProfile($profile)
    {
        Assertion::url($profile);
        $this->profile = $profile;
    }

    /**
     * @param null|string $picture
     */
    public function setPicture($picture)
    {
        Assertion::url($picture);
        $this->picture = $picture;
    }

    /**
     * @param null|string $website
     */
    public function setWebsite($website)
    {
        Assertion::url($website);
        $this->website = $website;
    }

    /**
     * @param null|string $gender
     */
    public function setGender($gender)
    {
        Assertion::inArray($gender, ['male', 'female']);
        $this->gender = $gender;
    }

    /**
     * @param null|string $birthdate
     */
    public function setBirthdate($birthdate)
    {
        Assertion::string($birthdate);
        $this->birthdate = $birthdate;
    }

    /**
     * @param null|string $zone_info
     */
    public function setZoneInfo($zone_info)
    {
        Assertion::inArray($zone_info, timezone_identifiers_list());
        $this->zone_info = $zone_info;
    }

    /**
     * @param null|string $locale
     */
    public function setLocale($locale)
    {
        Assertion::string($locale);
        $this->locale = $locale;
    }

    /**
     * @param null|int $updated_at
     */
    public function setUpdatedAt($updated_at)
    {
        Assertion::integer($updated_at);
        $this->updated_at = $updated_at;
    }

    /**
     * @param null|string $email
     */
    public function setEmail($email)
    {
        Assertion::email($email);
        $this->email = $email;
    }

    /**
     * @param bool|null $email_verified
     */
    public function setEmailVerified($email_verified)
    {
        Assertion::boolean($email_verified);
        $this->email_verified = $email_verified;
    }

    /**
     * @param null|string $phone_number
     */
    public function setPhoneNumber($phone_number)
    {
        Assertion::string($phone_number);
        $this->phone_number = $phone_number;
    }

    /**
     * @param bool|null $phone_number_verified
     */
    public function setPhoneNumberVerified($phone_number_verified)
    {
        Assertion::boolean($phone_number_verified);
        $this->phone_number_verified = $phone_number_verified;
    }

    /**
     * @param \OAuth2\OpenIDConnect\AddressInterface $address
     */
    public function setAddress(AddressInterface $address)
    {
        $this->address = $address;
    }

    /**
     * @param string[] $authentication_methods_references
     */
    public function setAuthenticationMethodsReferences(array $authentication_methods_references)
    {
        $this->authentication_methods_references = $authentication_methods_references;
    }

    /**
     * @param string[] $authentication_context_class_reference
     */
    public function setAuthenticationContextClassReference(array $authentication_context_class_reference)
    {
        $this->authentication_context_class_reference = $authentication_context_class_reference;
    }
}
