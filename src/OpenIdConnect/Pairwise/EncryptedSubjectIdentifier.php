<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect\Pairwise;

use Assert\Assertion;
use Base64Url\Base64Url;
use OAuth2\UserAccount\UserAccountInterface as BaseUserAccountInterface;

class EncryptedSubjectIdentifier implements PairwiseSubjectIdentifierAlgorithmInterface
{
    /**
     * @var string
     */
    private $pairwise_encryption_key;

    /**
     * @var string
     */
    private $algorithm;

    /**
     * @var string
     */
    private $salt;

    /**
     * @var null|string
     */
    private $iv;

    /**
     * EncryptedSubjectIdentifier constructor.
     *
     * @param string      $pairwise_encryption_key
     * @param string      $algorithm
     * @param null|string $iv
     * @param string      $salt
     */
    public function __construct($pairwise_encryption_key, $algorithm, $iv, $salt)
    {
        Assertion::nullOrString($iv);
        Assertion::string($salt);
        Assertion::string($pairwise_encryption_key);
        Assertion::string($algorithm);
        Assertion::inArray($algorithm, openssl_get_cipher_methods(), sprintf('The algorithm "%s" is not supported.', $algorithm));
        $this->pairwise_encryption_key = $pairwise_encryption_key;
        $this->algorithm = $algorithm;
        $this->salt = $salt;
        $this->iv = $iv;
    }

    /**
     * {@inheritdoc}
     */
    public function calculateSubjectIdentifier(BaseUserAccountInterface $user_account, $sector_identifier_host)
    {
        $prepared = sprintf(
            '%s:%s:%s',
            $sector_identifier_host,
            $user_account->getPublicId(),
            $this->salt
        );

        return Base64Url::encode(openssl_encrypt($prepared, $this->algorithm, $this->pairwise_encryption_key, OPENSSL_RAW_DATA, $this->iv));
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicIdFromSubjectIdentifier($subject_identifier)
    {
        $decoded = openssl_decrypt(Base64Url::decode($subject_identifier), $this->algorithm, $this->pairwise_encryption_key, OPENSSL_RAW_DATA, $this->iv);
        $parts = explode(':', $decoded);
        if (3 !== count($parts)) {
            return;
        }

        return $parts[1];
    }
}
