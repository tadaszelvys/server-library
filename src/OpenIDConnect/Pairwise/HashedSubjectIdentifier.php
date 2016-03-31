<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIDConnect\Pairwise;

use Assert\Assertion;
use Base64Url\Base64Url;
use OAuth2\User\UserInterface as BaseUserInterface;

class HashedSubjectIdentifier implements PairwiseSubjectIdentifierAlgorithmInterface
{
    /**
     * @var string
     */
    private $algorithm;
    
    /**
     * @var string
     */
    private $pairwise_hash_key;
    
    /**
     * @var string
     */
    private $salt;

    /**
     * EncryptedSubjectIdentifier constructor.
     *
     * @param string $pairwise_hash_key
     * @param string $algorithm
     * @param string $salt
     */
    public function __construct($pairwise_hash_key, $algorithm, $salt)
    {
        Assertion::string($pairwise_hash_key);
        Assertion::string($algorithm);
        Assertion::string($salt);
        Assertion::inArray($algorithm, hash_algos(), sprintf('The algorithm "%s" is not supported.', $algorithm));
        $this->pairwise_hash_key = $pairwise_hash_key;
        $this->algorithm = $algorithm;
        $this->salt = $salt;
    }

    /**
     * {@inheritdoc}
     */
    public function calculateSubjectIdentifier(BaseUserInterface $user, $sector_identifier_host)
    {
        $prepared = sprintf(
            '%s%s%s',
            $sector_identifier_host,
            $user->getPublicId(),
            $this->salt
        );

        return Base64Url::encode(hash_hmac($this->algorithm, $prepared, $this->pairwise_hash_key, true));
    }
}
