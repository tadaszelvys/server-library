<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect\UserInfo;

use Assert\Assertion;
use OAuth2\Client\ClientInterface;
use OAuth2\OpenIdConnect\Pairwise\PairwiseSubjectIdentifierAlgorithmInterface;
use OAuth2\UserAccount\UserAccountInterface;

trait HasPairwiseSubjectIdentifierSupportTrait
{
    /**
     * @var null|\OAuth2\OpenIdConnect\Pairwise\PairwiseSubjectIdentifierAlgorithmInterface
     */
    private $pairwise_algorithm = null;

    /**
     * @var bool
     */
    private $is_pairwise_subject_default = false;

    /**
     * {@inheritdoc}
     */
    public function enablePairwiseSubject(PairwiseSubjectIdentifierAlgorithmInterface $pairwise_algorithm)
    {
        $this->pairwise_algorithm = $pairwise_algorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function setPairwiseSubjectByDefault()
    {
        Assertion::notNull($this->pairwise_algorithm, 'The pairwise algorithm must be set before calling this method.');
        $this->is_pairwise_subject_default = true;
    }

    /**
     * {@inheritdoc}
     */
    public function setPublicSubjectByDefault()
    {
        $this->is_pairwise_subject_default = false;
    }

    /**
     * {@inheritdoc}
     */
    public function isPairwiseSubjectIdentifierSupported()
    {
        return null !== $this->pairwise_algorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function isPairwiseSubjectDefault()
    {
        return $this->is_pairwise_subject_default;
    }

    /**
     * @param \OAuth2\Client\ClientInterface           $client
     * @param \OAuth2\UserAccount\UserAccountInterface $user_account
     * @param string                                   $redirect_uri
     *
     * @return string
     */
    protected function calculateSubjectIdentifier(ClientInterface $client, UserAccountInterface $user_account, $redirect_uri)
    {
        $sub = $user_account->getPublicId();

        if (false === $this->isPairwiseSubjectIdentifierSupported()) {
            return $sub;
        }
        if ($client->has('subject_type') && ('pairwise' === $client->get('subject_type') || true === $this->isPairwiseSubjectDefault())) {
            $sector_identifier_host = $this->getSectorIdentifierHost($client, $redirect_uri);

            return $this->pairwise_algorithm->calculateSubjectIdentifier(
                $user_account,
                $sector_identifier_host
            );
        }

        return $sub;
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param string                         $redirect_uri
     *
     * @return string
     */
    private function getSectorIdentifierHost(ClientInterface $client, $redirect_uri)
    {
        $uri = $redirect_uri;

        if (true === $client->has('sector_identifier_uri')) {
            $uri = $client->get('sector_identifier_uri');
        }

        $data = parse_url($uri);
        if (!is_array($data) || !array_key_exists('host', $data)) {
            throw new \InvalidArgumentException(sprintf('Invalid Sector Identifier Uri "%s".', $uri));
        }

        return $data['host'];
    }
}
