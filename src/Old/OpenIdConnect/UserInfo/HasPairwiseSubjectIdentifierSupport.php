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
use OAuth2\Model\Client\Client;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\OpenIdConnect\Pairwise\PairwiseSubjectIdentifierAlgorithmInterface;

trait HasPairwiseSubjectIdentifierSupport
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
    public function getPairwiseSubjectIdentifierAlgorithm()
    {
        return $this->pairwise_algorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function isPairwiseSubjectDefault()
    {
        return $this->is_pairwise_subject_default;
    }

    /**
     * @param Client           $client
     * @param UserAccount $user_account
     * @param string                                   $redirect_uri
     *
     * @return string
     */
    protected function calculateSubjectIdentifier(Client $client, UserAccount $user_account, $redirect_uri)
    {
        $sub = $user_account->getId()->getValue();

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
     * @param Client $client
     * @param string                         $redirect_uri
     *
     * @return string
     */
    private function getSectorIdentifierHost(Client $client, $redirect_uri)
    {
        $uri = $redirect_uri;

        if (true === $client->has('sector_identifier_uri')) {
            $uri = $client->get('sector_identifier_uri');
        }

        $data = parse_url($uri);
        Assertion::true(is_array($data) && array_key_exists('host', $data), sprintf('Invalid Sector Identifier Uri \'%s\'.', $uri));

        return $data['host'];
    }
}
