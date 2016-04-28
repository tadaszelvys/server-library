<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect;

use OAuth2\Client\ClientInterface;
use OAuth2\OpenIdConnect\Pairwise\PairwiseSubjectIdentifierAlgorithmInterface;
use OAuth2\User\UserInterface;

trait HasPairwiseSubjectIdentifierSupportTrait
{
    /**
     * @var null|\OAuth2\OpenIdConnect\Pairwise\PairwiseSubjectIdentifierAlgorithmInterface
     */
    private $pairwise_algorithm = null;

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
    public function isPairwiseSubjectIdentifierSupported()
    {
        return null !== $this->pairwise_algorithm;
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param \OAuth2\User\UserInterface     $user
     * @param string                         $redirect_uri
     *
     * @return string
     */
    protected function calculateSubjectIdentifier(ClientInterface $client, UserInterface $user, $redirect_uri)
    {
        $sub = $user->getPublicId();

        if (false === $this->isPairwiseSubjectIdentifierSupported()) {
            return $sub;
        }

        $sector_identifier_host = $this->getSectorIdentifierHost($client, $redirect_uri);

        return $this->pairwise_algorithm->calculateSubjectIdentifier(
            $user,
            $sector_identifier_host
        );
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
