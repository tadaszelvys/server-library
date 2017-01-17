<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\AccessToken;

use OAuth2\Model\Client\Client;
use OAuth2\Model\ResourceOwner\ResourceOwner;

interface AccessTokenRepositoryInterface
{
    /**
     * @param ResourceOwner      $resourceOwner
     * @param Client             $client
     * @param array              $parameters
     * @param array              $metadatas
     * @param string[]           $scopes
     * @param \DateTimeImmutable $expiresAt
     *
     * @return AccessToken
     */
    public function create(ResourceOwner $resourceOwner, Client $client, array $parameters, array $metadatas, array $scopes, \DateTimeImmutable $expiresAt);

    /**
     * @param AccessToken $token
     */
    public function save(AccessToken $token);

    /**
     * This function revoke an access token.
     *
     * @param AccessToken $token The access token to revoke
     */
    public function revoke(AccessToken $token);

    /**
     * @param AccessTokenId $accessTokenId The access token ID
     *
     * @return bool
     */
    public function has(AccessTokenId $accessTokenId): bool;

    /**
     * @param AccessTokenId $accessTokenId The access token ID
     *
     * @return AccessToken|null Return the access token or null if the argument is not a valid access token
     */
    public function find(AccessTokenId $accessTokenId);
}
