<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\IdToken;

use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\Model\AuthCode\AuthCode;
use OAuth2\Model\Client\Client;
use OAuth2\Model\UserAccount\UserAccount;

interface IdTokenRepositoryInterface
{
    /**
     * @param Client           $client
     * @param UserAccount      $userAccount
     * @param string           $redirectUri
     * @param array            $claimsLocales
     * @param array            $requestClaims
     * @param array            $scopes
     * @param array            $idTokenClaims
     * @param AccessToken|null $accessToken
     * @param AuthCode|null    $authCode
     *
     * @return mixed
     */
    public function create(Client $client, UserAccount $userAccount, string $redirectUri, array $claimsLocales, array $requestClaims, array $scopes, array $idTokenClaims, AccessToken $accessToken = null, AuthCode $authCode = null);

    /**
     * @param IdToken $token The ID token to revoke
     */
    public function revoke(IdToken $token);

    /**
     * @param IdTokenId $idTokenId
     *
     * @return null|IdToken
     */
    public function find(IdTokenId $idTokenId);
}
