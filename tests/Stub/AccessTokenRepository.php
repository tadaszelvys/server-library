<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

/*use Jose\JWTCreatorInterface;
use Jose\JWTLoaderInterface;
use Jose\Object\JWKSetInterface;*/
use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\Model\AccessToken\AccessTokenId;
use OAuth2\Model\AccessToken\AccessTokenRepositoryInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\RefreshToken\RefreshToken;
use OAuth2\Model\RefreshToken\RefreshTokenId;
use OAuth2\Model\ResourceOwner\ResourceOwner;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\Model\UserAccount\UserAccountId;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    /**
     * @var AccessToken[]
     */
    private $accessTokens = [];

    public function __construct()
    {
        $this->save(AccessToken::create(
            AccessTokenId::create('ACCESS_TOKEN_#1'),
            UserAccount::create(
                UserAccountId::create('User #1'),
                []
            ),
            Client::create(
                ClientId::create('client1'),
                [],
                UserAccount::create(
                    UserAccountId::create('User #1'),
                    []
                )
            ),
            [],
            [],
            [],
            new \DateTimeImmutable('now +3600 seconds'),
            RefreshToken::create(
                RefreshTokenId::create('REFRESH_TOKEN_#1'),
                UserAccount::create(
                    UserAccountId::create('User #1'),
                    []
                ),
                Client::create(
                    ClientId::create('client1'),
                    [],
                    UserAccount::create(
                        UserAccountId::create('User #1'),
                        []
                    )
                ),
                [],
                new \DateTimeImmutable('now +2 days'),
                [],
                []
            )
        ));

        $this->save(AccessToken::create(
            AccessTokenId::create('ACCESS_TOKEN_#2'),
            UserAccount::create(
                UserAccountId::create('User #1'),
                []
            ),
            Client::create(
                ClientId::create('client2'),
                [],
                UserAccount::create(
                    UserAccountId::create('User #1'),
                    []
                )
            ),
            [],
            [],
            [],
            new \DateTimeImmutable('now +3600 seconds'),
            RefreshToken::create(
                RefreshTokenId::create('REFRESH_TOKEN_#1'),
                UserAccount::create(
                    UserAccountId::create('User #1'),
                    []
                ),
                Client::create(
                    ClientId::create('client2'),
                    [],
                    UserAccount::create(
                        UserAccountId::create('User #1'),
                        []
                    )
                ),
                [],
                new \DateTimeImmutable('now +2 days'),
                [],
                []
            )
        ));
    }

    /**
     * JWTAccessTokenManager constructor.
     *
     * @param \Jose\JWTCreatorInterface    $jwt_creator
     * @param \Jose\JWTLoaderInterface     $jwt_loader
     * @param string                       $signature_algorithm
     * @param \Jose\Object\JWKSetInterface $signature_key_set
     * @param string                       $key_encryption_algorithm
     * @param string                       $content_encryption_algorithm
     * @param \Jose\Object\JWKSetInterface $key_encryption_key_set
     * @param string                       $issuer
     */
    /*public function __construct(JWTCreatorInterface $jwt_creator,
                                JWTLoaderInterface $jwt_loader,
                                $signature_algorithm,
                                JWKSetInterface $signature_key_set,
                                $key_encryption_algorithm,
                                $content_encryption_algorithm,
                                JWKSetInterface $key_encryption_key_set,
                                $issuer
    ) {
        parent::__construct(
            $jwt_creator,
            $jwt_loader,
            $signature_algorithm,
            $signature_key_set,
            $key_encryption_algorithm,
            $content_encryption_algorithm,
            $key_encryption_key_set,
            $issuer
        );

        $abcd = new AccessToken();
        $abcd->setExpiresAt(time() + 3600);
        $abcd->setResourceOwnerPublicId($client_manager->getClientByName('Mufasa')->getPublicId());
        $abcd->setUserAccountPublicId(null);
        $abcd->setScope([]);
        $abcd->setClientPublicId($client_manager->getClientByName('Mufasa')->getPublicId());
        $abcd->setRefreshToken(null);
        $abcd->setToken('ABCD');
        $abcd->setParameter('token_type', 'Bearer');
        $abcd->setParameter('foo', 'bar');
        $abcd->setMetadatas(['plic', 'ploc', 'pluc']);

        $efgh = new AccessToken();
        $efgh->setExpiresAt(time() + 3600);
        $efgh->setResourceOwnerPublicId($client_manager->getClientByName('foo')->getPublicId());
        $efgh->setUserAccountPublicId(null);
        $efgh->setScope([]);
        $efgh->setClientPublicId($client_manager->getClientByName('foo')->getPublicId());
        $efgh->setRefreshToken('REFRESH_EFGH');
        $efgh->setToken('EFGH');
        $efgh->setParameter('token_type', 'Bearer');

        $initial_accessToken = new AccessToken();
        $initial_accessToken->setExpiresAt(time() + 3600);
        $initial_accessToken->setResourceOwnerPublicId('real_user1_public_id');
        $initial_accessToken->setUserAccountPublicId('user1');
        $initial_accessToken->setScope(['urn:oauth:v2:client:registration']);
        $initial_accessToken->setClientPublicId($client_manager->getClientByName('foo')->getPublicId());
        $initial_accessToken->setToken('INITIAL_ACCESS_TOKEN');
        $initial_accessToken->setParameter('token_type', 'Bearer');

        $no_user_info = new AccessToken();
        $no_user_info->setExpiresAt(time() + 3600);
        $no_user_info->setResourceOwnerPublicId('real_user1_public_id');
        $no_user_info->setUserAccountPublicId('user1');
        $no_user_info->setScope(['scope1']);
        $no_user_info->setClientPublicId($client_manager->getClientByName('foo')->getPublicId());
        $no_user_info->setToken('NO_USER_INFO');
        $no_user_info->setParameter('token_type', 'Bearer');
        $no_user_info->setMetadata('redirect_uri', 'https://example.com');
        $no_user_info->setMetadata('claims_locales', null);
        $no_user_info->setMetadata('requested_claims', ['id_token' => ['website' => ['essential' => false], 'picture' => ['essential' => false], 'email' => ['essential' => true], 'email_verified' => ['essential' => true]], 'userinfo' => ['website' => ['essential' => false], 'picture' => ['essential' => false], 'email' => ['essential' => true], 'email_verified' => ['essential' => true]]]);

        $user_info = new AccessToken();
        $user_info->setExpiresAt(time() + 3600);
        $user_info->setResourceOwnerPublicId('real_user1_public_id');
        $user_info->setUserAccountPublicId('user1');
        $user_info->setScope(['openid', 'profile', 'address', 'phone']);
        $user_info->setClientPublicId($client_manager->getClientByName('foo')->getPublicId());
        $user_info->setToken('USER_INFO');
        $user_info->setParameter('token_type', 'Bearer');
        $user_info->setMetadata('redirect_uri', 'https://example.com');
        $user_info->setMetadata('claims_locales', ['fr_fr', 'fr']);
        $user_info->setMetadata('requested_claims', ['id_token' => ['website' => ['essential' => false], 'picture' => ['essential' => false], 'email' => ['essential' => true], 'email_verified' => ['essential' => true]], 'userinfo' => ['website' => ['essential' => false], 'picture' => ['essential' => false], 'email' => ['essential' => true], 'email_verified' => ['essential' => true]]]);

        $user_info2 = new AccessToken();
        $user_info2->setExpiresAt(time() + 3600);
        $user_info2->setResourceOwnerPublicId('real_user1_public_id');
        $user_info2->setUserAccountPublicId('user1');
        $user_info2->setScope(['openid', 'profile', 'address', 'phone']);
        $user_info2->setClientPublicId($client_manager->getClientByName('jwt1')->getPublicId());
        $user_info2->setToken('USER_INFO2');
        $user_info2->setParameter('token_type', 'Bearer');
        $user_info2->setMetadata('redirect_uri', 'https://example2.com');
        $user_info2->setMetadata('claims_locales', null);
        $user_info2->setMetadata('requested_claims', ['id_token' => ['website' => ['essential' => false], 'picture' => ['essential' => false], 'email' => ['essential' => true], 'email_verified' => ['essential' => true]], 'userinfo' => ['website' => ['essential' => false], 'picture' => ['essential' => false], 'email' => ['essential' => true], 'email_verified' => ['essential' => true]]]);

        $user_info_mac = new AccessToken();
        $user_info_mac->setExpiresAt(time() + 3600);
        $user_info_mac->setResourceOwnerPublicId('real_user1_public_id');
        $user_info_mac->setUserAccountPublicId('user1');
        $user_info_mac->setScope(['openid', 'profile', 'address', 'phone']);
        $user_info_mac->setClientPublicId($client_manager->getClientByName('jwt1')->getPublicId());
        $user_info_mac->setToken('USER_INFO_MAC');
        $user_info_mac->setParameters([
            'token_type'    => 'MAC',
            'mac_key'       => 'Ajpw1Q2mebV8kz4',
            'mac_algorithm' => 'hmac-sha-256',
        ]);
        $user_info_mac->setMetadata('redirect_uri', 'https://example_mac.com');
        $user_info_mac->setMetadata('claims_locales', null);
        $user_info_mac->setMetadata('requested_claims', ['id_token' => ['website' => ['essential' => false], 'picture' => ['essential' => false], 'email' => ['essential' => true], 'email_verified' => ['essential' => true]], 'userinfo' => ['website' => ['essential' => false], 'picture' => ['essential' => false], 'email' => ['essential' => true], 'email_verified' => ['essential' => true]]]);

        $this->accessTokens[$abcd->getToken()] = $abcd;
        $this->accessTokens[$efgh->getToken()] = $efgh;
        $this->accessTokens[$user_info->getToken()] = $user_info;
        $this->accessTokens[$user_info2->getToken()] = $user_info2;
        $this->accessTokens[$user_info_mac->getToken()] = $user_info_mac;
        $this->accessTokens[$no_user_info->getToken()] = $no_user_info;
        $this->accessTokens[$initial_accessToken->getToken()] = $initial_accessToken;
    }*/

    /**
     * {@inheritdoc}
     */
    public function revoke(AccessToken $accessToken)
    {
        if ($this->has($accessToken->getId())) {
            unset($this->accessTokens[$accessToken->getId()->getValue()]);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function has(AccessTokenId $accessTokenId): bool
    {
        return array_key_exists($accessTokenId->getValue(), $this->accessTokens);
    }

    /**
     * {@inheritdoc}
     */
    public function find(AccessTokenId $tokenId)
    {
        return array_key_exists($tokenId->getValue(), $this->accessTokens) ? $this->accessTokens[$tokenId->getValue()] : $this->loadAccessToken($tokenId);
    }

    public function create(ResourceOwner $resourceOwner, Client $client, array $parameters, array $metadatas, array $scopes, \DateTimeImmutable $expiresAt, RefreshToken $refreshToken = null)
    {
        return AccessToken::create(
            AccessTokenId::create(bin2hex(random_bytes(50))),
            $resourceOwner,
            $client,
            $parameters,
            $metadatas,
            $scopes,
            $expiresAt,
            $refreshToken
        );
    }

    public function save(AccessToken $token)
    {
        $this->accessTokens[$token->getId()->getValue()] = $token;
    }

    /**
     * @param AccessTokenId $tokenId
     *
     * @return null|AccessToken
     */
    private function loadAccessToken(AccessTokenId $tokenId)
    {
    }
}
