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

use Jose\JWTCreatorInterface;
use Jose\JWTLoaderInterface;
use Jose\Object\JWKSetInterface;
use OAuth2\Token\AccessToken;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\JWTAccessTokenManager as Base;

class JWTAccessTokenManager extends Base
{
    /**
     * @var \OAuth2\Token\AccessTokenInterface[]
     */
    private $access_tokens = [];

    /**
     * JWTAccessTokenManager constructor.
     *
     * @param \OAuth2\Test\Stub\ClientManager $client_manager
     * @param \Jose\JWTCreatorInterface       $jwt_creator
     * @param \Jose\JWTLoaderInterface        $jwt_loader
     * @param string                          $signature_algorithm
     * @param \Jose\Object\JWKSetInterface    $signature_key_set
     * @param string                          $key_encryption_algorithm
     * @param string                          $content_encryption_algorithm
     * @param \Jose\Object\JWKSetInterface    $key_encryption_key_set
     * @param string                          $issuer
     */
    public function __construct(ClientManager $client_manager,
                                JWTCreatorInterface $jwt_creator,
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
        $abcd->setTokenType('Bearer');
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
        $efgh->setTokenType('Bearer');

        $initial_access_token = new AccessToken();
        $initial_access_token->setExpiresAt(time() + 3600);
        $initial_access_token->setResourceOwnerPublicId('real_user1_public_id');
        $initial_access_token->setUserAccountPublicId('user1');
        $initial_access_token->setScope(['urn:oauth:v2:client:registration']);
        $initial_access_token->setClientPublicId($client_manager->getClientByName('foo')->getPublicId());
        $initial_access_token->setToken('INITIAL_ACCESS_TOKEN');
        $initial_access_token->setTokenType('Bearer');

        $no_user_info = new AccessToken();
        $no_user_info->setExpiresAt(time() + 3600);
        $no_user_info->setResourceOwnerPublicId('real_user1_public_id');
        $no_user_info->setUserAccountPublicId('user1');
        $no_user_info->setScope(['scope1']);
        $no_user_info->setClientPublicId($client_manager->getClientByName('foo')->getPublicId());
        $no_user_info->setToken('NO_USER_INFO');
        $no_user_info->setTokenType('Bearer');
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
        $user_info->setTokenType('Bearer');
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
        $user_info2->setTokenType('Bearer');
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
        $user_info_mac->setTokenType('MAC');
        $user_info_mac->setParameters([
            'mac_key'       => 'Ajpw1Q2mebV8kz4',
            'mac_algorithm' => 'hmac-sha-256',
        ]);
        $user_info_mac->setMetadata('redirect_uri', 'https://example_mac.com');
        $user_info_mac->setMetadata('claims_locales', null);
        $user_info_mac->setMetadata('requested_claims', ['id_token' => ['website' => ['essential' => false], 'picture' => ['essential' => false], 'email' => ['essential' => true], 'email_verified' => ['essential' => true]], 'userinfo' => ['website' => ['essential' => false], 'picture' => ['essential' => false], 'email' => ['essential' => true], 'email_verified' => ['essential' => true]]]);

        $this->access_tokens[$abcd->getToken()] = $abcd;
        $this->access_tokens[$efgh->getToken()] = $efgh;
        $this->access_tokens[$user_info->getToken()] = $user_info;
        $this->access_tokens[$user_info2->getToken()] = $user_info2;
        $this->access_tokens[$user_info_mac->getToken()] = $user_info_mac;
        $this->access_tokens[$no_user_info->getToken()] = $no_user_info;
        $this->access_tokens[$initial_access_token->getToken()] = $initial_access_token;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAccessToken(AccessTokenInterface $access_token)
    {
        if (isset($this->access_tokens[$access_token->getToken()])) {
            unset($this->access_tokens[$access_token->getToken()]);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken($token)
    {
        return array_key_exists($token, $this->access_tokens) ? $this->access_tokens[$token] : parent::getAccessToken($token);
    }
}
