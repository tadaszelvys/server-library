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

use OAuth2\Model\AuthCode\AuthCode;
use OAuth2\Model\AuthCode\AuthCodeId;
use OAuth2\Model\AuthCode\AuthCodeRepositoryInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Model\UserAccount\UserAccount;
use Zend\Diactoros\Uri;

class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    /**
     * @var AuthCode[]
     */
    private $authCodes = [];

    /**
     * AuthCodeRepository constructor.
     */
    public function __construct()
    {
        $this->save(AuthCode::create(
            AuthCodeId::create('VALID_AUTH_CODE'),
            Client::create(),
            UserAccount::create(),
            [],
            new Uri(),
            new \DateTimeImmutable('now +1 day'),
            [],
            [],
            []
        ));

        /*$valid_authCode1 = new AuthCode();
        $valid_authCode1->setIssueRefreshToken(true);
        $valid_authCode1->setMetadata('redirect_uri', 'http://example.com/redirect_uri/');
        $valid_authCode1->setClientPublicId($client_manager->getClientByName('Mufasa')->getPublicId());
        $valid_authCode1->setResourceOwnerPublicId('real_user1_public_id');
        $valid_authCode1->setUserAccountPublicId('user1');
        $valid_authCode1->setExpiresAt(time() + 3000);
        $valid_authCode1->setScope([
                'scope1',
                'scope2',
            ]);
        $valid_authCode1->setToken('VALID_AUTH_CODE');

        $valid_authCode_to_be_revoked = new AuthCode();
        $valid_authCode_to_be_revoked->setIssueRefreshToken(true);
        $valid_authCode_to_be_revoked->setMetadata('redirect_uri', 'http://example.com/redirect_uri/');
        $valid_authCode_to_be_revoked->setClientPublicId($client_manager->getClientByName('foo')->getPublicId());
        $valid_authCode_to_be_revoked->setResourceOwnerPublicId('real_user1_public_id');
        $valid_authCode_to_be_revoked->setUserAccountPublicId('user1');
        $valid_authCode_to_be_revoked->setExpiresAt(time() + 3000);
        $valid_authCode_to_be_revoked->setScope([
                'scope1',
                'scope2',
            ]);
        $valid_authCode_to_be_revoked->setToken('VALID_AUTH_CODE_TO_BE_REVOKED');

        $valid_authCode2 = new AuthCode();
        $valid_authCode2->setIssueRefreshToken(true);
        $valid_authCode2->setMetadata('redirect_uri', 'http://example.com/redirect_uri/');
        $valid_authCode2->setClientPublicId($client_manager->getClientByName('foo')->getPublicId());
        $valid_authCode2->setResourceOwnerPublicId('real_user1_public_id');
        $valid_authCode2->setUserAccountPublicId('user1');
        $valid_authCode2->setExpiresAt(time() + 3000);
        $valid_authCode2->setScope([
                'scope1',
                'scope2',
            ]);
        $valid_authCode2->setQueryParams([
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'plain',
        ]);
        $valid_authCode2->setToken('VALID_AUTH_CODE_PUBLIC_CLIENT');

        $expired_authCode = new AuthCode();
        $expired_authCode->setIssueRefreshToken(true);
        $expired_authCode->setMetadata('redirect_uri', 'http://example.com/redirect_uri/');
        $expired_authCode->setClientPublicId($client_manager->getClientByName('Mufasa')->getPublicId());
        $expired_authCode->setResourceOwnerPublicId('real_user1_public_id');
        $expired_authCode->setResourceOwnerPublicId('user1');
        $expired_authCode->setExpiresAt(time() - 1);
        $expired_authCode->setScope([
                'scope1',
                'scope2',
            ]);
        $expired_authCode->setToken('EXPIRED_AUTH_CODE');

        $this->authCodes['VALID_AUTH_CODE'] = $valid_authCode1;
        $this->authCodes['VALID_AUTH_CODE_PUBLIC_CLIENT'] = $valid_authCode2;
        $this->authCodes['EXPIRED_AUTH_CODE'] = $expired_authCode;
        $this->authCodes['VALID_AUTH_CODE_TO_BE_REVOKED'] = $valid_authCode_to_be_revoked;*/
    }

    /**
     * @param AuthCode $authCode
     */
    public function save(AuthCode $authCode)
    {
        $this->authCodes[$authCode->getId()->getValue()] = $authCode;
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(AuthCode $code)
    {
        if (array_key_exists($code->getId()->getValue(), $this->authCodes)) {
            unset($this->authCodes[$code->getId()->getValue()]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function create(Client $client, UserAccount $userAccount, array $queryParameters, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function has(AuthCodeId $authCodeId): bool
    {
        return array_key_exists($authCodeId->getValue(), $this->authCodes);
    }

    /**
     * {@inheritdoc}
     */
    public function find(AuthCodeId $authCodeId)
    {
        return $this->has($authCodeId) ? $this->authCodes[$authCodeId->getValue()] : null;
    }
}
