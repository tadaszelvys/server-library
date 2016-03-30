<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIDConnect;

use Assert\Assertion;
use Jose\Object\JWKInterface;
use OAuth2\Behaviour\HasClientManagerSupervisor;
use OAuth2\Behaviour\HasUserManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTCreator;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerSupervisorInterface;
use OAuth2\Client\EncryptionCapabilitiesInterface;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\User\UserManagerInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\JWTCreator;

final class UserInfo implements UserInfoInterface
{
    use HasExceptionManager;
    use HasUserManager;
    use HasClientManagerSupervisor;
    use HasJWTCreator;

    /**
     * @var string|null
     */
    private $issuer = null;

    /**
     * @var \Jose\Object\JWKInterface|null
     */
    private $signature_key = null;

    /**
     * @var string|null
     */
    private $signature_algorithm = null;

    /**
     * UserInfoEndpoint constructor.
     *
     * @param \OAuth2\User\UserManagerInterface         $user_manager
     * @param \OAuth2\Client\ClientManagerSupervisorInterface $client_manager_supervisor
     * @param \OAuth2\Exception\ExceptionManagerInterface     $exception_manager
     */
    public function __construct(UserManagerInterface $user_manager,
                                ClientManagerSupervisorInterface $client_manager_supervisor,
                                ExceptionManagerInterface $exception_manager
    ) {
        $this->setUserManager($user_manager);
        $this->setClientManagerSupervisor($client_manager_supervisor);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * @param \OAuth2\Util\JWTCreator        $jwt_creator
     * @param string                         $issuer
     * @param string                         $signature_algorithm
     * @param \Jose\Object\JWKInterface      $signature_key
     */
    public function enableSignedResponsesSupport(JWTCreator $jwt_creator,
                                                 $issuer,
                                                 $signature_algorithm,
                                                 JWKInterface $signature_key
    ) {
        Assertion::string($issuer);
        Assertion::inArray($signature_algorithm, $jwt_creator->getSignatureAlgorithms());
        $this->setJWTCreator($jwt_creator);

        $this->issuer = $issuer;
        $this->signature_key = $signature_key;
        $this->signature_algorithm = $signature_algorithm;
    }

    /**
     * @return bool
     */
    public function isSignedResponsesSupportEnabled()
    {
        return null !== $this->getJWTCreator();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedSignatureAlgorithms()
    {
        return $this->getJWTCreator()->getSignatureAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedKeyEncryptionAlgorithms()
    {
        return $this->getJWTCreator()->getKeyEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return $this->getJWTCreator()->getContentEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getUserInfo(AccessTokenInterface $access_token)
    {

        if (!in_array('openid', $access_token->getScope())) {
            throw $this->getExceptionManager()->getBadRequestException(
                ExceptionManagerInterface::INVALID_REQUEST,
                'Access token does not contain the "openid" scope.'
            );
        }

        $user = $this->getUserManager()->getUser($access_token->getResourceOwnerPublicId());
        if (null === $user) {
            throw $this->getExceptionManager()->getBadRequestException(
                ExceptionManagerInterface::INVALID_REQUEST,
                'Unable to find the resource owner.'
            );
        }

        $client = $this->getClientManagerSupervisor()->getClient($access_token->getClientPublicId());
        if (null === $client) {
            throw $this->getExceptionManager()->getBadRequestException(
                ExceptionManagerInterface::INVALID_REQUEST,
                'Unable to find the client.'
            );
        }

        $info = [
            'aud' => $client->getPublicId(),
            'sub' => $user->getPublicId(),
            'iss' => $this->issuer,
            'iat' => time(),
            'nbf' => time(),
        ];
        if (0 !== $access_token->getExpiresAt()) {
            $info['exp'] = $access_token->getExpiresAt();
        }
        if ($user instanceof UserInterface) {
            $info = array_merge(
                $info,
                $user->getUserInfo($access_token->getScope())
            );
        }
        
        $this->signAndEncrypt($info, $client);
        
        return $info;
    }

    private function signAndEncrypt(&$data, ClientInterface $client)
    {
        if (true === $this->isSignedResponsesSupportEnabled()) {
            $data = $this->getJWTCreator()->sign(
                $data,
                [
                    'typ' => 'JWT',
                    'alg' => $this->signature_algorithm,
                ],
                $this->signature_key
            );
        }

        if ($client instanceof EncryptionCapabilitiesInterface) {
            $data = $this->getJWTCreator()->encrypt(
                $data,
                [
                    'alg' => $client->getKeyEncryptionAlgorithm(),
                    'enc' => $client->getContentEncryptionAlgorithm(),
                ],
                $client->getEncryptionPublicKey()
            );
        }
    }
}