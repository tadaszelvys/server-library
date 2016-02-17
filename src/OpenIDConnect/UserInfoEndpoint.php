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
use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasClientManagerSupervisor;
use OAuth2\Behaviour\HasEndUserManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTCreator;
use OAuth2\Behaviour\HasTokenTypeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerSupervisorInterface;
use OAuth2\Client\EncryptionCapabilitiesInterface;
use OAuth2\EndUser\EndUserManagerInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\TokenTypeManagerInterface;
use OAuth2\Util\JWTCreator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class UserInfoEndpoint implements UserInfoEndpointInterface
{
    use HasExceptionManager;
    use HasTokenTypeManager;
    use HasAccessTokenManager;
    use HasEndUserManager;
    use HasClientManagerSupervisor;
    use HasJWTCreator;

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
     * @param \OAuth2\Token\TokenTypeManagerInterface         $token_type_manager
     * @param \OAuth2\Token\AccessTokenManagerInterface       $access_token_manager
     * @param \OAuth2\EndUser\EndUserManagerInterface         $end_user_manager
     * @param \OAuth2\Client\ClientManagerSupervisorInterface $client_manager_supervisor
     * @param \OAuth2\Exception\ExceptionManagerInterface     $exception_manager
     */
    public function __construct(TokenTypeManagerInterface $token_type_manager,
                                AccessTokenManagerInterface $access_token_manager,
                                EndUserManagerInterface $end_user_manager,
                                ClientManagerSupervisorInterface $client_manager_supervisor,
                                ExceptionManagerInterface $exception_manager
    ) {
        $this->setTokenTypeManager($token_type_manager);
        $this->setAccessTokenManager($access_token_manager);
        $this->setEndUserManager($end_user_manager);
        $this->setClientManagerSupervisor($client_manager_supervisor);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * @param \OAuth2\Util\JWTCreator   $jwt_creator
     * @param string                    $signature_algorithm
     * @param \Jose\Object\JWKInterface $signature_key
     */
    public function enableSignedAndEncryptedResponsesSupport(JWTCreator $jwt_creator,
                                                             $signature_algorithm,
                                                             JWKInterface $signature_key
    ) {
        Assertion::inArray($signature_algorithm, $jwt_creator->getSignatureAlgorithms());
        $this->setJWTCreator($jwt_creator);

        $this->signature_algorithm = $signature_algorithm;
        $this->signature_key = $signature_key;
    }

    /**
     * @return bool
     */
    public function isSignedAndEncryptedResponsesSupportEnabled()
    {
        return null !== $this->getJWTCreator() && null !== $this->signature_algorithm  && null !== $this->signature_key;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignatureAlgorithms()
    {
        return $this->getJWTCreator()->getSignatureAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyEncryptionAlgorithms()
    {
        return $this->getJWTCreator()->getKeyEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getContentEncryptionAlgorithms()
    {
        return $this->getJWTCreator()->getContentEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getUserInfo(ServerRequestInterface $request, ResponseInterface &$response)
    {
        if (!$this->isRequestSecured($request)) {
            $exception = $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Request must be secured');
            $exception->getHttpResponse($response);

            return;
        }

        $token = $this->getTokenTypeManager()->findToken($request);

        if (null === $token) {
            $exception = $this->getExceptionManager()->getAuthenticateException(
                ExceptionManagerInterface::INVALID_TOKEN,
                'Access token required.',
                ['schemes' => $this->getTokenTypeManager()->getTokenTypeSchemes()]
            );
            $exception->getHttpResponse($response);

            return;
        }

        $access_token = $this->getAccessTokenManager()->getAccessToken($token['token']);
        if (null === $access_token || false === $token['type']->isTokenRequestValid($access_token, $request, $token['additional_credential_values'])) {
            $exception = $this->getExceptionManager()->getAuthenticateException(
                ExceptionManagerInterface::INVALID_TOKEN,
                'Access token does not exist or is not valid.',
                ['schemes' => $this->getTokenTypeManager()->getTokenTypeSchemes()]
            );
            $exception->getHttpResponse($response);

            return;
        }

        if (!in_array('openid', $access_token->getScope())) {
            $exception = $this->getExceptionManager()->getAuthenticateException(
                ExceptionManagerInterface::INVALID_TOKEN,
                'Access token does not contain the "openid" scope.',
                ['schemes' => $this->getTokenTypeManager()->getTokenTypeSchemes()]
            );
            $exception->getHttpResponse($response);

            return;
        }

        $end_user = $this->getEndUserManager()->getEndUser($access_token->getResourceOwnerPublicId());
        if (null === $end_user) {
            $exception = $this->getExceptionManager()->getAuthenticateException(
                ExceptionManagerInterface::INVALID_TOKEN,
                'Unable to find the resource owner.',
                ['schemes' => $this->getTokenTypeManager()->getTokenTypeSchemes()]
            );
            $exception->getHttpResponse($response);

            return;
        }

        $client = $this->getClientManagerSupervisor()->getClient($access_token->getClientPublicId());
        if (null === $client) {
            $exception = $this->getExceptionManager()->getAuthenticateException(
                ExceptionManagerInterface::INVALID_TOKEN,
                'Unable to find the client.',
                ['schemes' => $this->getTokenTypeManager()->getTokenTypeSchemes()]
            );
            $exception->getHttpResponse($response);

            return;
        }

        $this->populateResponse($response, $end_user->getUserInfo($access_token), $client);
    }

    /**
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param array                               $data
     * @param \OAuth2\Client\ClientInterface      $client
     */
    private function populateResponse(ResponseInterface &$response, array $data, ClientInterface $client)
    {
        $this->signAndEncrypt($data, $client);
        $response = $response->withHeader('Content-Type', 'application/json');
        $response = $response->withHeader('Cache-Control', 'no-store');
        $response = $response->withHeader('Pragma', 'no-cache');
        $response = $response->withStatus(200);
        $response->getBody()->write(is_array($data)?json_encode($data):$data);
    }

    private function signAndEncrypt(&$data, ClientInterface $client)
    {
        if (true === $this->isSignedAndEncryptedResponsesSupportEnabled()) {
            $data = $this->getJWTCreator()->sign(
                $data,
                [
                    'typ'       => 'JWT',
                    'alg' => $this->signature_algorithm
                ],
                $this->signature_key
            );
        }

        /*if ($client instanceof EncryptionCapabilitiesInterface) {
            $data = $this->getJWTCreator()->encrypt($data, [], $client->getEncryptionPublicKeySet()[0], $this->key_encryption_key);
        }*/
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return bool
     */
    private function isRequestSecured(ServerRequestInterface $request)
    {
        $server_params = $request->getServerParams();

        return !empty($server_params['HTTPS']) && 'on' === strtolower($server_params['HTTPS']);
    }
}
