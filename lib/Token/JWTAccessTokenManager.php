<?php

namespace OAuth2\Token;

use Jose\JWTInterface;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTEncrypter;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Behaviour\HasJWTSigner;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use OAuth2\Util\JWTEncrypter;
use SpomkyLabs\Jose\JWT;

abstract class JWTAccessTokenManager extends AccessTokenManager
{
    use HasExceptionManager;
    use HasJWTLoader;
    use HasJWTSigner;
    use HasJWTEncrypter;

    /**
     * @var array
     */
    protected $encryption_private_key = [];

    /**
     * @return array
     */
    public function getEncryptionPrivateKey()
    {
        return $this->encryption_private_key;
    }

    /**
     * @param array $encryption_private_key
     *
     * @return $this
     */
    public function setEncryptionPrivateKey(array $encryption_private_key)
    {
        $this->encryption_private_key = $encryption_private_key;

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    public function createAccessToken(ClientInterface $client, ResourceOwnerInterface $resource_owner, array $scope = [], RefreshTokenInterface $refresh_token = null)
    {
        $payload = $this->preparePayload($client, $scope, $resource_owner, $refresh_token);
        $signature_header = $this->prepareSignatureHeader();

        $jwt = new JWT();
        $jwt->setPayload($payload)
            ->setProtectedHeader($signature_header);

        $jws = $this->getJWTSigner()->sign($jwt->getPayload(), $jwt->getProtectedHeader());
        $jwe = $this->encrypt($jws, $client);

        $access_token = new AccessToken();
        $access_token->setRefreshToken(null === $refresh_token ? null : $refresh_token->getToken())
            ->setExpiresAt(time() + $this->getLifetime($client))
            ->setResourceOwnerPublicId(null === $resource_owner ? null : $resource_owner->getPublicId())
            ->setScope($scope)
            ->setToken($jwe)
            ->setClientPublicId($client->getPublicId());

        return $access_token;
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return array
     */
    protected function prepareEncryptionHeader(ClientInterface $client)
    {
        $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm();
        $content_encryption_algorithm = $this->getContentEncryptionAlgorithm();
        $audience = $this->getConfiguration()->get('jwt_access_token_audience', null);
        $issuer = $this->getConfiguration()->get('jwt_access_token_issuer', null);

        if (!is_string($key_encryption_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The configuration option "jwt_access_token_key_encryption_algorithm" is not set.');
        }
        if (!is_string($content_encryption_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The configuration option "jwt_access_token_content_encryption_algorithm" is not set.');
        }

        $header = array_merge(
            [
                'iss' => $issuer,
                'aud' => $audience,
                'iat' => time(),
                'nbf' => time(),
                'exp' => time() + $this->getLifetime($client),
                'typ' => 'JWT',
                'alg' => $key_encryption_algorithm,
                'enc' => $content_encryption_algorithm,
            ]
        );

        $key = $this->getJWTEncrypter()->getKeyEncryptionKey();
        if (null !== $key->getKeyID()) {
            $header['kid'] = $key->getKeyID();
        }

        return $header;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return array
     */
    protected function prepareSignatureHeader()
    {
        $signature_algorithm = $this->getSignatureAlgorithm();
        if (!is_string($signature_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The configuration option "jwt_access_token_signature_algorithm" is not set.');
        }

        $header = [
            'typ' => 'JWT',
            'alg' => $signature_algorithm,
        ];

        $key = $this->getJWTSigner()->getSignatureKey();
        if (null !== $key->getKeyID()) {
            $header['kid'] = $key->getKeyID();
        }

        return $header;
    }

    /**
     * @param \OAuth2\Client\ClientInterface                    $client
     * @param array                                             $scope
     * @param \OAuth2\ResourceOwner\ResourceOwnerInterface|null $resource_owner
     * @param \OAuth2\Token\RefreshTokenInterface|null          $refresh_token
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return array
     */
    protected function preparePayload(ClientInterface $client, array $scope = [], ResourceOwnerInterface $resource_owner = null, RefreshTokenInterface $refresh_token = null)
    {
        $audience = $this->getConfiguration()->get('jwt_access_token_audience', null);
        $issuer = $this->getConfiguration()->get('jwt_access_token_issuer', null);

        if (!is_string($audience)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The configuration option "jwt_access_token_audience" is not set.');
        }
        if (!is_string($issuer)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The configuration option "jwt_access_token_issuer" is not set.');
        }

        $payload = [
            'iss' => $issuer,
            'aud' => $audience,
            'iat' => time(),
            'nbf' => time(),
            'exp' => time() + $this->getLifetime($client),
            'sub' => $client->getPublicId(),
            'sco' => $scope,
        ];
        if (null !== $resource_owner) {
            $payload['r_o'] = $resource_owner->getPublicId();
        }
        if (null !== $refresh_token) {
            $payload['ref'] = $refresh_token->getToken();
        }

        return $payload;
    }

    /**
     * @param string                         $payload
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    private function encrypt($payload, ClientInterface $client)
    {
        if (false === $this->getConfiguration()->get('jwt_access_token_encrypted', false)) {
            return $payload;
        }

        if (!$this->getJWTEncrypter() instanceof JWTEncrypter) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'Encrypter is not defined.');
        }

        $header = $this->prepareEncryptionHeader($client);

        return $this->getJWTEncrypter()->encrypt($payload, $header, $this->getEncryptionPrivateKey());
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken($assertion)
    {
        $jwt = $this->getJWTLoader()->load($assertion);

        $access_token = new AccessToken();
        $access_token->setClientPublicId($jwt->getSubject())
            ->setExpiresAt($jwt->getExpirationTime())
            ->setToken($assertion);
        if (null !== $resource_owner = $jwt->getPayloadValue('r_o')) {
            $access_token->setResourceOwnerPublicId($resource_owner);
        }
        if (null !== $scope = $jwt->getPayloadValue('sco')) {
            $access_token->setScope($scope);
        }
        if (null !== $refresh_token = $jwt->getPayloadValue('ref')) {
            $access_token->setRefreshToken($refresh_token);
        }

        return $access_token;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAccessToken(AccessTokenInterface $access_token)
    {
        //Not implemented
        return $this;
    }

    /**
     * By default, this method does nothing, but should be overridden and check other claims (issuer, jti...).
     *
     * @param \Jose\JWTInterface $jwt
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function checkJWT(JWTInterface $jwt)
    {
    }

    /**
     * @return string[]
     */
    protected function getRequiredClaims()
    {
        return [
            'iss',
            'aud',
            'sub',
            'exp',
        ];
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    protected function getSignatureAlgorithm()
    {
        $signature_algorithm = $this->getConfiguration()->get('jwt_access_token_signature_algorithm', null);
        if (!is_string($signature_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The signature algorithm used to sign access tokens is not set.');
        }

        return $signature_algorithm;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    protected function getKeyEncryptionAlgorithm()
    {
        $key_encryption_algorithm = $this->getConfiguration()->get('jwt_access_token_key_encryption_algorithm', null);
        if (!is_string($key_encryption_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The key encryption algorithm used to encrypt access tokens is not set.');
        }

        return $key_encryption_algorithm;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    protected function getContentEncryptionAlgorithm()
    {
        $content_encryption_algorithm = $this->getConfiguration()->get('jwt_access_token_content_encryption_algorithm', null);
        if (!is_string($content_encryption_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The content encryption algorithm used to encrypt access tokens is not set.');
        }

        return $content_encryption_algorithm;
    }
}
