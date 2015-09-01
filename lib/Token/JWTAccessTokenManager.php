<?php

namespace OAuth2\Token;

use Jose\JSONSerializationModes;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use SpomkyLabs\Jose\EncryptionInstruction;
use SpomkyLabs\Jose\SignatureInstruction;

abstract class JWTAccessTokenManager extends AccessTokenManager
{
    use HasExceptionManager;

    /**
     * @return \Jose\JWKInterface
     */
    abstract protected function getSignaturePrivateKey();

    /**
     * @return \Jose\JWKInterface
     */
    protected function getSignaturePublicKey()
    {

    }

    /**
     * @return \Jose\JWKInterface
     */
    protected function getEncryptionPublicKey()
    {

    }

    /**
     * @return \Jose\JWKInterface
     */
    protected function getEncryptionPrivateKey()
    {

    }

    /**
     * @return \Jose\SignerInterface
     */
    abstract protected function getSigner();

    /**
     * @return \Jose\EncrypterInterface|null
     */
    protected function getEncrypter()
    {
    }

    /**
     * @return array
     */
    protected function getJWTExtraClaims()
    {
        return [];
    }

    /**
     * @return array
     */
    protected function getJWTExtraHeaders()
    {
        return [];
    }

    /**
     * @return string|null
     */
    protected function generateTokenID()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    public function createAccessToken(ClientInterface $client, array $scope = [], ResourceOwnerInterface $resource_owner = null, RefreshTokenInterface $refresh_token = null)
    {
        $is_encrypted = $this->getConfiguration()->get('jwt_access_token_encrypted', false);

        $payload = $this->preparePayload($client, $scope, $resource_owner, $refresh_token);

        $jwt = $this->sign($payload);

        if (true === $is_encrypted && !is_null($this->getEncrypter())) {
            $jwt = $this->encrypt($jwt, $client);
        }

        $access_token = new AccessToken();
        $access_token->setExipresAt(time() + $this->getLifetime($client))
            ->setRefreshToken(is_null($refresh_token)?null:$refresh_token->getToken())
            ->setResourceOwnerPublicId(is_null($resource_owner)?null:$resource_owner->getPublicId())
            ->setScope($scope)
            ->setToken($jwt)
            ->setClientPublicId($client->getPublicId());

        return $access_token;
    }

    /**
     * @return array
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function prepareEncryptionHeader(ClientInterface $client)
    {
        $key_encryption_algorithm = $this->getConfiguration()->get('jwt_access_token_key_encryption_algorithm', null);
        $content_encryption_algorithm = $this->getConfiguration()->get('jwt_access_token_content_encryption_algorithm', null);
        $audience = $this->getConfiguration()->get('jwt_access_token_audience', null);
        $issuer = $this->getConfiguration()->get('jwt_access_token_issuer', null);

        if (!is_string($key_encryption_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, 'key_encryption_algorithm_not_defined', 'The configuration option "jwt_access_token_key_encryption_algorithm" is not set.');
        }
        if (!is_string($content_encryption_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, 'content_encryption_algorithm_not_defined', 'The configuration option "jwt_access_token_content_encryption_algorithm" is not set.');
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

        $jti = $this->generateTokenID();
        if (!is_null($jti)) {
            $header['jti'] = $jti;
        }

        return $header;
    }

    /**
     * @return array
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function prepareSignatureHeader()
    {
        $signature_algorithm = $this->getConfiguration()->get('jwt_access_token_signature_algorithm', null);
        if (!is_string($signature_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, 'signature_algorithm_not_defined', 'The configuration option "jwt_access_token_signature_algorithm" is not set.');
        }
        $header = array_merge(
            [
                'typ' => 'JWT',
                'alg' => $signature_algorithm,
            ],
            $this->getJWTExtraHeaders()
        );

        $jti = $this->generateTokenID();
        if (!is_null($jti)) {
            $header['jti'] = $jti;
        }

        return $header;
    }

    /**
     * @param \OAuth2\Client\ClientInterface                    $client
     * @param array                                             $scope
     * @param \OAuth2\ResourceOwner\ResourceOwnerInterface|null $resource_owner
     * @param \OAuth2\Token\RefreshTokenInterface|null          $refresh_token
     *
     * @return array
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function preparePayload(ClientInterface $client, array $scope = [], ResourceOwnerInterface $resource_owner = null, RefreshTokenInterface $refresh_token = null)
    {
        $audience = $this->getConfiguration()->get('jwt_access_token_audience', null);
        $issuer = $this->getConfiguration()->get('jwt_access_token_issuer', null);

        if (!is_string($audience)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, 'audience_not_defined', 'The configuration option "jwt_access_token_audience" is not set.');
        }
        if (!is_string($issuer)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, 'issuer_not_defined', 'The configuration option "jwt_access_token_issuer" is not set.');
        }

        $payload = array_merge(
            [
                'iss' => $issuer,
                'aud' => $audience,
                'iat' => time(),
                'nbf' => time(),
                'exp' => time() + $this->getLifetime($client),
                'sub' => $client->getPublicId(),
                'sco' => $scope,
            ],
            $this->getJWTExtraClaims()
        );
        if (!is_null($resource_owner)) {
            $payload['r_o'] = $resource_owner->getPublicId();
        }
        if (!is_null($refresh_token)) {
            $payload['ref'] = $refresh_token->getToken();
        }

        return $payload;
    }

    /**
     * @param array $payload
     *
     * @return string
     */
    private function sign(array $payload)
    {
        $header = $this->prepareSignatureHeader();
        $key = $this->getSignaturePrivateKey();
        if (!is_null($key->getKeyID())) {
            $header['kid'] = $key->getKeyID();
        }
        $instruction = new SignatureInstruction();
        $instruction->setKey($key)
            ->setProtectedHeader($header);

        return $this->getSigner()->sign($payload,[$instruction],JSONSerializationModes::JSON_COMPACT_SERIALIZATION);
    }

    /**
     * @param array $payload
     *
     * @return string
     */
    private function encrypt($payload, ClientInterface $client)
    {
        $header = array_merge(
            [],
            $this->prepareEncryptionHeader($client)
        );
        $public_key = $this->getEncryptionPublicKey();
        $private_key = $this->getEncryptionPrivateKey();

        if (!is_null($public_key->getKeyID())) {
            $header['kid'] = $public_key->getKeyID();
        }
        $instruction = new EncryptionInstruction();
        $instruction->setRecipientKey($public_key);
        if (!is_null($private_key)) {
            $instruction->setSenderKey($private_key);
        }

        return $this->getEncrypter()->encrypt($payload, [$instruction], $header);
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken($access_token)
    {

    }

    /**
     * {@inheritdoc}
     */
    public function revokeAccessToken(AccessTokenInterface $access_token)
    {
        //Not implemented
        return $this;
    }
}
