<?php

namespace OAuth2\Token;

use Jose\EncrypterInterface;
use Jose\JSONSerializationModes;
use Jose\JWEInterface;
use Jose\JWKManagerInterface;
use Jose\JWKSetManagerInterface;
use Jose\JWSInterface;
use Jose\JWTInterface;
use Jose\LoaderInterface;
use Jose\SignerInterface;
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
     * @var array
     */
    protected $signature_private_key = [];

    /**
     * @var array
     */
    protected $signature_public_key = [];

    /**
     * @var array
     */
    protected $encryption_private_key = [];

    /**
     * @var array
     */
    protected $encryption_public_key = [];

    /**
     * @var \Jose\LoaderInterface
     */
    protected $loader;

    /**
     * @var \Jose\SignerInterface
     */
    protected $signer;

    /**
     * @var \Jose\EncrypterInterface
     */
    protected $encrypter;

    /**
     * @var \Jose\JWKManagerInterface
     */
    protected $key_manager;

    /**
     * @var \Jose\JWKSetManagerInterface
     */
    protected $key_set_manager;

    /**
     * @return array
     */
    public function getSignaturePrivateKey()
    {
        return $this->signature_private_key;
    }

    /**
     * @return array
     */
    public function getSignaturePublicKey()
    {
        return $this->signature_public_key;
    }

    /**
     * @return array
     */
    public function getEncryptionPrivateKey()
    {
        return $this->encryption_public_key;
    }

    /**
     * @return array
     */
    public function getEncryptionPublicKey()
    {
        return $this->encryption_public_key;
    }

    /**
     * @return \Jose\LoaderInterface
     */
    public function getLoader()
    {
        return $this->loader;
    }

    /**
     * @param \Jose\LoaderInterface $loader
     *
     * @return self
     */
    public function setLoader(LoaderInterface $loader)
    {
        $this->loader = $loader;

        return $this;
    }

    /**
     * @return \Jose\SignerInterface
     */
    public function getSigner()
    {
        return $this->signer;
    }

    /**
     * @param \Jose\SignerInterface $signer
     *
     * @return self
     */
    public function setSigner(SignerInterface $signer)
    {
        $this->signer = $signer;

        return $this;
    }

    /**
     * @return \Jose\EncrypterInterface|null
     */
    public function getEncrypter()
    {
        return $this->encrypter;
    }

    /**
     * @param \Jose\EncrypterInterface $encrypter
     *
     * @return self
     */
    public function setEncrypter(EncrypterInterface $encrypter)
    {
        $this->encrypter = $encrypter;

        return $this;
    }

    /**
     * @return \Jose\JWKManagerInterface
     */
    public function getKeyManager()
    {
        return $this->key_manager;
    }

    /**
     * @param \Jose\JWKManagerInterface $key_manager
     *
     * @return self
     */
    public function setKeyManager(JWKManagerInterface $key_manager)
    {
        $this->key_manager = $key_manager;

        return $this;
    }

    /**
     * @return \Jose\JWKSetManagerInterface
     */
    public function getKeySetManager()
    {
        return $this->key_set_manager;
    }

    /**
     * @param \Jose\JWKSetManagerInterface $key_set_manager
     *
     * @return self
     */
    public function setKeySetManager(JWKSetManagerInterface $key_set_manager)
    {
        $this->key_set_manager = $key_set_manager;

        return $this;
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
        if (is_array($jwt)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'JWT should be a string.');
        }

        if (true === $is_encrypted && !is_null($this->getEncrypter())) {
            $jwt = $this->encrypt($jwt, $client);
            if (is_array($jwt)) {
                throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'JWT should be a string.');
            }
        }

        $access_token = new AccessToken();
        $access_token->setRefreshToken(is_null($refresh_token) ? null : $refresh_token->getToken())
            ->setExpiresAt(time() + $this->getLifetime($client))
            ->setResourceOwnerPublicId(is_null($resource_owner) ? null : $resource_owner->getPublicId())
            ->setScope($scope)
            ->setToken($jwt)
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
    private function prepareEncryptionHeader(ClientInterface $client)
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
                'sub' => $client->getPublicId(),
            ]
        );

        $jti = $this->generateTokenID();
        if (!is_null($jti)) {
            $header['jti'] = $jti;
        }

        return $header;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return array
     */
    private function prepareSignatureHeader()
    {
        $signature_algorithm = $this->getSignatureAlgorithm();
        if (!is_string($signature_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The configuration option "jwt_access_token_signature_algorithm" is not set.');
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
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return array
     */
    private function preparePayload(ClientInterface $client, array $scope = [], ResourceOwnerInterface $resource_owner = null, RefreshTokenInterface $refresh_token = null)
    {
        $audience = $this->getConfiguration()->get('jwt_access_token_audience', null);
        $issuer = $this->getConfiguration()->get('jwt_access_token_issuer', null);

        if (!is_string($audience)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The configuration option "jwt_access_token_audience" is not set.');
        }
        if (!is_string($issuer)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The configuration option "jwt_access_token_issuer" is not set.');
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
        $key = $this->getKeyManager()->createJWK($this->getSignaturePrivateKey());

        if (!is_null($key->getKeyID())) {
            $header['kid'] = $key->getKeyID();
        }
        $instruction = new SignatureInstruction();
        $instruction->setKey($key)
            ->setProtectedHeader($header);

        return $this->getSigner()->sign($payload, [$instruction], JSONSerializationModes::JSON_COMPACT_SERIALIZATION);
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
        $header = array_merge(
            [],
            $this->prepareEncryptionHeader($client)
        );
        $public_key = $this->getKeyManager()->createJWK($this->getEncryptionPublicKey());
        $private_key = $this->getKeyManager()->createJWK($this->getEncryptionPrivateKey());

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
    public function getAccessToken($assertion)
    {
        //We load the assertion
        $jwt = $this->loadAssertion($assertion);
        if ($jwt instanceof JWEInterface) {
            $this->verifyAssertion($jwt);
            $jwt = $this->decryptAssertion($jwt);
        }
        $this->verifyAssertion($jwt);

        $access_token = new AccessToken();
        $access_token->setClientPublicId($jwt->getSubject())
            ->setExpiresAt($jwt->getExpirationTime())
            ->setToken($assertion);
        if (!is_null($resource_owner = $jwt->getPayloadValue('r_o'))) {
            $access_token->setResourceOwnerPublicId($resource_owner);
        }
        if (!is_null($scope = $jwt->getPayloadValue('sco'))) {
            $access_token->setScope($scope);
        }
        if (!is_null($refresh_token = $jwt->getPayloadValue('ref'))) {
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
     * @param $assertion
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \Jose\JWEInterface|\Jose\JWSInterface
     */
    protected function loadAssertion($assertion)
    {
        $jwt = $this->getLoader()->load($assertion);
        if (!$jwt instanceof JWEInterface && !$jwt instanceof JWSInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The assertion does not contain a single JWS or a single JWE.');
        }

        return $jwt;
    }

    /**
     * @param \Jose\JWEInterface $jwe
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \Jose\JWSInterface
     */
    protected function decryptAssertion(JWEInterface $jwe)
    {
        $key_set = $this->getKeySetManager()->createJWKSet();
        $key = $this->getKeyManager()->createJWK($this->getEncryptionPrivateKey());
        $key_set->addKey($key);

        if ($jwe->getAlgorithm() !== $this->getKeyEncryptionAlgorithm() || $jwe->getEncryptionAlgorithm() !== $this->getContentEncryptionAlgorithm()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, sprintf('Algorithm not allowed. Authorized algorithms: %s.', json_encode([$this->getKeyEncryptionAlgorithm(), $this->getContentEncryptionAlgorithm()])));
        }
        $this->getLoader()->decrypt($jwe, $key_set);

        $jws = $this->getLoader()->load($jwe->getPayload());
        if (!$jws instanceof JWSInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The encrypted assertion does not contain a single JWS.');
        }

        return $jws;
    }

    /**
     * @param \Jose\JWSInterface $jws
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function verifySignature(JWSInterface $jws)
    {
        if ($jws->getAlgorithm() !== $this->getSignatureAlgorithm()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, sprintf('Algorithm not allowed. Authorized algorithm is "%s".', $this->getSignatureAlgorithm()));
        }
        $key_set = $this->getKeySetManager()->createJWKSet();
        $key_set->addKey($this->getKeyManager()->createJWK($this->getSignaturePublicKey()));

        if (false === $this->getLoader()->verifySignature($jws, $key_set)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Invalid signature.');
        }
    }

    /**
     * @param \Jose\JWTInterface $jwt
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function verifyAssertion(JWTInterface $jwt)
    {
        foreach ($this->getRequiredClaims() as $claim) {
            if (is_null($jwt->getHeaderOrPayloadValue($claim))) {
                throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, sprintf('Claim "%s" is mandatory.', $claim));
            }
        }
        try {
            $this->getLoader()->verify($jwt);
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
        }

        $this->checkJWT($jwt);
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
