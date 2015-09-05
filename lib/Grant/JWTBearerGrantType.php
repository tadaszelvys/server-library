<?php

namespace OAuth2\Grant;

use Jose\JWEInterface;
use Jose\JWKSetManagerInterface;
use Jose\JWSInterface;
use Jose\JWTInterface;
use Jose\LoaderInterface;
use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\JWTClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

class JWTBearerGrantType implements GrantTypeSupportInterface
{
    use HasExceptionManager;
    use HasConfiguration;

    /**
     * @var \Jose\LoaderInterface
     */
    protected $jwt_loader;

    /**
     * @var \Jose\JWKSetManagerInterface
     */
    protected $key_set_manager;

    /**
     * @var string[]
     */
    protected $allowed_encryption_algorithms = [];

    /**
     * @var array
     */
    protected $private_key_set;

    /**
     * @return \Jose\JWKSetManagerInterface
     */
    public function getKeySetManager()
    {
        return $this->key_set_manager;
    }

    /**
     * @param  $key_set_manager
     *
     * @return self
     */
    public function setKeySetManager(JWKSetManagerInterface $key_set_manager)
    {
        $this->key_set_manager = $key_set_manager;

        return $this;
    }

    /**
     * @return \Jose\LoaderInterface
     */
    public function getJWTLoader()
    {
        return $this->jwt_loader;
    }

    /**
     * @param \Jose\LoaderInterface $jwt_loader
     *
     * @return self
     */
    public function setJWTLoader(LoaderInterface $jwt_loader)
    {
        $this->jwt_loader = $jwt_loader;

        return $this;
    }

    /**
     * @return array
     */
    public function getPrivateKeySet()
    {
        return $this->private_key_set;
    }

    /**
     * @param array $private_key_set
     *
     * @return self
     */
    public function setPrivateKeySet(array $private_key_set)
    {
        $this->private_key_set = $private_key_set;

        return $this;
    }

    /**
     * @return string[]
     */
    public function getAllowedEncryptionAlgorithms()
    {
        return $this->allowed_encryption_algorithms;
    }

    /**
     * @param string[] $allowed_encryption_algorithms
     *
     * @return self
     */
    public function setAllowedEncryptionAlgorithms(array $allowed_encryption_algorithms)
    {
        $this->allowed_encryption_algorithms = $allowed_encryption_algorithms;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantType()
    {
        return 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    }

    /**
     * {@inheritdoc}
     */
    public function prepareGrantTypeResponse(ServerRequestInterface $request, GrantTypeResponseInterface &$grant_type_response)
    {
        $assertion = RequestBody::getParameter($request, 'assertion');
        //We verify the client_public_id assertion exists
        if (is_null($assertion)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "assertion" is missing.');
        }

        //We load the assertion
        $jwt = $this->getJWTLoader()->load($assertion);

        if (!$jwt instanceof JWEInterface && !$jwt instanceof JWSInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "client_assertion" is not a JWS or JWE.');
        }

        $this->checkAssertion($jwt);

        $grant_type_response->setClientPublicId($jwt->getSubject());
    }

    /**
     * {@inheritdoc}
     */
    public function grantAccessToken(ServerRequestInterface $request, ClientInterface $client, GrantTypeResponseInterface &$grant_type_response)
    {
        if (!$client instanceof JWTClientInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_CLIENT, 'The client_public_id is not a confidential client');
        }
        $issue_refresh_token = $this->getConfiguration()->get('issue_refresh_token_with_client_credentials_grant_type', false);
        $scope = RequestBody::getParameter($request, 'scope');

        $grant_type_response->setRequestedScope($scope)
                 ->setAvailableScope(null)
                 ->setResourceOwnerPublicId($client->getPublicId())
                 ->setRefreshTokenIssued($issue_refresh_token)
                 ->setRefreshTokenScope($scope)
                 ->setRefreshTokenRevoked(null);
    }

    /**
     * @param \Jose\JWTInterface $jwt
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkAssertion(JWTInterface $jwt)
    {
        foreach ($this->getRequiredClaims() as $claim) {
            if (is_null($jwt->getHeaderOrPayloadValue($claim))) {
                throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, sprintf('Claim "%s" is mandatory.', $claim));
            }
        }
        try {
            $this->getJWTLoader()->verify($jwt);
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
}
