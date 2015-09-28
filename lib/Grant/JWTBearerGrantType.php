<?php

namespace OAuth2\Grant;

use Jose\JWEInterface;
use OAuth2\Behaviour\CanLoadJWT;
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
    use CanLoadJWT;

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
        if (null === $assertion) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "assertion" is missing.');
        }

        //We load the assertion
        $jwt = $this->loadAssertion($assertion);
        if ($jwt instanceof JWEInterface) {
            $this->verifyAssertion($jwt);
            $jwt = $this->decryptAssertion($jwt);
        }
        $this->verifyAssertion($jwt);

        $grant_type_response->setClientPublicId($jwt->getSubject())
            ->setAdditionalData('jwt', $jwt);
    }

    /**
     * {@inheritdoc}
     */
    public function grantAccessToken(ServerRequestInterface $request, ClientInterface $client, GrantTypeResponseInterface &$grant_type_response)
    {
        if (!$client instanceof JWTClientInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_CLIENT, 'The client is not a JWT client');
        }
        $jwt = $grant_type_response->getAdditionalData('jwt');

        $this->verifySignature($jwt, $client);

        $issue_refresh_token = $this->getConfiguration()->get('issue_refresh_token_with_client_credentials_grant_type', false);
        $scope = RequestBody::getParameter($request, 'scope');

        $grant_type_response->setRequestedScope($scope)
                 ->setAvailableScope(null)
                 ->setResourceOwnerPublicId($client->getPublicId())
                 ->setRefreshTokenIssued($issue_refresh_token)
                 ->setRefreshTokenScope($scope)
                 ->setRefreshTokenRevoked(null);
    }
}
