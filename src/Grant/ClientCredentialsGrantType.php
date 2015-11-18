<?php

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ConfidentialClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

class ClientCredentialsGrantType implements GrantTypeSupportInterface
{
    use HasExceptionManager;
    use HasConfiguration;

    /**
     * {@inheritdoc}
     */
    public function getGrantType()
    {
        return 'client_credentials';
    }

    /**
     * {@inheritdoc}
     */
    public function prepareGrantTypeResponse(ServerRequestInterface $request, GrantTypeResponseInterface &$grant_type_response)
    {
        // Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function grantAccessToken(ServerRequestInterface $request, ClientInterface $client, GrantTypeResponseInterface &$grant_type_response)
    {
        if (!$client instanceof ConfidentialClientInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_CLIENT, 'The client is not a confidential client');
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
}
