<?php

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ConfidentialClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Util\RequestBody;

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
    public function grantAccessToken(Request $request, ClientInterface $client)
    {
        if (!$client instanceof ConfidentialClientInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_CLIENT, 'The client is not a confidential client');
        }
        $issue_refresh_token = $this->getConfiguration()->get('issue_refresh_token_with_client_credentials_grant_type', false);
        $scope = RequestBody::getParameter($request, 'scope');

        $response = new GrantTypeResponse();
        $response->setRequestedScope($scope)
                 ->setAvailableScope(null)
                 ->setResourceOwnerPublicId($client->getPublicId())
                 ->setRefreshTokenIssued($issue_refresh_token)
                 ->setRefreshTokenScope($scope)
                 ->setRefreshTokenRevoked(null);

        return $response;
    }
}
