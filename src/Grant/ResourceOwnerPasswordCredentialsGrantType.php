<?php

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasEndUserManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\EndUser\EndUserInterface;
use OAuth2\EndUser\IssueRefreshTokenExtensionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

final class ResourceOwnerPasswordCredentialsGrantType implements GrantTypeSupportInterface
{
    use HasExceptionManager;
    use HasConfiguration;
    use HasEndUserManager;

    /**
     * {@inheritdoc}
     */
    public function getGrantType()
    {
        return 'password';
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
        $username = RequestBody::getParameter($request, 'username');
        $password = RequestBody::getParameter($request, 'password');

        $end_user = $this->getEndUserManager()->getEndUser($username);
        if (null === $end_user || !$this->getEndUserManager()->checkEndUserPasswordCredentials($end_user, $password)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_GRANT, 'Invalid username and password combination');
        }

        $scope = RequestBody::getParameter($request, 'scope');

        $grant_type_response->setRequestedScope($scope)
                 ->setAvailableScope(null)
                 ->setResourceOwnerPublicId($end_user->getPublicId())
                 ->setRefreshTokenIssued($this->getIssueRefreshToken($client, $end_user, $request))
                 ->setRefreshTokenScope($scope)
                 ->setRefreshTokenRevoked(null);
    }

    /**
     * @param \OAuth2\Client\ClientInterface           $client
     * @param \OAuth2\EndUser\EndUserInterface         $end_user
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return bool
     */
    protected function getIssueRefreshToken(ClientInterface $client, EndUserInterface $end_user, ServerRequestInterface $request)
    {
        if ($end_user instanceof IssueRefreshTokenExtensionInterface && false === $end_user->isRefreshTokenIssuanceAllowed($client, 'password')) {
            return false;
        }

        return $this->getConfiguration()->get('allow_refresh_token_with_resource_owner_grant_type', true);
    }
}
