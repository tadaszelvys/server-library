<?php

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasEndUserManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\EndUser\EndUserInterface;
use OAuth2\EndUser\EndUserManagerInterface;
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
     * ResourceOwnerPasswordCredentialsGrantType constructor.
     *
     * @param \OAuth2\EndUser\EndUserManagerInterface      $end_user_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface  $exception_manager
     * @param \OAuth2\Configuration\ConfigurationInterface $configuration
     */
    public function __construct(
        EndUserManagerInterface $end_user_manager,
        ExceptionManagerInterface $exception_manager,
        ConfigurationInterface $configuration
    )
    {
        $this->setEndUserManager($end_user_manager);
        $this->setExceptionManager($exception_manager);
        $this->setConfiguration($configuration);
    }

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

        $grant_type_response->setRequestedScope($scope);
        $grant_type_response->setAvailableScope(null);
        $grant_type_response->setResourceOwnerPublicId($end_user->getPublicId());
        $grant_type_response->setRefreshTokenIssued($this->getIssueRefreshToken($client, $end_user, $request));
        $grant_type_response->setRefreshTokenScope($scope);
        $grant_type_response->setRefreshTokenRevoked(null);
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
