<?php

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasRefreshTokenManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Token\RefreshTokenInterface;
use Psr\Http\Message\ServerRequestInterface;
use OAuth2\Util\RequestBody;

class RefreshTokenGrantType implements GrantTypeSupportInterface
{
    use HasExceptionManager;
    use HasRefreshTokenManager;

    /**
     * {@inheritdoc}
     */
    public function getGrantType()
    {
        return 'refresh_token';
    }

    /**
     * {@inheritdoc}
     */
    public function grantAccessToken(ServerRequestInterface $request, ClientInterface $client)
    {
        $refresh_token = RequestBody::getParameter($request, 'refresh_token');
        if (is_null($refresh_token)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'No "refresh_token" parameter found');
        }

        $token = $this->getRefreshTokenManager()->getRefreshToken($refresh_token);

        if (!$token instanceof RefreshTokenInterface || $token->isUsed()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_GRANT, 'Invalid refresh token');
        }

        $this->checkRefreshToken($token, $client);

        $response = new GrantTypeResponse();
        $response->setRequestedScope(RequestBody::getParameter($request, 'scope') ?: $token->getScope())
                 ->setAvailableScope($token->getScope())
                 ->setResourceOwnerPublicId($token->getResourceOwnerPublicId())
                 ->setRefreshTokenIssued(true)
                 ->setRefreshTokenScope($token->getScope())
                 ->setRefreshTokenRevoked($token);

        return $response;
    }

    /**
     * {@inheritdoc}
     */
    public function checkRefreshToken(RefreshTokenInterface $token, ClientInterface $client)
    {
        if ($client->getPublicId() !== $token->getClientPublicId()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_GRANT, 'Invalid refresh token');
        }

        if ($token->hasExpired()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_GRANT, 'Refresh token has expired');
        }
    }
}
