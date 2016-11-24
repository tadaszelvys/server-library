<?php

namespace OAuth2\Test\Application;

use OAuth2\Grant\AuthorizationCodeGrantType;
use OAuth2\Grant\ImplicitGrantType;

trait GrantTypesTrait
{
    /**
     * @var null|AuthorizationCodeGrantType
     */
    private $grantAuthorizationCodeGrantType = null;

    /**
     * @return AuthorizationCodeGrantType
     */
    public function getAuthorizationCodeGrantType(): AuthorizationCodeGrantType
    {
        if (null === $this->grantAuthorizationCodeGrantType) {
            $this->grantAuthorizationCodeGrantType = new AuthorizationCodeGrantType(

            );
            $this->grantAuthorizationCodeGrantType->
        }

        return $this->grantAuthorizationCodeGrantType;
    }
    /**
     * @var null|AuthorizationCodeGrantType
     */
    private $grantImplicitGrantType = null;

    /**
     * @return ImplicitGrantType
     */
    public function getImplicitGrantType(): ImplicitGrantType
    {
        if (null === $this->grantImplicitGrantType) {
            $this->grantImplicitGrantType = new ImplicitGrantType(
                $this->getTokenTypeManager(),
                $this->getAccessTokenRepository()
            );
        }

        return $this->grantImplicitGrantType;
    }



















}
