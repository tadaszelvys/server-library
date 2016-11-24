<?php

namespace OAuth2\Test\Application;

use OAuth2\Grant\GrantTypeManager;
use OAuth2\Grant\GrantTypeManagerInterface;

trait GrantTypeManagerTrait
{
    /**
     * @var null|GrantTypeManagerInterface
     */
    private $grantTypeManager = null;

    /**
     * @return GrantTypeManagerInterface
     */
    public function getGrantTypeManager(): GrantTypeManagerInterface
    {
        if (null === $this->grantTypeManager) {
            $this->grantTypeManager = new GrantTypeManager();
        }

        return $this->grantTypeManager;
    }
}
