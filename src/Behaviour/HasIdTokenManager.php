<?php

namespace OAuth2\Behaviour;

use OAuth2\Token\IdTokenManagerInterface;

trait HasIdTokenManager
{
    /**
     * @var \OAuth2\Token\IdTokenManagerInterface
     */
    private $id_token_manager;

    /**
     * @return \OAuth2\Token\IdTokenManagerInterface
     */
    protected function getIdTokenManager()
    {
        return $this->id_token_manager;
    }

    /**
     * @param \OAuth2\Token\IdTokenManagerInterface $id_token_manager
     */
    private function setIdTokenManager(IdTokenManagerInterface $id_token_manager)
    {
        $this->id_token_manager = $id_token_manager;
    }
}
