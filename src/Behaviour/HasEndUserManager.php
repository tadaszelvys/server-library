<?php

namespace OAuth2\Behaviour;

use OAuth2\EndUser\EndUserManagerInterface;

trait HasEndUserManager
{
    /**
     * @var \OAuth2\EndUser\EndUserManagerInterface
     */
    protected $end_user_manager;

    /**
     * @return \OAuth2\EndUser\EndUserManagerInterface
     */
    public function getEndUserManager()
    {
        return $this->end_user_manager;
    }

    /**
     * @param \OAuth2\EndUser\EndUserManagerInterface $end_user_manager
     *
     * @return self
     */
    public function setEndUserManager(EndUserManagerInterface $end_user_manager)
    {
        $this->end_user_manager = $end_user_manager;

        return $this;
    }
}
