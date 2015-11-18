<?php

namespace OAuth2\EndUser;

interface EndUserManagerInterface
{
    /**
     * Check if the end-user password is valid.
     *
     * @param \OAuth2\EndUser\EndUserInterface $end_user The end-user
     * @param string                           $password Password
     *
     * @return bool
     */
    public function checkEndUserPasswordCredentials(EndUserInterface $end_user, $password);

    /**
     * Get the end-user with the specified username.
     *
     * @param string $username Username
     *
     * @return \OAuth2\EndUser\EndUserInterface|null
     */
    public function getEndUser($username);
}
