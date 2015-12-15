<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

class AuthCode extends Token implements AuthCodeInterface
{
    /**
     * @var bool|false
     */
    protected $issue_refresh_token = false;

    /**
     * @var string
     */
    protected $redirect_uri = null;

    /**
     * @var array
     */
    protected $query_params = [];

    /**
     * {@inheritdoc}
     */
    public function getIssueRefreshToken()
    {
        return $this->issue_refresh_token;
    }

    /**
     * {@inheritdoc}
     */
    public function setIssueRefreshToken($issue_refresh_token)
    {
        $this->issue_refresh_token = $issue_refresh_token;
    }

    /**
     * {@inheritdoc}
     */
    public function getRedirectUri()
    {
        return $this->redirect_uri;
    }

    /**
     * {@inheritdoc}
     */
    public function setRedirectUri($redirect_uri)
    {
        $this->redirect_uri = $redirect_uri;
    }

    /**
     * {@inheritdoc}
     */
    public function getQueryParams()
    {
        return $this->query_params;
    }

    /**
     * {@inheritdoc}
     */
    public function setQueryParams(array $query_params)
    {
        $this->query_params = $query_params;
    }
}
