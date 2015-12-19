<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint;

use OAuth2\Client\ClientInterface;
use OAuth2\EndUser\EndUserInterface;

final class Authorization
{
    /**
     * @var bool
     */
    private $is_authorized;

    /**
     * @var \OAuth2\Client\ClientInterface
     */
    private $client;

    /**
     * @var \OAuth2\EndUser\EndUserInterface
     */
    private $end_user;

    /**
     * @var array
     */
    private $scopes = [];

    const DISPLAY_PAGE = 'page';
    const DISPLAY_POPUP = 'popup';
    const DISPLAY_TOUCH = 'touch';
    const DISPLAY_WAP = 'wap';

    /**
     * @return array
     */
    public function getAllowedDisplayValues()
    {
        return [
            null,
            self::DISPLAY_PAGE,
            self::DISPLAY_POPUP,
            self::DISPLAY_TOUCH,
            self::DISPLAY_WAP,
        ];
    }

    const PROMPT_NONE = 'none';
    const PROMPT_LOGIN = 'login';
    const PROMPT_CONSENT = 'consent';
    const PROMPT_SELECT_ACCOUNT = 'select_account';

    /**
     * @return array
     */
    public function getAllowedPromptValues()
    {
        return [
            null,
            self::PROMPT_NONE,
            self::PROMPT_LOGIN,
            self::PROMPT_CONSENT,
            self::PROMPT_SELECT_ACCOUNT,
        ];
    }

    /**
     * @var array
     */
    private $query_params = [];

    /**
     * Authorization constructor.
     *
     * @param array                            $query_params
     * @param \OAuth2\EndUser\EndUserInterface $end_user
     * @param bool                             $is_authorized
     * @param \OAuth2\Client\ClientInterface   $client
     * @param array                            $scopes
     */
    public function __construct(array $query_params,
                                EndUserInterface $end_user,
                                $is_authorized,
                                ClientInterface $client,
                                array $scopes = []
    )
    {
        $this->query_params = $query_params;
        $this->end_user = $end_user;
        $this->client = $client;
        $this->is_authorized = $is_authorized;
        $this->scopes = $scopes;

        $this->checkDisplay();
        $this->checkPrompt();
    }

    /**
     * @return \OAuth2\EndUser\EndUserInterface
     */
    public function getEndUser()
    {
        return $this->end_user;
    }

    /**
     * @return \OAuth2\Client\ClientInterface
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * @return array
     */
    public function getQueryParams()
    {
        return $this->query_params;
    }

    /**
     * @return array
     */
    public function getScopes()
    {
        return $this->scopes;
    }

    /**
     * @param array $scopes
     */
    public function setScopes(array $scopes)
    {
        $this->scopes = $scopes;
    }

    /**
     * @return bool
     */
    public function isAuthorized()
    {
        return $this->is_authorized;
    }

    /**
     * @param bool $is_authorized
     */
    public function setAuthorized($is_authorized)
    {
        $this->is_authorized = $is_authorized;
    }

    /**
     * @param string $param
     *
     * @return bool
     */
    public function has($param)
    {
        return array_key_exists($param, $this->query_params);
    }

    /**
     * @param string $param
     *
     * @return mixed
     */
    public function get($param)
    {
        if (!$this->has($param)) {
            throw new \InvalidArgumentException(sprintf('Invalid parameter "%s"', $param));
        }

        return $this->query_params[$param];
    }

    /**
     *
     */
    private function checkDisplay()
    {
        if ($this->has('display') && !in_array($this->get('display'), $this->getAllowedDisplayValues())) {
            throw new \InvalidArgumentException('Invalid "display" parameter. Allowed values are '.json_encode($this->getAllowedDisplayValues()));
        }
    }

    /**
     *
     */
    private function checkPrompt()
    {
        if ($this->has('prompt') && !in_array($this->get('prompt'), $this->getAllowedPromptValues())) {
            throw new \InvalidArgumentException('Invalid "prompt" parameter. Allowed values are '.json_encode($this->getAllowedPromptValues()));
        }
    }
}
