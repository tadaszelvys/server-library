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

/**
 * @method string getClientId()
 * @method setClientId(string $client_id)
 * @method \OAuth2\Client\ClientInterface getClient()
 * @method setClient(\OAuth2\Client\ClientInterface $client)
 * @method \OAuth2\EndUser\EndUserInterface getEndUser()
 * @method setEndUser(\OAuth2\EndUser\EndUserInterface $end_user)
 * @method null|string getResponseType()
 * @method setResponseType(string $response_type)
 * @method null|string getRedirectUri()
 * @method setRedirectUri(string $redirect_uri)
 * @method string[] getScope()
 * @method setScope(string[] $scope)
 * @method null|string getState()
 * @method setState(string $state)
 * @method bool isAuthorized()
 * @method setAuthorized(bool $authorized)
 * @method bool getIssueRefreshToken()
 * @method setIssueRefreshToken(bool $issue_refresh_token)
 * @method null|string getResponseMode()
 * @method setResponseMode(string $response_mode)
 * @method null|string getNonce()
 * @method setNonce(string $nonce)
 * @method null|string getDisplay()
 * @method setDisplay(string $display)
 * @method null|string getPrompt()
 * @method setPrompt(string $prompt)
 * @method null|int getMaxAge()
 * @method setMaxAge(int $max_age)
 * @method null|string getUiLocales()
 * @method setUiLocales(string $ui_locales)
 * @method null|string getIdTokenHint()
 * @method setIdTokenHint(string $id_token_hint)
 * @method null|string getLoginHint()
 * @method setLoginHint(string $login_hint)
 * @method null|string getAcrValues()
 * @method setAcrValues(string $acr_values)
 * @method array getQueryParams()
 * @method setQueryParams(array $query_params)
 */
final class Authorization
{
    /**
     * @var null|\OAuth2\Client\ClientInterface
     */
    protected $client = null;

    /**
     * @var null|string
     */
    protected $client_id = null;

    /**
     * @var null|string
     */
    protected $response_type = null;

    /**
     * @var null|string
     */
    protected $redirect_uri = null;

    /**
     * @var null|\OAuth2\EndUser\EndUserInterface
     */
    protected $end_user = null;

    /**
     * @var array
     */
    protected $scope = [];

    /**
     * @var null|string
     */
    protected $state = null;

    /**
     * @var bool
     */
    protected $issue_refresh_token = false;

    /**
     * @var bool
     */
    protected $authorized = false;

    /**
     * @var null|string
     */
    protected $response_mode = null;

    /**
     * @var null|string
     */
    protected $nonce = null;

    /**
     * @var array
     */
    protected $claims = [];

    /**
     * @var null|int
     */
    protected $max_age = null;

    /**
     * @var null|string
     */
    protected $display = null;

    const DISPLAY_PAGE = 'page';
    const DISPLAY_POPUP = 'popup';
    const DISPLAY_TOUCH = 'touch';
    const DISPLAY_WAP = 'wap';

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

    /**
     * @var null|string
     */
    protected $prompt = null;

    const PROMPT_NONE = 'none';
    const PROMPT_LOGIN = 'login';
    const PROMPT_CONSENT = 'consent';
    const PROMPT_SELECT_ACCOUNT = 'select_account';

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
     * @var null|string
     */
    protected $ui_locales = null;

    /**
     * @var null|string
     */
    protected $id_token_hint = null;

    /**
     * @var null|string
     */
    protected $login_hint = null;

    /**
     * @var null|string
     */
    protected $acr_values = null;

    /**
     * @var array
     */
    protected $query_params = [];

    /**
     * @param       $method
     * @param array $arguments
     *
     * @return mixed
     */
    public function __call($method, array $arguments)
    {
        if (method_exists($this, $method)) {
            return call_user_func_array([$this, $method], $arguments);
        }

        if (0 === strpos($method, 'get')) {
            $param = $this->underscore(substr($method, 3));
            if (property_exists($this, $param)) {
                return $this->$param;
            }
        } elseif (0 === strpos($method, 'is')) {
            $param = $this->underscore(substr($method, 2));
            if (property_exists($this, $param)) {
                return $this->$param;
            }
        } elseif (0 === strpos($method, 'set')) {
            $param = $this->underscore(substr($method, 3));
            if (property_exists($this, $param)) {
                if (count($arguments) !== 1) {
                    throw new \InvalidArgumentException('Only one argument allowed');
                }
                $this->$param = $arguments[0];

                return;
            }
        }
        throw new \BadMethodCallException(sprintf('Unknown method "%s"', $method));
    }

    /**
     * @param string $cameled
     *
     * @return string
     */
    private function underscore($cameled)
    {
        return implode(
            '_',
            array_map(
                'strtolower',
                preg_split('/([A-Z]{1}[^A-Z]*)/', $cameled, -1, PREG_SPLIT_DELIM_CAPTURE | PREG_SPLIT_NO_EMPTY)));
    }
}
