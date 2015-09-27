<?php

namespace OAuth2\Endpoint;

/**
 * @method null|\OAuth2\Client\ClientInterface getClient()
 * @method self setClient(null|\OAuth2\Client\ClientInterface $client)
 * @method null|\OAuth2\ResourceOwner\ResourceOwnerInterface getResourceOwner()
 * @method self setResourceOwner(null|\OAuth2\ResourceOwner\ResourceOwnerInterface $client)
 * @method null|string getResponseType()
 * @method self setResponseType(string $response_type)
 * @method null|string getRedirectUri()
 * @method self setRedirectUri(string $redirect_uri)
 * @method null|string getScope()
 * @method self setScope(string $scope)
 * @method null|string getState()
 * @method self setState(string $state)
 * @method bool isAuthorized()
 * @method self setAuthorized(bool $authorized)
 * @method bool getIssuerRefreshToken()
 * @method self setIssuerRefreshToken(bool $issue_refresh_token)
 * @method null|string getResponseMode()
 * @method self setResponseMode(string $response_mode)
 * @method null|string getNonce()
 * @method self setNonce(string $nonce)
 * @method null|string getDisplay()
 * @method self setDisplay(string $display)
 * @method null|string getPrompt()
 * @method self setPrompt(string $prompt)
 * @method null|int getMaxAge()
 * @method self setMaxAge(int $max_age)
 * @method null|string getUiLocales()
 * @method self setUiLocales(string $ui_locales)
 * @method null|string getIdTokenHint()
 * @method self setIdTokenHint(string $id_token_hint)
 * @method null|string getLoginHint()
 * @method self setLoginHint(string $login_hint)
 * @method null|string getAcrValues()
 * @method self setAcrValues(string $acr_values)
 */

class Authorization
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
     * @var null|\OAuth2\ResourceOwner\ResourceOwnerInterface
     */
    protected $resource_owner = null;

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

    const PROMPT_NONE ='none';
    const PROMPT_LOGIN ='login';
    const PROMPT_CONSENT ='consent';
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

                return $this;
            }
        }
        throw new \BadMethodCallException('Unknown method "'.$method.'""');
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
                preg_split('/([A-Z]{1}[^A-Z]*)/', $cameled, -1, PREG_SPLIT_DELIM_CAPTURE|PREG_SPLIT_NO_EMPTY)));
    }
}
