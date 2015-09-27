<?php

namespace OAuth2\Endpoint;

class Authorization
{
    /**
     * @var null|\OAuth2\Client\ClientInterface
     */
    protected $client = null;

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

    /**
     * @var null|string
     */
    protected $prompt = null;

    const PROMPT_NONE ='none';
    const PROMPT_LOGIN ='login';
    const PROMPT_CONSENT ='consent';
    const PROMPT_SELECT_ACCOUNT = 'select_account';

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
