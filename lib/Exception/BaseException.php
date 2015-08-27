<?php

namespace OAuth2\Exception;

use Symfony\Component\HttpFoundation\Response;

abstract class BaseException extends \Exception implements BaseExceptionInterface
{
    protected $errorData = array();

    /**
     * @param string $code              HTTP error code
     * @param string $error             Short name of the error
     * @param string $error_description Description of the error (optional)
     * @param string $error_uri         Uri of the error (optional)
     */
    public function __construct($code, $error, $error_description = null, $error_uri = null)
    {
        parent::__construct($error, $code);

        //Check %x20-21 / %x23-5B / %x5D-7E for error and error_description
        //Check %x21 / %x23-5B / %x5D-7E for error_uri
        $this->errorData['error'] = $error;
        if (!is_null($error_description)) {
            $this->errorData['error_description'] = $error_description;
        }
        if (!is_null($error_uri)) {
            $this->errorData['error_uri'] = urlencode($error_uri);
        }
    }

    public function getDescription()
    {
        return isset($this->errorData['error_description']) ? $this->errorData['error_description'] : null;
    }

    public function getUri()
    {
        return isset($this->errorData['error_uri']) ? urldecode($this->errorData['error_uri']) : null;
    }

    public function getHttpResponse()
    {
        return new Response(
            $this->getResponseBody(),
            $this->getHttpCode(),
            $this->getResponseHeaders()
        );
    }

    public function getHttpCode()
    {
        return $this->getCode();
    }

    public function getResponseHeaders()
    {
        return array(
            'Content-Type' => 'application/json',
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        );
    }

    public function getResponseBody()
    {
        return json_encode($this->errorData);
    }
}
