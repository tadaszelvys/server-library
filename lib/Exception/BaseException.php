<?php

namespace OAuth2\Exception;

use Psr\Http\Message\ResponseInterface;

class BaseException extends \Exception implements BaseExceptionInterface
{
    /**
     * @var array
     */
    protected $errorData = [];

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

    /**
     * @return null|string
     */
    public function getDescription()
    {
        return isset($this->errorData['error_description']) ? $this->errorData['error_description'] : null;
    }

    /**
     * @return null|string
     */
    public function getUri()
    {
        return isset($this->errorData['error_uri']) ? urldecode($this->errorData['error_uri']) : null;
    }

    /**
     * @param \Psr\Http\Message\ResponseInterface $response
     */
    public function getHttpResponse(ResponseInterface &$response)
    {
        $response->getBody()->write($this->getResponseBody());
        $response = $response->withStatus($this->getHttpCode());
        foreach($this->getResponseHeaders() as $header => $value) {
            $response = $response->withHeader($header, $value);
        }
    }

    /**
     * @return int
     */
    public function getHttpCode()
    {
        return $this->getCode();
    }

    /**
     * @return array
     */
    public function getResponseHeaders()
    {
        return [
            'Content-Type'  => 'application/json',
            'Cache-Control' => 'no-store',
            'Pragma'        => 'no-cache',
        ];
    }

    /**
     * @return string
     */
    public function getResponseBody()
    {
        return json_encode($this->errorData);
    }
}
