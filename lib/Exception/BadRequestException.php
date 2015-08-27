<?php

namespace OAuth2\Exception;

class BadRequestException extends BaseException implements BadRequestExceptionInterface
{
    /**
     * @param string $error             Short name of the error
     * @param string $error_description Description of the error (optional)
     * @param string $error_uri         Uri of the error (optional)
     * @param array  $data              Additional data sent to the exception (optional)
     */
    public function __construct($error, $error_description = null, $error_uri = null, array $data = array())
    {
        parent::__construct(400, $error, $error_description, $error_uri);
    }
}
