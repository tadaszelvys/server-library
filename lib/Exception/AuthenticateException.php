<?php

namespace OAuth2\Exception;

class AuthenticateException extends BaseException implements AuthenticateExceptionInterface
{
    protected $header;

    /**
     * @param string $error             Short name of the error
     * @param string $error_description Description of the error (optional)
     * @param string $error_uri         Uri of the error (optional)
     * @param array  $data              Additional data sent to the exception (optional)
     */
    public function __construct($error, $error_description = null, $error_uri = null, array $data = array())
    {
        parent::__construct(401, $error, $error_description, $error_uri);

        if (!isset($data['scheme'])) {
            throw new \InvalidArgumentException('scheme_not_defined');
        }

        $headers = $data['scheme'].' ';
        unset($data['scheme']);
        $params = array();
        foreach ($data as $key => $value) {
            $params[] = sprintf('%s=%s', $key, $this->quote($value));
        }
        $headers .= implode(',', $params);

        $this->header = array('WWW-Authenticate' => $headers);
    }

    public function getResponseHeaders()
    {
        return $this->header + parent::getResponseHeaders();
    }

    public function getResponseBody()
    {
    }

    protected function quote($text)
    {
        // Reference to IETF Draft must be updated
        // https://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-17#section-3.2.3
        $text = preg_replace(
            '~
                        [^
                            \x21-\x7E
                            \x80-\xFF
                            \ \t
                        ]
                        ~x',
            '',
            $text
        );

        $text = addcslashes($text, '"\\');

        return '"'.$text.'"';
    }
}
