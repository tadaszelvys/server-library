<?php

namespace OAuth2\Token;


use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class AccessTokenTypeManager implements AccessTokenTypeManagerInterface
{
    use HasExceptionManager;

    /**
     * @var \OAuth2\Token\AccessTokenTypeInterface[]
     */
    private $access_token_types = [];

    /**
     * @var null|string
     */
    private $default_access_token_type = null;

    public function addAccessTokenType(AccessTokenTypeInterface $access_token_type, $default = false)
    {
        if (array_key_exists($access_token_type->getScheme(), $this->access_token_types)) {
            $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, sprintf("Scheme '%s' already defined.", $access_token_type->getScheme()));
            throw $exception;
        }
        $this->access_token_types[$access_token_type->getScheme()] = $access_token_type;
        if (is_null($this->default_access_token_type) || true === $default) {
            $this->default_access_token_type = $access_token_type->getScheme();
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function findAccessToken(ServerRequestInterface $request, AccessTokenTypeInterface &$access_token_type = null)
    {
        foreach($this->access_token_types as $type) {
            if (null !== $token = $type->findAccessToken($request)) {
                $access_token_type = $type;
                return $token;
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getDefaultAccessTokenType()
    {
        if (is_null($this->default_access_token_type) || !array_key_exists($this->default_access_token_type, $this->access_token_types)) {
            $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'No access token type defined or invalid access token type.');
            throw $exception;
        }
        return $this->access_token_types[$this->default_access_token_type];
    }
}
