<?php

namespace OAuth2\Test\Application;

use OAuth2\Grant\ResponseTypeManager;
use OAuth2\Grant\ResponseTypeManagerInterface;

trait ResponseTypeManagerTrait
{
    /**
     * @var null|ResponseTypeManagerInterface
     */
    private $responseTypeManager = null;

    /**
     * @return ResponseTypeManagerInterface
     */
    public function getResponseTypeManager(): ResponseTypeManagerInterface
    {
        if (null === $this->responseTypeManager) {
            $this->responseTypeManager = new ResponseTypeManager();
        }

        return $this->responseTypeManager;
    }
}
