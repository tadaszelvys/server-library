<?php

namespace OAuth2\Test\Application;

use OAuth2\Middleware\InitialAccessTokenMiddleware;
use OAuth2\Model\InitialAccessToken\InitialAccessTokenRepositoryInterface;
use OAuth2\Test\Stub\InitialAccessTokenRepository;
use OAuth2\TokenType\BearerToken;

trait InitialAccessTokenTrait
{
    /**
     * @var null|InitialAccessTokenRepositoryInterface
     */
    private $initialAccessTokenRepository = null;

    /**
     * @var null|InitialAccessTokenMiddleware
     */
    private $initialAccessTokenMiddleware = null;

    /**
     * @return InitialAccessTokenMiddleware
     */
    public function getInitialAccessTokenMiddleware(): InitialAccessTokenMiddleware
    {
        if (null === $this->initialAccessTokenMiddleware) {
            $this->initialAccessTokenMiddleware = new InitialAccessTokenMiddleware(
                new BearerToken(),
                $this->getInitialAccessTokenRepository()
            );
        }

        return $this->initialAccessTokenMiddleware;
    }

    /**
     * @return InitialAccessTokenRepositoryInterface
     */
    public function getInitialAccessTokenRepository(): InitialAccessTokenRepositoryInterface
    {
        if (null === $this->initialAccessTokenRepository) {
            $this->initialAccessTokenRepository = new InitialAccessTokenRepository();
        }

        return $this->initialAccessTokenRepository;
    }
}
