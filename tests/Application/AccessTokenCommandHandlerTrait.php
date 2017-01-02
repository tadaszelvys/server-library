<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Application;

use OAuth2\Command\AccessToken\RevokeAccessTokenCommandHandler;
use OAuth2\Model\AccessToken\AccessTokenRepositoryInterface;
use SimpleBus\Message\Recorder\PublicMessageRecorder;

trait AccessTokenCommandHandlerTrait
{
    abstract public function getAccessTokenRepository(): AccessTokenRepositoryInterface;

    abstract public function getPublicMessageRecorder(): PublicMessageRecorder;

    /**
     * @var null|RevokeAccessTokenCommandHandler
     */
    private $revokeAccessTokenCommandHandler = null;

    /**
     * @return RevokeAccessTokenCommandHandler
     */
    public function getRevokeAccessTokenCommandHandler(): RevokeAccessTokenCommandHandler
    {
        if (null === $this->revokeAccessTokenCommandHandler) {
            $this->revokeAccessTokenCommandHandler = new RevokeAccessTokenCommandHandler(
                $this->getAccessTokenRepository(),
                $this->getPublicMessageRecorder()
            );
        }

        return $this->revokeAccessTokenCommandHandler;
    }
}
