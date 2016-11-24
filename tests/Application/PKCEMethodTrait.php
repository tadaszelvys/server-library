<?php

namespace OAuth2\Test\Application;

use OAuth2\Grant\PKCEMethod\PKCEMethodInterface;
use OAuth2\Grant\PKCEMethod\PKCEMethodManager;
use OAuth2\Grant\PKCEMethod\PKCEMethodManagerInterface;
use OAuth2\Grant\PKCEMethod\Plain;
use OAuth2\Grant\PKCEMethod\S256;

trait PKCEMethodTrait
{
    /**
     * @var null|PKCEMethodManagerInterface
     */
    private $pkceMethodManager = null;

    /**
     * @var null|PKCEMethodInterface
     */
    private $pkceMethodPlain = null;

    /**
     * @var null|PKCEMethodInterface
     */
    private $pkceMethodS256 = null;

    /**
     * @return PKCEMethodManagerInterface
     */
    public function getPKCEMethodManager(): PKCEMethodManagerInterface
    {
        if (null === $this->pkceMethodManager) {
            $this->pkceMethodManager = new PKCEMethodManager();
            $this->pkceMethodManager
                ->addPKCEMethod($this->getPKCEMethodPlain())
                ->addPKCEMethod($this->getPKCEMethodS256());
        }

        return $this->pkceMethodManager;
    }

    /**
     * @return PKCEMethodInterface
     */
    protected function getPKCEMethodPlain(): PKCEMethodInterface
    {
        if (null === $this->pkceMethodPlain) {
            $this->pkceMethodPlain = new Plain();
        }

        return $this->pkceMethodPlain;
    }

    /**
     * @return PKCEMethodInterface
     */
    protected function getPKCEMethodS256(): PKCEMethodInterface
    {
        if (null === $this->pkceMethodS256) {
            $this->pkceMethodS256 = new S256();
        }

        return $this->pkceMethodS256;
    }
}
