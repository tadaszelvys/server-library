<?php

namespace OAuth2\Test\Application;

use OAuth2\Model\Scope\DefaultScopePolicy;
use OAuth2\Model\Scope\ErrorScopePolicy;
use OAuth2\Model\Scope\ScopeRepository;
use OAuth2\Model\Scope\ScopeRepositoryInterface;
use OAuth2\Model\Scope\ScopePolicyInterface;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;

trait ScopeRepositoryTrait
{
    abstract public function getOAuth2ResponseFactory(): OAuth2ResponseFactoryManagerInterface;

    /**
     * @var null|ScopeRepositoryInterface
     */
    private $scopeRepository = null;

    /**
     * @var null|ScopePolicyInterface
     */
    private $scopePolicyDefault = null;

    /**
     * @var null|ScopePolicyInterface
     */
    private $scopePolicyError = null;

    /**
     * @return ScopeRepositoryInterface
     */
    public function getScopeRepository(): ScopeRepositoryInterface
    {
        if (null === $this->scopeRepository) {
            $this->scopeRepository = new ScopeRepository(
                $this->getOAuth2ResponseFactory(),
                ['data_read', 'data_write', 'openid', 'profile', 'email', 'phone', 'address', 'offline_access']
            );
            $this->scopeRepository
                ->addScopePolicy($this->getScopePolicyDefault())
                ->addScopePolicy($this->getScopePolicyError());
        }

        return $this->scopeRepository;
    }

    /**
     * @return ScopePolicyInterface
     */
    public function getScopePolicyDefault(): ScopePolicyInterface
    {
        if (null === $this->scopePolicyDefault) {
            $this->scopePolicyDefault = new DefaultScopePolicy([
                'data_read',
            ]);
        }

        return $this->scopePolicyDefault;
    }

    /**
     * @return ScopePolicyInterface
     */
    public function getScopePolicyError(): ScopePolicyInterface
    {
        if (null === $this->scopePolicyError) {
            $this->scopePolicyError = new ErrorScopePolicy();
        }

        return $this->scopePolicyError;
    }
}
