<?php

namespace OAuth2\Test\Application;

use Jose\Factory\JWKFactory;
use Jose\Object\JWKSetInterface;
use OAuth2\Client\Rule\ClientIdRule;
use OAuth2\Client\Rule\CommonParametersRule;
use OAuth2\Client\Rule\GrantTypeFlowRule;
use OAuth2\Client\Rule\RedirectionUriRule;
use OAuth2\Client\Rule\RuleManager;
use OAuth2\Client\Rule\ScopeRule;
use OAuth2\Client\Rule\SoftwareRule;
use OAuth2\Model\Scope\ScopeRepositoryInterface;
use OAuth2\Test\Stub\ClientRegistrationManagementRule;

trait RuleManagerTrait
{
    abstract public function getGrantTypeFlowRule(): GrantTypeFlowRule;
    abstract public function getScopeRepository(): ScopeRepositoryInterface;

    /**
     * @var null|RuleManager
     */
    private $ruleManager = null;

    /**
     * @return RuleManager
     */
    public function getRuleManager(): RuleManager
    {
        if (null === $this->ruleManager) {
            $this->ruleManager = new RuleManager();
            $this->ruleManager
                ->appendRule(new ClientIdRule())
                ->appendRule(new ClientRegistrationManagementRule())
                ->appendRule(new CommonParametersRule())
                ->appendRule($this->getGrantTypeFlowRule())
                ->appendRule(new RedirectionUriRule())
                ->appendRule(new ScopeRule($this->getScopeRepository()))
                ->appendRule($this->getSoftwareRule());
        }

        return $this->ruleManager;
    }

    /**
     * @var null|SoftwareRule
     */
    private $softwareRule = null;

    /**
     * @return SoftwareRule
     */
    private function getSoftwareRule(): SoftwareRule
    {
        if (null === $this->softwareRule) {
            $this->softwareRule = new SoftwareRule();
            $this->softwareRule->allowRegistrationWithoutSoftwareStatement();
            $this->softwareRule->enableSoftwareStatementSupport(
                $this->getJwtLoader(),
                $this->getSoftwareStatementPublicKeys()
            );
        }

        return $this->softwareRule;
    }

    /**
     * @return JWKSetInterface
     */
    private function getSoftwareStatementPublicKeys(): JWKSetInterface
    {
        return JWKFactory::createPublicKeySet($this->getSoftwareStatementPrivateKeys());
    }

    /**
     * @var null|JWKSetInterface
     */
    private $softwareStatementPrivateKeys = null;

    /**
     * @return JWKSetInterface
     */
    public function getSoftwareStatementPrivateKeys(): JWKSetInterface
    {
        if (null === $this->softwareStatementPrivateKeys) {
            $this->softwareStatementPrivateKeys = JWKFactory::createStorableKeySet(
                tempnam(sys_get_temp_dir(), 'OAUTH2'),
                [
                    'kty' => 'EC',
                    'alg' => 'ES256',
                    'crv' => 'P-256',
                ],
                2
            );
        }

        return $this->softwareStatementPrivateKeys;
    }
}
