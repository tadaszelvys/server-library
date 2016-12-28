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

use OAuth2\Client\Rule\GrantTypeFlowRule;
use OAuth2\Grant\GrantTypeManagerInterface;
use OAuth2\Grant\ResponseTypeManagerInterface;

trait GrantTypeFlowRuleTrait
{
    abstract public function getGrantTypeManager(): GrantTypeManagerInterface;

    abstract public function getResponseTypeManager(): ResponseTypeManagerInterface;

    /**
     * @var null|GrantTypeFlowRule
     */
    private $grantTypeFlowRule = null;

    /**
     * @return GrantTypeFlowRule
     */
    public function getGrantTypeFlowRule(): GrantTypeFlowRule
    {
        if (null === $this->grantTypeFlowRule) {
            $this->grantTypeFlowRule = new GrantTypeFlowRule(
                $this->getGrantTypeManager(),
                $this->getResponseTypeManager()
            );
        }

        return $this->grantTypeFlowRule;
    }
}
