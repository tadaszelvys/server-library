<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Behaviour;

use OAuth2\Configuration\ConfigurationInterface;

trait HasConfiguration
{
    /**
     * @var \OAuth2\Configuration\ConfigurationInterface
     */
    private $configuration;

    /**
     * @return \OAuth2\Configuration\ConfigurationInterface
     */
    protected function getConfiguration()
    {
        return $this->configuration;
    }

    /**
     * @param \OAuth2\Configuration\ConfigurationInterface $configuration
     */
    private function setConfiguration(ConfigurationInterface $configuration)
    {
        $this->configuration = $configuration;
    }
}
