<?php

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
