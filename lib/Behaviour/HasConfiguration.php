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
     * {@inheritdoc}
     */
    public function getConfiguration()
    {
        return $this->configuration;
    }

    /**
     * @param \OAuth2\Configuration\ConfigurationInterface $configuration
     *
     * @return self
     */
    public function setConfiguration(ConfigurationInterface $configuration)
    {
        $this->configuration = $configuration;

        return $this;
    }
}
