<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization\ParameterChecker;

use OAuth2\Behaviour\HasResponseFactoryManager;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;

class ParameterCheckerManager implements ParameterCheckerManagerInterface
{
    use HasScopeManager;
    use HasResponseFactoryManager;

    /**
     * @var \OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerInterface[]
     */
    private $parameter_checkers = [];

    /**
     * ParameterCheckerManager constructor.
     *
     * @param \OAuth2\Response\OAuth2ResponseFactoryManagerInterface $response_factory_manager
     */
    public function __construct(OAuth2ResponseFactoryManagerInterface $response_factory_manager)
    {
        $this->setResponsefactoryManager($response_factory_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function addParameterChecker(ParameterCheckerInterface $parameter_checker)
    {
        $this->parameter_checkers[] = $parameter_checker;
    }

    /**
     * {@inheritdoc}
     */
    public function checkParameters(ClientInterface $client, array &$parameters)
    {
        foreach ($this->parameter_checkers as $parameter_checker) {
            try {
                $parameter_checker->checkerParameter($client, $parameters);
            } catch (\InvalidArgumentException $e) {
                throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => $parameter_checker->getError(), 'error_description' => $e->getMessage()]));
            }
        }
    }
}
