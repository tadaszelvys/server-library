<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization\ParameterChecker;

use OAuth2\Model\Client\Client;
use OAuth2\Response\OAuth2Exception;

final class ParameterCheckerManager implements ParameterCheckerManagerInterface
{
    /**
     * @var ParameterCheckerInterface[]
     */
    private $parameterCheckers = [];

    /**
     * {@inheritdoc}
     */
    public function addParameterChecker(ParameterCheckerInterface $parameterChecker): ParameterCheckerManagerInterface
    {
        $this->parameterCheckers[] = $parameterChecker;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function checkParameters(Client $client, array &$parameters)
    {
        foreach ($this->parameterCheckers as $parameterChecker) {
            try {
                $parameterChecker->checkerParameter($client, $parameters);
            } catch (\InvalidArgumentException $e) {
                throw new OAuth2Exception(400, ['error' => $parameterChecker->getError(), 'error_description' => $e->getMessage()]);
            }
        }
    }
}
