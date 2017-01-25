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

namespace OAuth2\Client\Rule;

use Assert\Assertion;
use OAuth2\GrantType\GrantTypeManager;
use OAuth2\Model\UserAccount\UserAccountId;
use OAuth2\ResponseType\ResponseTypeManager;

final class GrantTypeFlowRule implements RuleInterface
{
    /**
     * @var GrantTypeManager
     */
    private $grantTypeManager;

    /**
     * @var ResponseTypeManager
     */
    private $responseTypeManager;

    /**
     * GrantTypeFlowRule constructor.
     *
     * @param GrantTypeManager    $grantTypeManager
     * @param ResponseTypeManager $responseTypeManager
     */
    public function __construct(GrantTypeManager $grantTypeManager, ResponseTypeManager $responseTypeManager)
    {
        $this->grantTypeManager = $grantTypeManager;
        $this->responseTypeManager = $responseTypeManager;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(array $commandParameters, array $validatedParameters, UserAccountId $userAccountId, callable $next)
    {
        if (!array_key_exists('grant_types', $commandParameters)) {
            $commandParameters['grant_types'] = [];
        }
        if (!array_key_exists('response_types', $commandParameters)) {
            $commandParameters['response_types'] = [];
        }
        $this->checkGrantTypes($commandParameters);
        $this->checkResponseTypes($commandParameters);

        $validatedParameters['grant_types'] = $commandParameters['grant_types'];
        $validatedParameters['response_types'] = $commandParameters['response_types'];

        return $next($commandParameters, $validatedParameters, $userAccountId);
    }

    /**
     * @param array $parameters
     *
     * @throws \InvalidArgumentException
     */
    private function checkGrantTypes(array $parameters)
    {
        Assertion::isArray($parameters['grant_types'], 'The parameter \'grant_types\' must be an array of strings.');
        Assertion::allString($parameters['grant_types'], 'The parameter \'grant_types\' must be an array of strings.');

        foreach ($parameters['grant_types'] as $grant_type) {
            $type = $this->grantTypeManager->get($grant_type);
            $associated_response_types = $type->getAssociatedResponseTypes();
            $diff = array_diff($associated_response_types, $parameters['response_types']);
            Assertion::true(empty($diff), sprintf('The grant type \'%s\' is associated with the response types \'%s\' but this response type is missing.', $type->getGrantType(), implode(', ', $diff)));
        }
    }

    /**
     * @param array $parameters
     *
     * @throws \InvalidArgumentException
     */
    private function checkResponseTypes(array $parameters)
    {
        Assertion::isArray($parameters['response_types'], 'The parameter \'response_types\' must be an array of strings.');
        Assertion::allString($parameters['response_types'], 'The parameter \'response_types\' must be an array of strings.');

        foreach ($parameters['response_types'] as $response_type) {
            $types = $this->responseTypeManager->find($response_type);
            foreach ($types as $type) {
                $associated_grant_types = $type->getAssociatedGrantTypes();
                $diff = array_diff($associated_grant_types, $parameters['grant_types']);
                Assertion::true(empty($diff), sprintf('The response type \'%s\' is associated with the grant types \'%s\' but this response type is missing.', $type->getResponseType(), implode(', ', $diff)));
            }
        }
    }
}
