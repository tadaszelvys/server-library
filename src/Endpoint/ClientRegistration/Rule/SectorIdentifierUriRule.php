<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\ClientRegistration\Rule;

use Assert\Assertion;
use GuzzleHttp\Client;

final class SectorIdentifierUriRule implements ParameterRuleInterface
{
    /**
     * @var bool
     */
    private $allow_http_connections = false;

    /**
     * @var bool
     */
    private $allow_unsecured_connections = false;

    /**
     * {@inheritdoc}
     */
    public function allowHttpConnections()
    {
        $this->allow_http_connections = true;
    }

    /**
     * {@inheritdoc}
     */
    public function disallowHttpConnections()
    {
        $this->allow_http_connections = false;
    }

    /**
     * {@inheritdoc}
     */
    public function allowUnsecuredConnections()
    {
        $this->allow_unsecured_connections = true;
    }

    /**
     * {@inheritdoc}
     */
    public function disallowUnsecuredConnections()
    {
        $this->allow_unsecured_connections = false;
    }

    /**
     * {@inheritdoc}
     */
    public function checkParameters(array $registration_parameters, array &$metadatas, array $previous_metadata = [])
    {
        if (!array_key_exists('sector_identifier_uri', $registration_parameters)) {
            return;
        }

        Assertion::url($registration_parameters['sector_identifier_uri'], sprintf('The sector identifier URI "%s" is not valid.', $registration_parameters['sector_identifier_uri']));
        $this->checkSectorIdentifierUri($registration_parameters['sector_identifier_uri']);

        $metadatas['sector_identifier_uri'] = $registration_parameters['sector_identifier_uri'];
    }

    /**
     * @param string $url
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     *
     * @return string
     */
    private function checkSectorIdentifierUri($url)
    {
        $allowed_protocols = ['https'];
        if (true === $this->allow_http_connections) {
            $allowed_protocols[] = 'http';
        }
        Assertion::inArray(mb_substr($url, 0, mb_strpos($url, '://', 0, '8bit'), '8bit'), $allowed_protocols, sprintf('The provided sector identifier URI is not valid: scheme must be one of the following: %s.', json_encode($allowed_protocols)));
        $client = new Client([
            'verify' => !$this->allow_unsecured_connections,
        ]);
        $response = $client->get($url);
        Assertion::eq(200, $response->getStatusCode());

        $body = $response->getBody()->getContents();
        $data = json_decode($body, true);
        Assertion::isArray($data, 'The provided sector identifier URI is not valid: bad response.');
        Assertion::notEmpty($data, 'The provided sector identifier URI is not valid: it must contain at least one URI.');
        foreach ($data as $sector_url) {
            Assertion::url($sector_url, 'The provided sector identifier URI is not valid: it must contain only URIs.');
            Assertion::inArray(mb_substr($sector_url, 0, mb_strpos($sector_url, '://', 0, '8bit'), '8bit'), $allowed_protocols, sprintf('An URL provided in the sector identifier URI is not valid: scheme must be one of the following: %s.', json_encode($allowed_protocols)));
        }
    }
}
