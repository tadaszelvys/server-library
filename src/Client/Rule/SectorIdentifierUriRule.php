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
use Http\Client\HttpClient;
use Interop\Http\Factory\RequestFactoryInterface;
use OAuth2\Model\UserAccount\UserAccountId;
use Webmozart\Json\JsonDecoder;

final class SectorIdentifierUriRule implements RuleInterface
{
    /**
     * @var \Http\Client\HttpClient
     */
    private $client;

    /**
     * @var RequestFactoryInterface
     */
    private $requestFactory;

    /**
     * @var JsonDecoder
     */
    private $decoder;

    /**
     * @var bool
     */
    private $allow_http_connections;

    /**
     * SectorIdentifierUriRule constructor.
     *
     * @param RequestFactoryInterface $requestFactory
     * @param JsonDecoder             $decoder
     * @param HttpClient              $client
     * @param bool                    $allow_http_connections
     */
    public function __construct(RequestFactoryInterface $requestFactory, JsonDecoder $decoder, HttpClient $client, bool $allow_http_connections = false)
    {
        $this->requestFactory = $requestFactory;
        $this->decoder = $decoder;
        $this->client = $client;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(array $command_parameters, array $validated_parameters, UserAccountId $userAccountId, callable $next)
    {
        if (array_key_exists('sector_identifier_uri', $command_parameters)) {
            Assertion::url($command_parameters['sector_identifier_uri'], sprintf('The sector identifier URI \'%s\' is not valid.', $command_parameters['sector_identifier_uri']));
            $this->checkSectorIdentifierUri($command_parameters['sector_identifier_uri']);
            $validated_parameters['sector_identifier_uri'] = $command_parameters['sector_identifier_uri'];
        }

        return $next($command_parameters, $validated_parameters, $userAccountId);
    }

    /**
     * @param string $url
     *
     * @throws \InvalidArgumentException
     */
    private function checkSectorIdentifierUri($url)
    {
        $allowed_protocols = ['https'];
        if (true === $this->allow_http_connections) {
            $allowed_protocols[] = 'http';
        }
        Assertion::inArray(mb_substr($url, 0, mb_strpos($url, '://', 0, '8bit'), '8bit'), $allowed_protocols, sprintf('The provided sector identifier URI is not valid: scheme must be one of the following: %s.', implode(', ', $allowed_protocols)));
        $request = $this->requestFactory->createRequest('GET', $url);
        $response = $this->client->sendRequest($request);
        Assertion::eq(200, $response->getStatusCode(), sprintf('Unable to get Uris from the Sector Identifier Uri \'%s\'.', $url));

        $body = $response->getBody()->getContents();
        $data = $this->decoder->decode($body);
        Assertion::isArray($data, 'The provided sector identifier URI is not valid: bad response.');
        Assertion::notEmpty($data, 'The provided sector identifier URI is not valid: it must contain at least one URI.');
        foreach ($data as $sector_url) {
            Assertion::url($sector_url, 'The provided sector identifier URI is not valid: it must contain only URIs.');
            Assertion::inArray(mb_substr($sector_url, 0, mb_strpos($sector_url, '://', 0, '8bit'), '8bit'), $allowed_protocols, sprintf('An URL provided in the sector identifier URI is not valid: scheme must be one of the following: %s.', implode(', ', $allowed_protocols)));
        }
    }
}
