<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use Assert\Assertion;
use Psr\Http\Message\ServerRequestInterface;
use Security\DefuseGenerator;

class MacToken implements TokenTypeInterface
{
    /**
     * @var string
     */
    private $mac_key_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/';

    /**
     * @var int
     */
    private $timestamp_lifetime = 30;

    /**
     * @var string
     */
    private $mac_algorithm = 'hmac-sha-256';

    /**
     * @var int
     */
    private $mac_key_min_length = 20;

    /**
     * @var int
     */
    private $mac_key_max_length = 50;

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeName()
    {
        return 'MAC';
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeScheme()
    {
        return $this->getTokenTypeName();
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeInformation()
    {
        return [
            'token_type'    => $this->getTokenTypeName(),
            'mac_key'       => $this->generateMacKey(),
            'mac_algorithm' => $this->getMacAlgorithm(),
        ];
    }

    /**
     * @return string
     */
    private function generateMacKey()
    {
        $length = $this->getMacKeyLength();
        $charset = $this->getMacKeyCharset();

        return DefuseGenerator::getRandomString($length, $charset);
    }

    /**
     * @return int
     */
    public function getTimestampLifetime()
    {
        return $this->timestamp_lifetime;
    }

    /**
     * @param int $timestamp_lifetime
     */
    public function setTimestampLifetime($timestamp_lifetime)
    {
        Assertion::integer($timestamp_lifetime);
        Assertion::greaterThan($timestamp_lifetime, 0);
        $this->timestamp_lifetime = $timestamp_lifetime;
    }

    /**
     * @return int
     */
    private function getMacKeyLength()
    {
        $min_length = $this->getMacKeyMinLength();
        $max_length = $this->getMacKeyMaxLength();
        srand();

        return rand($min_length, $max_length);
    }

    /**
     * @return string
     */
    public function getMacKeyCharset()
    {
        return $this->mac_key_charset;
    }

    /**
     * @param string $mac_key_charset
     */
    public function setMacKeyCharset($mac_key_charset)
    {
        Assertion::string($mac_key_charset);
        $this->$mac_key_charset = $mac_key_charset;
    }

    /**
     * @return int
     */
    public function getMacKeyMinLength()
    {
        return $this->mac_key_min_length;
    }

    /**
     * @param int $mac_key_min_length
     */
    public function setMacKeyMinLength($mac_key_min_length)
    {
        Assertion::integer($mac_key_min_length);
        Assertion::greaterThan($mac_key_min_length, 0);
        Assertion::lessThan($mac_key_min_length, $this->getMacKeyMaxLength());
        $this->mac_key_min_length = $mac_key_min_length;
    }

    /**
     * @return int
     */
    public function getMacKeyMaxLength()
    {
        return $this->mac_key_max_length;
    }

    /**
     * @param int $mac_key_max_length
     */
    public function setMacKeyMaxLength($mac_key_max_length)
    {
        Assertion::integer($mac_key_max_length);
        Assertion::greaterThan($mac_key_max_length, $this->getMacKeyMinLength());
        $this->mac_key_max_length = $mac_key_max_length;
    }

    /**
     * @return string
     */
    public function getMacAlgorithm()
    {
        return $this->mac_algorithm;
    }

    /**
     * @param string $mac_algorithm
     */
    public function setMacAlgorithm($mac_algorithm)
    {
        Assertion::string($mac_algorithm);
        Assertion::inArray($mac_algorithm, array_keys($this->getAlgorithmMap()));
        $this->mac_algorithm = $mac_algorithm;
    }

    public function findToken(ServerRequestInterface $request, array &$additional_credential_values)
    {
        $authorization_headers = $request->getHeader('AUTHORIZATION');

        if (0 === count($authorization_headers)) {
            return;
        }

        foreach ($authorization_headers as $authorization_header) {
            if ('MAC ' === substr($authorization_header, 0, 4) && 1 === preg_match('/(\w+)=("((?:[^"\\\\]|\\\\.)+)"|([^\s,$]+))/', substr($authorization_header, 4), $matches)) {
                preg_match_all('/(\w+)=("((?:[^"\\\\]|\\\\.)+)"|([^\s,$]+))/', substr($authorization_header, 4), $matches, PREG_SET_ORDER);

                $values = [];
                foreach ($matches as $match) {
                    $values[$match[1]] = $match[3];
                }

                if (array_key_exists('id', $values)) {
                    $additional_credential_values = $values;

                    return $values['id'];
                }
            }
        }
    }

    public function isTokenRequestValid(AccessTokenInterface $access_token, ServerRequestInterface $request, array $additional_credential_values)
    {
        if ($access_token->getTokenType() !== $this->getTokenTypeName()) {
            return false;
        }

        if (!is_array($additional_credential_values)) {
            return false;
        }

        if (!isset($additional_credential_values['id']) || $additional_credential_values['id'] !== $access_token->getToken() || $access_token->hasExpired()) {
            return false;
        }

        if (false === $this->checkTimestampValid($additional_credential_values['ts'])) {
            return false;
        }

        $mac = $this->generateMac($request, $access_token, $additional_credential_values);

        return $mac === $additional_credential_values['mac'];
    }

    private function generateMac(ServerRequestInterface $request, AccessTokenInterface $token, array $values)
    {
        $timestamp = $values['ts'];
        $nonce = $values['nonce'];
        $method = $request->getMethod();
        $request_uri = $request->getRequestTarget();
        $host = $request->getUri()->getHost();
        $port = $request->getUri()->getPort();
        $ext = isset($values['ext']) ? $values['ext'] : null;

        $basestr =
            $timestamp."\n".
            $nonce."\n".
            $method."\n".
            $request_uri."\n".
            $host."\n".
            $port."\n".
            $ext."\n";

        $algorithms = $this->getAlgorithmMap();
        if (!array_key_exists($token->getParameter('mac_algorithm'), $algorithms)) {
            return false;
        }

        return base64_encode(hash_hmac(
            $algorithms[$token->getParameter('mac_algorithm')],
            $basestr,
            $token->getParameter('mac_key'),
            true
        ));
    }

    /**
     * @param int $timestamp
     *
     * @return bool
     */
    private function checkTimestampValid($timestamp)
    {
        if ($timestamp < time() - $this->getTimestampLifetime()) {
            return false;
        }

        return true;
    }

    /**
     * @return array
     */
    protected function getAlgorithmMap()
    {
        return [
            'hmac-sha-1'   => 'sha1',
            'hmac-sha-256' => 'sha256',
        ];
    }
}
