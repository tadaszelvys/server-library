<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization;

use Http\Client\HttpClient;
use Jose\JWTLoaderInterface;
use Jose\Object\JWKSetInterface;
use Psr\Http\Message\ServerRequestInterface;

interface AuthorizationRequestLoaderInterface
{
    /**
     * @return bool
     */
    public function isRequestObjectSupportEnabled();

    /**
     * @return bool
     */
    public function isRequestObjectReferenceSupportEnabled();

    /**
     * {@inheritdoc}
     */
    public function getSupportedSignatureAlgorithms();

    /**
     * {@inheritdoc}
     */
    public function getSupportedKeyEncryptionAlgorithms();

    /**
     * {@inheritdoc}
     */
    public function getSupportedContentEncryptionAlgorithms();

    /**
     * @param \Jose\JWTLoaderInterface $jwt_loader
     * @param string[]                 $mandatory_claims
     */
    public function enableRequestObjectSupport(JWTLoaderInterface $jwt_loader, array $mandatory_claims = []);

    /**
     * @param \Http\Client\HttpClient $client
     */
    public function enableRequestObjectReferenceSupport(HttpClient $client);

    /**
     * @param \Jose\Object\JWKSetInterface $key_encryption_key_set
     * @param bool                         $require_encryption
     */
    public function enableEncryptedRequestObjectSupport(JWKSetInterface $key_encryption_key_set, $require_encryption);

    /**
     * @return bool
     */
    public function isEncryptedRequestsSupportEnabled();

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return array
     */
    public function loadParametersFromRequest(ServerRequestInterface $request);
}
