<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization;

use Jose\JWTLoader;
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
     * @param \Jose\JWTLoader $jwt_loader
     */
    public function enableRequestObjectSupport(JWTLoader $jwt_loader);

    /**
     * @return mixed
     */
    public function enableRequestObjectReferenceSupport();

    /**
     * @param \Jose\Object\JWKSetInterface $key_encryption_key_set
     */
    public function enableEncryptedRequestObjectSupport(JWKSetInterface $key_encryption_key_set);

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
