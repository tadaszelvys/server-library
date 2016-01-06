<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

/**
 * This interface is for confidential clients.
 * You can create confidential clients using this interface.
 *
 * @see http://tools.ietf.org/html/rfc6749#section-2.1
 */
interface ConfidentialClientInterface extends RegisteredClientInterface
{
}
