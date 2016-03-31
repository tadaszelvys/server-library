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

use OAuth2\ResourceOwner\ResourceOwnerTrait;

/**
 * Class Client.
 *
 * This class is used for every client types.
 * A client is a resource owner with a set of allowed grant types and can perform requests against
 * available endpoints.
 */
class Client implements ClientInterface
{
    use ResourceOwnerTrait;
    use ClientTrait;
}
