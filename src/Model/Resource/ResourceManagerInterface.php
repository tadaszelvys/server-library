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

namespace OAuth2\Model\Resource;

use OAuth2\Model\Resource\ResourceId;

interface ResourceManagerInterface
{
    /**
     * @param ResourceId $resourceId
     *
     * @return ResourceInterface|null
     */
    public function find(ResourceId $resourceId);
}
