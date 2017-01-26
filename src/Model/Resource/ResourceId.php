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

namespace OAuth2\Model\Resource;

use OAuth2\Model\Id\Id;

final class ResourceId extends Id implements \JsonSerializable
{
    /**
     * @param string $value
     *
     * @return self
     */
    public static function create(string $value): self
    {
        return new self($value);
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return $this->getValue();
    }
}
