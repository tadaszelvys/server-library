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

namespace OAuth2\Command;

use OAuth2\DataTransporter;

abstract class CommandWithDataTransporter
{
    /**
     * @var DataTransporter
     */
    private $dataTransporter;

    /**
     * CommandWithDataTransporter constructor.
     *
     * @param DataTransporter|null $dataTransporter
     */
    protected function __construct(DataTransporter $dataTransporter = null)
    {
        $this->dataTransporter = $dataTransporter;
    }

    /**
     * @return null|DataTransporter
     */
    public function getDataTransporter()
    {
        return $this->dataTransporter;
    }
}
