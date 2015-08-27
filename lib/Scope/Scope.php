<?php

namespace OAuth2\Scope;

abstract class Scope implements ScopeInterface
{
    public function jsonSerialize()
    {
        return $this->__toString();
    }
}
