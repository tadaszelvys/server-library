<?php

namespace OAuth2\Scope;

interface ScopeInterface extends \JsonSerializable
{
    /**
     * The scope name. MUST use the following charset : 1*( %x21 / %x23-5B / %x5D-7E ).
     *
     * @return string The scope name
     */
    public function __toString();
}
