<?php

namespace OAuth2\Test\Stub;

use OAuth2\Exception\ExceptionManager as Base;

class ExceptionManager extends Base
{
    public function getUri($type, $error, $error_description = null, array $data = [])
    {
        if ($type !== self::INTERNAL_SERVER_ERROR) {
            return "https://foo.test/Error/$type/$error";
        }

        return "https://foo.test/Internal/$type/$error";;
    }
}
