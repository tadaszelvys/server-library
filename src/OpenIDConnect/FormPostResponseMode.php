<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIDConnect;

use OAuth2\Endpoint\ResponseModeInterface;
use OAuth2\Grant\ResponseTypeSupportInterface;
use Psr\Http\Message\ResponseInterface;

class FormPostResponseMode implements ResponseModeInterface
{
    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return ResponseTypeSupportInterface::RESPONSE_TYPE_MODE_FORM_POST;
    }

    /**
     * {@inheritdoc}
     */
    public function prepareResponse($redirect_uri, array $data, ResponseInterface &$response)
    {
        $input = [];
        foreach ($data as $key => $value) {
            $input[] = sprintf('<input type="hidden" name="%s" value="%s"/>', $key, $value);
        }
        $replacements = [
            '{{redirect_uri}}' => $redirect_uri,
            '{{input}}'        => implode(PHP_EOL, $input),
        ];
        $content = str_replace(array_keys($replacements), $replacements, $this->getTemplate());

        $response->getBody()->write($content);
    }

    /**
     * @return string
     */
    protected function getTemplate()
    {
        return <<<'EOT'
<!doctype html>
<html>
<head>
<title>Authorization form</title>
</head>
<body>
<form method="post" action="{{redirect_uri}}">
{{input}}
</form>
</body>
</html>
EOT;
    }
}
