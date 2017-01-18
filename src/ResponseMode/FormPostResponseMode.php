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

namespace OAuth2\ResponseMode;

use Interop\Http\Factory\ResponseFactoryInterface;
use Interop\Http\Factory\StreamFactoryInterface;
use OAuth2\Grant\ResponseTypeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

final class FormPostResponseMode implements ResponseModeInterface
{
    /**
     * @var ResponseFactoryInterface
     */
    private $responseFactory;

    /**
     * @var StreamFactoryInterface
     */
    private $streamFactory;

    /**
     * FormPostResponseMode constructor.
     *
     * @param ResponseFactoryInterface $responseFactory
     * @param StreamFactoryInterface   $streamFactory
     */
    public function __construct(ResponseFactoryInterface $responseFactory, StreamFactoryInterface $streamFactory)
    {
        $this->responseFactory = $responseFactory;
        $this->streamFactory = $streamFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return ResponseTypeInterface::RESPONSE_TYPE_MODE_FORM_POST;
    }

    /**
     * {@inheritdoc}
     */
    public function buildResponse(UriInterface $redirectUri, array $data): ResponseInterface
    {
        $template = $this->renderTemplate($redirectUri, $data);
        $response = $this->responseFactory->createResponse();
        $body = $this->streamFactory->createStream($template);
        $response = $response->withBody($body);
        $response = $response->withHeader('Content-Type', 'text/html');

        return $response;
    }

    /**
     * @param UriInterface $redirectUri
     * @param array        $data
     *
     * @return string
     */
    protected function renderTemplate(UriInterface $redirectUri, array $data): string
    {
        $content = <<<'EOT'
<!doctype html>
<html>
    <head>
    <title>Authorization form</title>
    <meta name="referrer" content="origin"/>
    <script type="text/javascript">
        function submitform() {
            document.forms[0].submit();
        }
    </script>
    </head>
    <body onload='submitform();'>
        <form method="post" action="{{redirect_uri}}">
        {{input}}
    </form>
    </body>
</html>
EOT;

        $input = [];
        foreach ($data as $key => $value) {
            $input[] = sprintf('<input type="hidden" name="%s" value="%s"/>', $key, $value);
        }
        $replacements = [
            '{{redirect_uri}}' => $redirectUri->__toString(),
            '{{input}}'        => implode(PHP_EOL, $input),
        ];

        return str_replace(array_keys($replacements), $replacements, $content);
    }
}
