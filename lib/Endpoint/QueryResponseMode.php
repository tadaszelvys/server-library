<?php

namespace OAuth2\Endpoint;

use OAuth2\Util\Uri;
use Psr\Http\Message\ResponseInterface;

class QueryResponseMode implements ResponseModeInterface
{
    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'query';
    }

    /**
     * {@inheritdoc}
     */
    public function prepareResponse($redirect_uri, array $data, ResponseInterface &$response)
    {
        $response = $response->withStatus(302)
            ->withHeader('Location', Uri::buildUri($redirect_uri, [$this->getName() => $data]));
    }
}
