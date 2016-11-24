<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect\SessionManagement;

use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response;

class IFrameEndpoint implements IFrameEndpointInterface
{
    /**
     * {@inheritdoc}
     */
    public function handle(ServerRequestInterface $server)
    {
        $content = $this->renderTemplate();

        $response = new Response('php://memory');
        $response = $response->withHeader('Cache-Control', 'no-store');
        $response = $response->withHeader('Pragma', 'no-cache');
        $response->getBody()->write($content);

        return $response;
    }

    /**
     * @return string
     */
    protected function renderTemplate()
    {
        $content = <<<'EOT'
<html>
    <head>
        <meta http-equiv="content-type" content="text/html;charset=UTF-8" />
        <title>OP iFrame</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/components/sha256-min.js"></script>
            window.addEventListener("message",receiveMessage, false);
            
            function getCookie(c_name)
            {
                var i,x,y,ARRcookies=document.cookie.split(";");
                for (i=0;i<ARRcookies.length;i++) {
                    x=ARRcookies[i].substr(0,ARRcookies[i].indexOf("="));
                    y=ARRcookies[i].substr(ARRcookies[i].indexOf("=")+1);
                    x=x.replace(/^\s+|\s+$/g,"");
                    if (x==c_name) {
                        return unescape(y);
                    }
                }
            }
            
            function receiveMessage(e){
                if ( e.origin !== origin) {
                    console.log(e.origin + ' !== ' + origin);
                    return;
                }
                var state = '';
                var parts = e.data.split(' ');
                var client_id = parts[0];
                var session_state = parts[1];
                var ss_parts = session_state.split('.');
                var salt = ss_parts[1];
                
                var ops = getCookie('ops');
                var ss = CryptoJS.SHA256(client_id + e.origin + ops + salt) + "." + salt;
                if (session_state == ss) {
                    state = 'unchanged';
                } else {
                    state = 'changed';
                }
                e.source.postMessage(state, e.origin);
            };
        //]]></script>
    </head>
    <body>
    </body>
</html>
EOT;

        return $content;
    }
}
