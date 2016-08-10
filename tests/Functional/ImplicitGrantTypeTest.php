<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Functional;

use Jose\Factory\JWEFactory;
use Jose\Factory\JWSFactory;
use Jose\Object\JWK;
use OAuth2\Test\Base;
use PHPHtmlParser\Dom;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

/**
 * @group ImplicitGrantType
 */
class ImplicitGrantTypeTest extends Base
{
    public function testClientIdParameterIsMissing()
    {
        $request = new ServerRequest();
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $response->getBody()->rewind();
        $this->assertEquals('{"error":"invalid_request","error_description":"Parameter \"client_id\" missing or invalid.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testResponseTypeParameterIsMissing()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'client_id' => 'foo',
            'state'     => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $response->getBody()->rewind();
        $this->assertEquals('{"error":"invalid_request","error_description":"The parameter \"response_type\" is mandatory.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testStateParameterIsMissing()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'response_type' => 'token',
            'redirect_uri'  => 'http://example.com/test?good=true',
            'client_id'     => 'foo',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertEquals('http://example.com/test?good=true#error=invalid_request&error_description=The+parameter+%22state%22+is+mandatory.&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Finvalid_request', $response->getHeader('Location')[0]);
    }

    public function testRedirectUriParameterIsNotValid()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'response_type' => 'token',
            'redirect_uri'  => 'http://example.com/test?good=true',
            'client_id'     => 'foo',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertEquals('http://example.com/test?good=true#error=invalid_request&error_description=The+specified+redirect+URI+is+not+valid.&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Finvalid_request&state=0123456789', $response->getHeader('Location')[0]);
    }

    public function testResponseTypeParameterIsNotSupported()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'bad_response_type',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertEquals('http://example.com/test?good=false&error=invalid_request&error_description=Response+type+%22bad_response_type%22+is+not+supported+by+this+server&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Finvalid_request&state=0123456789#', $response->getHeader('Location')[0]);
    }

    public function testNonConfidentialClientMustRegisterAtLeastOneRedirectUri()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'oof',
            'response_type' => 'none',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertEquals('http://example.com/test?good=false&error=invalid_request&error_description=Non-confidential+clients+must+register+at+least+one+redirect+URI.&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Finvalid_request&state=0123456789#', $response->getHeader('Location')[0]);
    }

    public function testResponseTypeisNotAuthorizedForTheClient()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'fii',
            'response_type' => 'token',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertEquals('http://example.com/test?good=false#error=unauthorized_client&error_description=The+response+type+%22token%22+is+unauthorized+for+this+client.&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Funauthorized_client&state=0123456789', $response->getHeader('Location')[0]);
    }

    public function testResourceOwnerDeniedAccess()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'token',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(false);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertEquals('http://example.com/test?good=false#error=access_denied&error_description=The+resource+owner+denied+access+to+your+client&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Faccess_denied&state=0123456789', $response->getHeader('Location')[0]);
    }

    public function testAccessTokenSuccess()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'token',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&expires_in=[\d]+&scope=scope1\+scope2&foo=bar&state=0123456789$/', $response->getHeader('Location')[0]);
    }

    public function testAccessTokenSuccessUsingSignedRequest()
    {
        $this->getImplicitGrantType()->allowConfidentialClients();

        $jwk2 = new JWK([
            'kid' => 'JWK2',
            'use' => 'sig',
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $claims = [
            'iat'           => time(),
            'nbf'           => time(),
            'exp'           => time() + 120,
            'iss'           => 'jwt1',
            'aud'           => 'https://server.example.com',
            'response_type' => 'token',
            'client_id'     => 'jwt1',
            'redirect_uri'  => 'http://example.com/test?good=false',
            'scope'         => 'openid scope1 scope2',
            'nonce'         => 'n-0S6_WzA2Mj',
        ];

        $jws = JWSFactory::createJWSToCompactJSON(
            $claims,
            $jwk2,
            [
                'kid' => 'JWK2',
                'cty' => 'JWT',
                'alg' => 'HS512',
            ]
        );

        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'request'       => $jws,
            'client_id'     => 'bad_client', // Wil be ignored as already set in the request object
            'redirect_uri'  => 'http://bad.example.com/test?good=false', // Wil be ignored as already set in the request object
            'scope'         => 'openid email profile address', // Wil be ignored as already set in the request object
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $response->getBody()->rewind();
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&scope=openid\+scope1\+scope2&foo=bar&state=0123456789&session_state=[^"]+$/', $response->getHeader('Location')[0]);

        $this->getImplicitGrantType()->disallowConfidentialClients();
    }

    public function testAccessTokenSuccessUsingSignedAndEncryptedRequest()
    {
        $this->getImplicitGrantType()->allowConfidentialClients();

        $jwk1 = new JWK([
            'kid' => 'JWK1',
            'use' => 'enc',
            'kty' => 'oct',
            'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
        ]);
        $jwk2 = new JWK([
            'kid' => 'JWK2',
            'use' => 'sig',
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $claims = [
            'iat'           => time(),
            'nbf'           => time(),
            'exp'           => time() + 120,
            'iss'           => 'jwt1',
            'aud'           => 'https://server.example.com',
            'response_type' => 'token',
            'client_id'     => 'jwt1',
            'redirect_uri'  => 'http://example.com/test?good=false',
            'scope'         => 'openid scope1 scope2',
            'nonce'         => 'n-0S6_WzA2Mj',
        ];

        $jws = JWSFactory::createJWSToCompactJSON(
            $claims,
            $jwk2,
            [
                'kid' => 'JWK2',
                'cty' => 'JWT',
                'alg' => 'HS512',
            ]
        );

        $jwe = JWEFactory::createJWEToCompactJSON(
            $jws,
            $jwk1,
            [
                'kid' => 'JWK1',
                'cty' => 'JWT',
                'alg' => 'A256KW',
                'enc' => 'A256CBC-HS512',
                'exp' => time() + 120,
                'aud' => $this->getIssuer(),
                'iss' => 'jwt1',
            ]
        );

        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'request'       => $jwe,
            'client_id'     => 'bad_client', // Wil be ignored as already set in the request object
            'redirect_uri'  => 'http://bad.example.com/test?good=false', // Wil be ignored as already set in the request object
            'scope'         => 'openid email profile address', // Wil be ignored as already set in the request object
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&scope=openid\+scope1\+scope2&foo=bar&state=0123456789&session_state=[^"]+$/', $response->getHeader('Location')[0]);

        $this->getImplicitGrantType()->disallowConfidentialClients();
    }

    public function testAccessTokenSuccessUsingSignedRequestUri()
    {
        $this->getImplicitGrantType()->allowConfidentialClients();

        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'request_uri'  => 'https://127.0.0.1/signed_request',
            'client_id'    => 'bad_client', // Wil be ignored as already set in the request object
            'redirect_uri' => 'http://bad.example.com/test?good=false', // Wil be ignored as already set in the request object
            'scope'        => 'openid email profile address', // Wil be ignored as already set in the request object
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&scope=openid\+scope1\+scope2&foo=bar&state=012345679&session_state=[^"]+$/', $response->getHeader('Location')[0]);

        $this->getImplicitGrantType()->disallowConfidentialClients();
    }

    public function testAccessTokenSuccessUsingSignedAndEncryptedRequestUri()
    {
        $this->getImplicitGrantType()->allowConfidentialClients();

        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'request_uri'  => 'https://127.0.0.1/signed_and_encrypted_request',
            'client_id'    => 'bad_client', // Wil be ignored as already set in the request object
            'redirect_uri' => 'http://bad.example.com/test?good=false', // Wil be ignored as already set in the request object
            'scope'        => 'openid email profile address', // Wil be ignored as already set in the request object
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&scope=openid\+scope1\+scope2&foo=bar&state=012345679&session_state=[^"]+$/', $response->getHeader('Location')[0]);

        $this->getImplicitGrantType()->disallowConfidentialClients();
    }

    public function testAccessTokenSuccessWithState()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'token',
            'state'                 => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&expires_in=[\d]+&scope=scope1\+scope2&foo=bar&state=[^"]+$/', $response->getHeader('Location')[0]);
    }

    public function testAccessTokenSuccessWithStateAndForPostResponseMode()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'token',
            'state'                 => '0123456789',
            'response_mode'         => 'form_post',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $dom = new Dom();
        $dom->load($content);
        $inputs = $dom->find('input');

        $this->assertNotNull($inputs);
        $this->assertEquals(6, count($inputs));
    }

    public function testAccessTokenSuccessWithUnsupportedResponseMode()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'token',
            'state'                 => '0123456789',
            'response_mode'         => 'foo_bar',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertEquals('http://example.com/test?good=false&error=invalid_request&error_description=Unsupported+response+mode+%22foo_bar%22.&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Finvalid_request&state=0123456789#', $response->getHeader('Location')[0]);
    }

    public function testAccessTokenSuccessWithDisabledResponseModeParameter()
    {
        $this->getAuthorizationFactory()->disableResponseModeParameterSupport();
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'token',
            'state'                 => '0123456789',
            'response_mode'         => 'query',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&expires_in=[\d]+&scope=scope1\+scope2&foo=bar&state=0123456789$/', $response->getHeader('Location')[0]);
        $this->getAuthorizationFactory()->enableResponseModeParameterSupport();
    }

    public function testAccessTokenSuccessWithUnsupportedResponseTypeCombination()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'token code id_token',
            'state'                 => '0123456789',
            'nonce'                 => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertEquals('http://example.com/test?good=false&error=invalid_request&error_description=Response+type+%22token+code+id_token%22+is+not+supported+by+this+server&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Finvalid_request&state=0123456789#', $response->getHeader('Location')[0]);
    }
}
