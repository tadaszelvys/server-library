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
use OAuth2\Exception\BaseExceptionInterface;
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
        try {
            $request = new ServerRequest();
            $this->getAuthorizationFactory()->createFromRequest(
                $request,
                $this->getUserManager()->getUser('user1'),
                true
            );
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Parameter "client_id" missing or invalid.', $e->getDescription());
        }
    }

    public function testResponseTypeParameterIsMissing()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'client_id' => 'foo',
            'state'     => '012345679',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Invalid "response_type" parameter or parameter is missing.', $e->getDescription());
        }
    }

    public function testRedirectUriParameterIsNotValid()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=true',
            'client_id'             => 'foo',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The specified redirect URI is not valid', $e->getDescription());
        }
    }

    public function testResponseTypeParameterIsNotSupported()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'bad_response_type',
            'state'         => '012345679',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Response type "bad_response_type" is not supported by this server', $e->getDescription());
        }
    }

    public function testNonConfidentialClientMustRegisterAtLeastOneRedirectUri()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'oof',
            'response_type'         => 'bad_response_type',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_client', $e->getMessage());
            $this->assertEquals('Non-confidential clients must register at least one redirect URI', $e->getDescription());
        }
    }

    public function testResponseTypeisNotAuthorizedForTheClient()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'fii',
            'response_type' => 'token',
            'state'         => '012345679',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('unauthorized_client', $e->getMessage());
            $this->assertEquals('The response type "token" is unauthorized for this client.', $e->getDescription());
        }
    }

    public function testResourceOwnerDeniedAccess()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'token',
            'state'         => '012345679',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            false
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertEquals('http://example.com/test?good=false#error=access_denied&error_description=The+resource+owner+denied+access+to+your+client&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Faccess_denied&state=012345679#', $response->getHeader('Location')[0]);
    }

    public function testAccessTokenSuccess()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'token',
            'state'         => '012345679',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&expires_in=[\d]+&scope=scope1\+scope2&foo=bar&state=012345679$/', $response->getHeader('Location')[0]);
    }

    public function testAccessTokenSuccessUsingSignedRequest()
    {
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
            'request' => $jws,
            'client_id'     => 'bad_client', // Wil be ignored as already set in the request object
            'redirect_uri'  => 'http://bad.example.com/test?good=false', // Wil be ignored as already set in the request object
            'scope'         => 'openid email profile address', // Wil be ignored as already set in the request object
            'state'         => '012345679',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&scope=openid\+scope1\+scope2&foo=bar&state=012345679$/', $response->getHeader('Location')[0]);
    }

    public function testAccessTokenSuccessUsingSignedAndEncryptedRequest()
    {
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
            'request' => $jwe,
            'client_id'     => 'bad_client', // Wil be ignored as already set in the request object
            'redirect_uri'  => 'http://bad.example.com/test?good=false', // Wil be ignored as already set in the request object
            'scope'         => 'openid email profile address', // Wil be ignored as already set in the request object
            'state'         => '012345679',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&scope=openid\+scope1\+scope2&foo=bar&state=012345679$/', $response->getHeader('Location')[0]);
    }

    public function testAccessTokenSuccessUsingSignedRequestUri()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'request_uri'  => 'https://gist.githubusercontent.com/Spomky/23ca2a645f97584aaa22/raw/e9ff926a07940db9033c0ed7b8d623afee5f144a/signed.jwt',
            'client_id'    => 'bad_client', // Wil be ignored as already set in the request object
            'redirect_uri' => 'http://bad.example.com/test?good=false', // Wil be ignored as already set in the request object
            'scope'        => 'openid email profile address', // Wil be ignored as already set in the request object
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&scope=openid\+scope1\+scope2&foo=bar&state=012345679$/', $response->getHeader('Location')[0]);
    }

    public function testAccessTokenSuccessUsingSignedAndEncryptedRequestUri()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'request_uri'  => 'https://gist.githubusercontent.com/Spomky/3f22bbdc279a05aaac62/raw/7bc47a71eb48b37296dc69c70ec81a2d782f8055/encrypted.jwt',
            'client_id'    => 'bad_client', // Wil be ignored as already set in the request object
            'redirect_uri' => 'http://bad.example.com/test?good=false', // Wil be ignored as already set in the request object
            'scope'        => 'openid email profile address', // Wil be ignored as already set in the request object
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&scope=openid\+scope1\+scope2&foo=bar&state=012345679$/', $response->getHeader('Location')[0]);
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
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
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
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);

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
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();

        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Unsupported response mode "foo_bar".', $e->getDescription());
        }
    }

    public function testAccessTokenSuccessWithUnsupportedResponseModeParameter()
    {
        $this->getAuthorizationEndpoint()->disallowResponseModeParameterInAuthorizationRequest();
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'token',
            'state'                 => '0123456789',
            'response_mode'         => 'fragment',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();

        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The response mode parameter is not authorized.', $e->getDescription());
        }
        $this->getAuthorizationEndpoint()->allowResponseModeParameterInAuthorizationRequest();
    }

    public function testAccessTokenSuccessWithUnsupportedResponseTypeCombination()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'token code id_token',
            'state'                 => '0123456789',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();

        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Unsupported response type combination "token code id_token".', $e->getDescription());
        }
    }
}
