<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Behat\Behat\Tester\Exception\PendingException;

class GrantContext extends BaseContext
{
    /**
     * @Given a valid authorization code request is received and the resource owner accepts it
     */
    public function aValidAuthorizationCodeRequestIsReceivedAndTheResourceOwnerAcceptsIt()
    {
        throw new PendingException();
    }

    /**
     * @Given the client should be redirected
     */
    public function theClientShouldBeRedirected()
    {
        throw new PendingException();
    }

    /**
     * @Given the redirect Uri contains an authorization code
     */
    public function theRedirectUriContainsAnAuthorizationCode()
    {
        throw new PendingException();
    }

    /**
     * @Given a public client sends a request without code verification parameter
     */
    public function aPublicClientSendsARequestWithoutCodeVerificationParameter()
    {
        throw new PendingException();
    }

    /**
     * @Given the redirect Uri contains an error
     */
    public function theRedirectUriContainsAnError()
    {
        throw new PendingException();
    }

    /**
     * @Given the error is :error
     */
    public function theErrorIs($error)
    {
        throw new PendingException();
    }

    /**
     * @Given the error description is :description
     */
    public function theErrorDescriptionIs($description)
    {
        throw new PendingException();
    }

    /**
     * @Given a public client sends a request with an invalid code verification parameter
     */
    public function aPublicClientSendsARequestWithAnInvalidCodeVerificationParameter()
    {
        throw new PendingException();
    }

    /**
     * @Given a valid authorization code grant is received
     */
    public function aValidAuthorizationCodeGrantIsReceived()
    {
        throw new PendingException();
    }

    /**
     * @Given an access token is issued
     */
    public function anAccessTokenIsIssued()
    {
        throw new PendingException();
    }
}
