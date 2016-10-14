<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Unit;

use OAuth2\Test\Base;

/**
 * @group UserInfo
 */
class UserInfoTest extends Base
{
    public function testSubjectAreCalculatedWithTheRedirectUriOrTheTheSectorUri()
    {
        $userinfo = $this->getUserInfo();
        $user_account = $this->getUserAccountManager()->getUserAccountByPublicId('user1');

        $client1 = $this->getClientManager()->getClientByName('Mufasa');
        $client2 = $this->getClientManager()->getClientByName('foo2');

        $id_token1 = $userinfo->getUserinfo($client1, $user_account, 'https://foo.bar.com', null, [], ['openid']);
        $id_token2 = $userinfo->getUserinfo($client2, $user_account, 'https://foo.bar.com', null, [], ['openid']);
        $id_token3 = $userinfo->getUserinfo($client1, $user_account, 'https://www.foo.com', null, [], ['openid']);
        $id_token4 = $userinfo->getUserinfo($client2, $user_account, 'urn:abc:edf', null, [], ['openid']);

        $this->assertNotEquals($id_token1, $id_token2);
        $this->assertEquals($id_token2, $id_token3);
        $this->assertEquals($id_token3, $id_token4);
    }
}
