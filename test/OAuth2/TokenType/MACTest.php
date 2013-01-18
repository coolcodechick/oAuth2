<?php

class OAuth2_TokenType_MACTest extends PHPUnit_Framework_TestCase
{
    public function testMacHeader()
    {
        $request = new OAuth2_Request();
        $token = 'sometoken';
        $authHeader = <<<EOF
MAC id="$token",
ts="1336363200",
nonce="dj83hs9s",
mac="bhCQXTVyfj5cmA9uKkPFx1zeOXM="
EOF;
        $request->headers = array('AUTHORIZATION' => $authHeader);

        // autoloader is called in test/bootstrap.php
        $macToken = new OAuth2_TokenType_MAC();
        $tokenParam = $macToken->getAccessTokenParameter($request);

        $this->assertNotNull($tokenParam);
        $this->assertEquals($tokenParam, $token);
    }
}
