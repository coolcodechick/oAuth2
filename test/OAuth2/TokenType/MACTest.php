<?php

class OAuth2_TokenType_MACTest extends PHPUnit_Framework_TestCase
{
    public function testMacHeader()
    {
        $request = new OAuth2_Request();
        $macToken = new OAuth2_TokenType_MAC(new OAuth2_Storage_Memory());

        // valid params returns the access token
        $token = 'sometoken';
        $timestamp = time();
        $nonce = rand();
        $authHeader = <<<EOF
MAC id="$token",
ts="$timestamp",
nonce="$nonce",
mac="bhCQXTVyfj5cmA9uKkPFx1zeOXM="
EOF;

        $request->headers = array('AUTHORIZATION' => $authHeader);
        $tokenParam = $macToken->getAccessTokenParameter($request);

        $this->assertNotNull($tokenParam);
        $this->assertEquals($tokenParam, $token);

        // invalid nonce
        $authHeader = <<<EOF
MAC id="$token",
ts="$timestamp",
nonce="$nonce",
mac="bhCQXTVyfj5cmA9uKkPFx1zeOXM="
EOF;

        $request->headers = array('AUTHORIZATION' => $authHeader);
        $tokenParam = $macToken->getAccessTokenParameter($request);
        $this->assertNull($tokenParam);
        $this->assertEquals($macToken->getResponse()->getParameter('error_description'), 'Nonce has already been used');

        // invalid timestamp
        $timestamp = time() - 50;
        $nonce = rand();
        $authHeader = <<<EOF
MAC id="$token",
ts="$timestamp",
nonce="$nonce",
mac="bhCQXTVyfj5cmA9uKkPFx1zeOXM="
EOF;

        $request->headers = array('AUTHORIZATION' => $authHeader);
        $tokenParam = $macToken->getAccessTokenParameter($request);
        $this->assertNull($tokenParam);
        $this->assertEquals($macToken->getResponse()->getParameter('error_description'), 'Invalid timestamp');
    }
}
