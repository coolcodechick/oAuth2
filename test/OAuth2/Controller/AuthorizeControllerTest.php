<?php

class OAuth2_Controller_AuthorizeControllerTest extends PHPUnit_Framework_TestCase
{
    public function testNoClientIdResponse()
    {
        $server = $this->getTestServer();
        $request = new OAuth2_Request();
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), false);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'No client id supplied');
    }

    public function testInvalidClientIdResponse()
    {
        $server = $this->getTestServer();
        $request = new OAuth2_Request(array(
            'client_id' => 'Fake Client ID', // invalid client id
        ));
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), false);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'The client id supplied is invalid');
    }

    public function testNoRedirectUriSuppliedOrStoredResponse()
    {
        $server = $this->getTestServer();
        $request = new OAuth2_Request(array(
            'client_id' => 'Test Client ID', // valid client id
        ));
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), false);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_uri');
        $this->assertEquals($response->getParameter('error_description'), 'No redirect URI was supplied or stored');
    }

    public function testNoResponseTypeResponse()
    {
        $server = $this->getTestServer();
        $request = new OAuth2_Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
        ));
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), false);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'invalid_request');
        $this->assertEquals($query['error_description'], 'Invalid or missing response type');
    }

    public function testInvalidResponseTypeResponse()
    {
        $server = $this->getTestServer();
        $request = new OAuth2_Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
            'response_type' => 'invalid', // invalid response type
        ));
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), false);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'invalid_request');
        $this->assertEquals($query['error_description'], 'Invalid or missing response type');
    }

    public function testRedirectUriFragmentResponse()
    {
        $server = $this->getTestServer();
        $request = new OAuth2_Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com#fragment', // valid redirect URI
            'response_type' => 'code', // invalid response type
        ));
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_uri');
        $this->assertEquals($response->getParameter('error_description'), 'The redirect URI must not contain a fragment');
    }

    public function testEnforceState()
    {
        $server = $this->getTestServer(array('enforce_state' => true));
        $request = new OAuth2_Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
            'response_type' => 'code',
        ));
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'invalid_request');
        $this->assertEquals($query['error_description'], 'The state parameter is required');
    }

    public function testDoNotEnforceState()
    {
        $server = $this->getTestServer(array('enforce_state' => false));
        $request = new OAuth2_Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
            'response_type' => 'code',
        ));
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $this->assertFalse(isset($query['error']));
    }

    public function testEnforceScope()
    {
        $server = $this->getTestServer();
        $scopeStorage = new OAuth2_Storage_Memory(array('default_scope' => false, 'supported_scopes' => array('testscope')));
        $server->setScopeUtil(new OAuth2_Scope($scopeStorage));

        $request = new OAuth2_Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
            'response_type' => 'code',
            'state' => 'xyz',
        ));
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $parts = parse_url($response->getHttpHeader('Location'));
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'invalid_client');
        $this->assertEquals($query['error_description'], 'This application requires you specify a scope parameter');

        $request->query['scope'] = 'testscope';
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $parts = parse_url($response->getHttpHeader('Location'));
        parse_str($parts['query'], $query);

        // success!
        $this->assertFalse(isset($query['error']));
    }

    public function testInvalidRedirectUri()
    {
        $server = $this->getTestServer();
        $request = new OAuth2_Request(array(
            'client_id' => 'Test Client ID with Redirect Uri', // valid client id
            'redirect_uri' => 'http://adobe.com', // invalid redirect URI
            'response_type' => 'code',
        ));
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'redirect_uri_mismatch');
        $this->assertEquals($response->getParameter('error_description'), 'The redirect URI provided is missing or does not match');
    }

    public function testNoRedirectUriWithMultipleRedirectUris()
    {
        $server = $this->getTestServer();

        // create a request with no "redirect_uri" in querystring
        $request = new OAuth2_Request(array(
            'client_id' => 'Test Client ID with Multiple Redirect Uris', // valid client id
            'response_type' => 'code',
        ));

        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_uri');
        $this->assertEquals($response->getParameter('error_description'), 'A redirect URI must be supplied when multiple redirect URIs are registered');
    }

    public function testRedirectUriWithValidRedirectUri()
    {
        $server = $this->getTestServer();

        // create a request with no "redirect_uri" in querystring
        $request = new OAuth2_Request(array(
            'client_id' => 'Test Client ID with Redirect Uri Parts', // valid client id
            'response_type' => 'code',
            'redirect_uri' => 'http://user:pass@brentertainment.com:2222/authorize/cb?auth_type=oauth',
        ));

        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
    }

    public function testRedirectUriWithDifferentQueryAndExactMatchRequired()
    {
        $server = $this->getTestServer(array('require_exact_redirect_uri' => true));

        // create a request with no "redirect_uri" in querystring
        $request = new OAuth2_Request(array(
            'client_id' => 'Test Client ID with Redirect Uri Parts', // valid client id
            'response_type' => 'code',
            'redirect_uri' => 'http://user:pass@brentertainment.com:2222/authorize/cb?auth_type=oauth&hereisa=querystring',
        ));

        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'redirect_uri_mismatch');
        $this->assertEquals($response->getParameter('error_description'), 'The redirect URI provided is missing or does not match');
    }

    public function testRedirectUriWithDifferentQueryAndExactMatchNotRequired()
    {
        $server = $this->getTestServer(array('require_exact_redirect_uri' => false));

        // create a request with no "redirect_uri" in querystring
        $request = new OAuth2_Request(array(
            'client_id' => 'Test Client ID with Redirect Uri Parts', // valid client id
            'response_type' => 'code',
            'redirect_uri' => 'http://user:pass@brentertainment.com:2222/authorize/cb?auth_type=oauth&hereisa=querystring',
        ));

        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
    }

    public function testMultipleRedirectUris()
    {
        $server = $this->getTestServer();
        $request = new OAuth2_Request(array(
            'client_id' => 'Test Client ID with Multiple Redirect Uris', // valid client id
            'redirect_uri' => 'http://brentertainment.com', // valid redirect URI
            'response_type' => 'code',
        ));

        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);
        $this->assertEquals($response->getStatusCode(), 302);

        // call again with different (but still valid) redirect URI
        $request->query['redirect_uri'] = 'http://morehazards.com';

        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);
        $this->assertEquals($response->getStatusCode(), 302);
    }

    public function testUserDeniesAccessResponse()
    {
        $server = $this->getTestServer();
        $request = new OAuth2_Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
            'response_type' => 'code',
            'state' => 'xyz',
        ));
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), false);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'access_denied');
        $this->assertEquals($query['error_description'], 'The user denied access to your application');
    }

    public function testCodeQueryParamIsSet()
    {
        $server = $this->getTestServer();
        $request = new OAuth2_Request(array(
            'client_id'     => 'Test Client ID', // valid client id
            'redirect_uri'  => 'http://adobe.com', // valid redirect URI
            'response_type' => 'code',
            'state'         => 'xyz',
        ));
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);

        $this->assertEquals('http', $parts['scheme']); // same as passed in to redirect_uri
        $this->assertEquals('adobe.com', $parts['host']); // same as passed in to redirect_uri
        $this->assertArrayHasKey('query', $parts);
        $this->assertFalse(isset($parts['fragment']));

        // assert fragment is in "application/x-www-form-urlencoded" format
        parse_str($parts['query'], $query);
        $this->assertNotNull($query);
        $this->assertArrayHasKey('code', $query);

        // ensure no error was returned
        $this->assertFalse(isset($query['error']));
        $this->assertFalse(isset($query['error_description']));
    }

    public function testSuccessfulRequestReturnsStateParameter()
    {
        $server = $this->getTestServer(array('allow_implicit' => true));
        $request = new OAuth2_Request(array(
            'client_id'     => 'Test Client ID', // valid client id
            'redirect_uri'  => 'http://adobe.com', // valid redirect URI
            'response_type' => 'code',
            'state'         => 'test', // valid state string (just needs to be passed back to us)
        ));
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);

        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        $this->assertArrayHasKey('query', $parts);
        parse_str($parts['query'], $query);

        $this->assertArrayHasKey('state', $query);
        $this->assertEquals($query['state'], 'test');

        // ensure no error was returned
        $this->assertFalse(isset($query['error']));
        $this->assertFalse(isset($query['error_description']));
    }

    public function testSuccessfulRequestStripsExtraParameters()
    {
        $server = $this->getTestServer(array('allow_implicit' => true));
        $request = new OAuth2_Request(array(
            'client_id'     => 'Test Client ID', // valid client id
            'redirect_uri'  => 'http://adobe.com', // valid redirect URI
            'response_type' => 'code',
            'state'         => 'test',      // valid state string (just needs to be passed back to us)
            'fake'          => 'something', // extra query param
        ));
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertNull($response->getParameter('error'));

        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        $this->assertFalse(isset($parts['fake']));
        $this->assertArrayHasKey('query', $parts);
        parse_str($parts['query'], $query);

        $this->assertFalse(isset($parmas['fake']));
        $this->assertArrayHasKey('state', $query);
        $this->assertEquals($query['state'], 'test');
    }

    private function getTestServer($config = array())
    {
        $storage = OAuth2_Storage_Bootstrap::getInstance()->getMemoryStorage();
        $server = new OAuth2_Server($storage, $config);

        // Add the two types supported for authorization grant
        $server->addGrantType(new OAuth2_GrantType_AuthorizationCode($storage));

        return $server;
    }
}
