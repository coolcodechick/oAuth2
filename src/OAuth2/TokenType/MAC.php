<?php

/**
* This is not yet supported!
*/
class OAuth2_TokenType_MAC extends OAuth2_TokenType_Bearer
{
    private $response;

    public function getTokenType()
    {
        return 'mac';
    }

    public function getAccessTokenParameter(OAuth2_RequestInterface $request)
    {
        $headers = $request->headers('AUTHORIZATION');

        if (empty($headers) || 0 !== strpos($headers, 'MAC ')) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Malformed auth header');
            return null;
        }

        $macInfo = array();

        $tokens = explode(',', trim(str_replace('MAC', '', $headers)));

            // In the format Key="Value"
        foreach ($tokens as $token) {
            list($key, $value) = preg_split("/\=/", trim($token), 2);

            //strip quotes off value
            $macInfo[$key] = preg_replace('/^"|"$/', '', $value);
        }

        return $macInfo['id'];
    }

    public function getResponse()
    {
        return $this->response;
    }
}
