<?php

/**
* @see http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-03
*/
class OAuth2_TokenType_MAC extends OAuth2_TokenType_Bearer
{
    private $response;
    private $config;
    private $nonceStorage;

    public function __construct(OAuth2_Storage_NonceInterface $nonceStorage, $config = array())
    {
        $this->config = array_merge(array(
            'token_mac_header_name' => 'MAC',
            'timestamp_valid_within' => 30,
        ), $config);
        $this->nonceStorage = $nonceStorage;
    }

    public function getTokenType()
    {
        return 'mac';
    }

    public function getAccessTokenParameter(OAuth2_RequestInterface $request)
    {
        $headers = $request->headers('AUTHORIZATION');

        if (empty($headers) || 0 !== strpos($headers, $this->config['token_mac_header_name'])) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Malformed auth header');
            return null;
        }

        $macInfo = array();

        $tokens = explode(',', trim(str_replace($this->config['token_mac_header_name'], '', $headers)));

        // In the format Key="Value"
        foreach ($tokens as $token) {
            list($key, $value) = preg_split("/\=/", trim($token), 2);

            //strip quotes off value
            $macInfo[$key] = preg_replace('/^"|"$/', '', $value);
        }

        if (!isset($macInfo['nonce']) || !isset($macInfo['ts']) || !isset($macInfo['mac'])) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Malformed auth header');
            return null;
        }

        if ($this->nonceStorage && $this->nonceStorage->isNonceValid($macInfo['nonce'])) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Nonce has already been used');
            return null;
        }

        if (abs($macInfo['ts'] - time()) > $this->config['timestamp_valid_within']) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Invalid timestamp');
            return null;
        }

        // request was successful - mark the nonce as used
        $this->nonceStorage->markNonceAsUsed($macInfo['nonce']);

        return $macInfo['id'];
    }

    public function getResponse()
    {
        return $this->response;
    }
}
