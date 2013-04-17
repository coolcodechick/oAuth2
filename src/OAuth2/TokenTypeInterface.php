<?php

interface OAuth2_TokenTypeInterface
{
    public function getTokenType();
    public function getAccessTokenParameter(OAuth2_RequestInterface $request);
    public function setAccessTokenParameters(array $tokenData);
}
