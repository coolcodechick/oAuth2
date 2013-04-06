<?php

/**
 * Implement this interface to specify where the OAuth2 Server
 * should verify nonces are unique
 *
 * @author Brent Shaffer <bshafs@gmail.com>
 */
interface OAuth2_Storage_NonceInterface
{
    public function isNonceValid($nonce);
    public function markNonceAsUsed($nonce);
}
