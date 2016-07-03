<?php

namespace Lexik\Bundle\JWTAuthenticationBundle\Exception;

use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailure\JWTDecodeFailureException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * Exception to be used during a failed JWT authentication process.
 *
 * @author Robin Chalas <robin.chalas@gmail.com>
 */
class JWTAuthenticationException extends AuthenticationException
{
    /**
     * Returns an AuthenticationException in case of invalid token.
     *
     * To be used if the token cannot be properly decoded.
     *
     * @param JWTDecodeFailureException|null $previous
     *
     * @return JWTAuthenticationException
     */
    public static function invalidToken(JWTDecodeFailureException $previous = null)
    {
        return new self($previous ? $previous->getMessage() : 'Invalid JWT Token', 401, $previous);
    }

    /**
     * Returns an AuthenticationException in case of invalid user.
     *
     * To be used if no user can be loaded from the identity retrieved from
     * the decoded token's payload.
     *
     * @param string|null $message
     *
     * @return JWTAuthenticationException
     */
    public static function invalidUser($identity, $identityField)
    {
        return new self(
            sprintf('Unable to load a valid user with %s "%s". If the user identity has been changed, you must renew the token. Otherwise, verify that the "lexik_jwt_authentication.user_identity_field" config option is correctly set. ', $identityField, $identity)
        );
    }

    /**
     * Returns an AuthenticationException in case of invalid payload.
     *
     * To be used if a key in missing in the payload or contains an unexpected value.
     *
     * @param string|null $message
     *
     * @return JWTAuthenticationException
     */
    public static function invalidPayload($message = 'Invalid payload')
    {
        return new self($message);
    }
}
