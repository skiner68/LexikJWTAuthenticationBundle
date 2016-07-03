<?php

namespace Lexik\Bundle\JWTAuthenticationBundle\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

/**
 * BeforeAuthToken.
 *
 * To be used before loading an user from a decoded JWT token.
 *
 * @author Robin Chalas <robin.chalas@gmail.com>
 */
final class BeforeAuthToken extends AbstractToken
{
    /**
     * @var string
     */
    private $rawToken;

    /**
     * @var array
     */
    private $payload;

    /**
     * @param string $rawToken
     */
    public function __construct($rawToken)
    {
        $this->rawToken = $rawToken;

        $this->setAuthenticated(false);
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials()
    {
        return $this->rawToken;
    }

    /**
     * {@inheritdoc}
     */
    public function setPayload(array $payload)
    {
        $this->payload = $payload;
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return $this->payload;
    }
}
