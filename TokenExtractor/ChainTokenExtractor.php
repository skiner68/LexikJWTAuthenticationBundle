<?php

namespace Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor;

use Symfony\Component\HttpFoundation\Request;

/**
 * ChainTokenExtractor is the class responsible to extract a JWT token from a
 * request using all the configured token extractors.
 *
 * @author Robin Chalas <robin.chalas@gmail.com>
 */
class ChainTokenExtractor implements TokenExtractorInterface
{
    /**
     * @var TokenExtractorInterface[]
     */
    private $extractors = [];

    /**
     * @param TokenExtractorInterface[] $extractors
     */
    public function __construct(array $extractors = [])
    {
        foreach ($extractors as $extractor) {
            $this->addTokenExtractor($extractor);
        }
    }

    /**
     * Calls {@link TokenExtractorInterface::extract()} for each extractors by
     * iterating over until a token is found.
     *
     * @param Request $request
     *
     * @return string|false The extracted token, false otherwise
     */
    public function extract(Request $request)
    {
        foreach ($this->extractors as $extractor) {
            if ($token = $extractor->extract($request)) {
                return $token;
            }
        }

        return false;
    }

    /**
     * @param TokenExtractorInterface $extractor
     */
    private function addTokenExtractor(TokenExtractorInterface $extractor)
    {
        $this->extractors[] = $extractor;
    }
}
