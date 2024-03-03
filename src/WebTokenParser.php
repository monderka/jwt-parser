<?php

namespace Monderka\JwtParser;

use Exception;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

final class WebTokenParser
{
    private JWSSerializerManager $serializerManager;
    private HeaderCheckerManager $headerCheckerManager;
    private JWSVerifier $verifier;
    private ?JWK $publicKey = null;

    /**
     * @param array{
     *     "jwtAlgo": string,
     *     "publicKeyPath": string,
     *     "accessTokenExpiration": int
     * } $config
     */
    public function __construct(
        private readonly array $config
    ) {
        $algoManager = new AlgorithmManager([ new RS256() ]);
        $this->serializerManager = new JWSSerializerManager([
            new CompactSerializer()
        ]);
        $this->verifier = new JWSVerifier($algoManager);
        $this->headerCheckerManager = new HeaderCheckerManager(
            [
                new AlgorithmChecker([ $this->config["jwtAlgo"] ])
            ],
            [
                new JWSTokenSupport()
            ]
        );
    }

    private function getClaimChecker(string $issuer): ClaimCheckerManager
    {
        return new ClaimCheckerManager([
            new IssuedAtChecker(),
            new NotBeforeChecker(),
            new ExpirationTimeChecker(),
            new IssuerChecker([
                $issuer
            ])
        ]);
    }

    private function getPublicKey(): JWK
    {
        if (empty($this->publicKey)) {
            $this->publicKey = JWKFactory::createFromKeyFile(
                $this->config["publicKeyPath"],
                '',
                [ "use" => "sig" ]
            );
        }
        return $this->publicKey;
    }

    /**
     * @return array<string, mixed>
     * @throws InvalidWebTokenException
     */
    public function parse(string $token, string $jwtIssuer): array
    {
        try {
            $token = str_replace("Bearer ", "", $token);
            $jws = $this->serializerManager->unserialize($token);
            $this->headerCheckerManager->check($jws, 0);
            if (!$this->verifier->verifyWithKey($jws, $this->getPublicKey(), 0)) {
                throw new InvalidWebTokenException();
            }
            /** @var array<string, mixed> $payload */
            $payload = json_decode($jws->getPayload() ?? "{}", true);
            $this->getClaimChecker($jwtIssuer)->check($payload);
            return $payload;
        } catch (Exception $exc) {
            throw new InvalidWebTokenException(message: $exc->getMessage(), previous: $exc);
        }
    }
}
