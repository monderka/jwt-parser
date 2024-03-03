<?php

namespace Monderka\JwtParser\Test\Unit;

use DateTime;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Monderka\JwtParser\InvalidWebTokenException;
use Monderka\JwtParser\WebTokenParser;
use PHPUnit\Framework\TestCase;

final class WebTokenParserTest extends TestCase
{
    private WebTokenParser $service;

    private array $config = [
        "jwtAlgo" => "RS256",
        "privateKeyPassPhrase" => "123456789",
        "privateKeyPath" => __DIR__ . "/private.pem",
        "publicKeyPath" => __DIR__ . "/public.pem",
        "accessTokenExpiration" => 3600
    ];
    private string $token;

    protected function setUp(): void
    {
        parent::setUp();
        $privateKey = JWKFactory::createFromKeyFile(
            $this->config["privateKeyPath"],
            $this->config["privateKeyPassPhrase"] ?? '',
            [ "use" => "sig" ]
        );
        $algo = new RS256();
        $algorithmManager = new AlgorithmManager([ $algo ]);
        $compactSerializer = new CompactSerializer();
        $jwsSerializerManager = new JWSSerializerManager([ $compactSerializer ]);
        $this->service = new WebTokenParser(
            $this->config
        );
        $jwsBuilder = new JWSBuilder($algorithmManager);
        $time = (new DateTime())->getTimestamp();
        $payload = [
            'iss' => "test issuer",
            'sub' => "555",
            'exp' => $time + (int) $this->config["accessTokenExpiration"],
            'iat' => $time,
            'nbf' => $time,
            'alg' => $this->config["jwtAlgo"],
            'name' => "test name",
            'scope' => implode(" ", [ "scope1", "scope2", "scope3" ])
        ];
        $jws = $jwsBuilder->create()
            ->withPayload(
                json_encode($payload, JSON_THROW_ON_ERROR)
            )->addSignature(
                $privateKey,
                [ "alg" => $this->config["jwtAlgo"] ]
            )->build();
        $this->token = $jwsSerializerManager->serialize('jws_compact', $jws, 0);
    }

    public function testParse(): void
    {
        $parsed = $this->service->parse($this->token, "test issuer");
        $this->assertIsArray($parsed);
        $this->assertEquals(555, (int) $parsed["sub"]);
        $this->assertEquals("test name", $parsed["name"]);
        $this->assertEquals("scope1 scope2 scope3", $parsed["scope"]);
    }

    public function testParseFailedOnInvalidSignature(): void
    {
        $token = $this->token . "1";
        $this->expectException(InvalidWebTokenException::class);
        $this->service->parse($token, "test issuer");
    }
}
