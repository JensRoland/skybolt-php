<?php

declare(strict_types=1);

namespace Skybolt\Tests;

use PHPUnit\Framework\TestCase;
use Skybolt\CacheDigest;

/**
 * Tests for CacheDigest (Cuckoo filter implementation)
 *
 * These tests use cross-language test vectors to ensure compatibility
 * with the JavaScript implementation.
 */
class CacheDigestTest extends TestCase
{
    /**
     * Cross-language test vectors for FNV-1a hash
     * These values must match the JavaScript implementation exactly
     */
    public function testFnv1aHashMatchesJavaScript(): void
    {
        // Test vectors verified against JavaScript BigInt implementation
        $testCases = [
            ['src/css/critical.css:abc123', 821208812],
            ['src/css/main.css:def456', 26790494],
            ['skybolt-launcher:xyz789', 452074441],
            ['123', 1916298011],
            ['', 2166136261], // Empty string returns offset basis
            ['a', 3826002220],
            ['test', 2949673445],
        ];

        foreach ($testCases as [$input, $expected]) {
            $this->assertSame(
                $expected,
                CacheDigest::fnv1a($input),
                "FNV-1a hash mismatch for '{$input}'"
            );
        }
    }

    /**
     * Test fingerprint generation
     */
    public function testFingerprintGeneration(): void
    {
        // Fingerprint should be in range [1, 4095] (12 bits, never 0)
        $testCases = [
            'src/css/critical.css:abc123',
            'src/css/main.css:def456',
            'skybolt-launcher:xyz789',
        ];

        foreach ($testCases as $input) {
            $fp = CacheDigest::fingerprint($input);
            $this->assertGreaterThanOrEqual(1, $fp);
            $this->assertLessThanOrEqual(4095, $fp);
        }
    }

    /**
     * Test fingerprint never returns 0
     */
    public function testFingerprintNeverZero(): void
    {
        // Generate many fingerprints and ensure none are 0
        for ($i = 0; $i < 1000; $i++) {
            $fp = CacheDigest::fingerprint("test-{$i}");
            $this->assertNotSame(0, $fp, "Fingerprint should never be 0");
        }
    }

    /**
     * Test alternate bucket calculation is reversible
     */
    public function testAlternateBucketReversible(): void
    {
        $numBuckets = 16; // Power of 2

        for ($bucket = 0; $bucket < $numBuckets; $bucket++) {
            for ($fp = 1; $fp <= 100; $fp++) {
                $alt = CacheDigest::computeAlternateBucket($bucket, $fp, $numBuckets);
                $original = CacheDigest::computeAlternateBucket($alt, $fp, $numBuckets);

                $this->assertSame(
                    $bucket,
                    $original,
                    "Alternate bucket should be reversible: bucket={$bucket}, fp={$fp}"
                );
            }
        }
    }

    /**
     * Test parsing a valid digest from JavaScript
     *
     * This digest was created by the JavaScript implementation with these assets:
     * - src/css/critical.css:B20ictSB
     * - src/css/main.css:DfFbFQk_
     * - src/js/app.js:DW873Fox
     * - skybolt-launcher:ptJmv_9y
     */
    public function testParseValidDigest(): void
    {
        $digest = 'AQAEAAQAAAAAAAAAAAXNB-UAAAAACT4NhgAAAAAAAAAAAAAAAA';
        $cd = CacheDigest::fromBase64($digest);

        $this->assertTrue($cd->isValid());

        // These should be found
        $this->assertTrue($cd->lookup('src/css/critical.css:B20ictSB'));
        $this->assertTrue($cd->lookup('src/css/main.css:DfFbFQk_'));
        $this->assertTrue($cd->lookup('src/js/app.js:DW873Fox'));
        $this->assertTrue($cd->lookup('skybolt-launcher:ptJmv_9y'));

        // These should NOT be found (different hashes)
        $this->assertFalse($cd->lookup('src/css/critical.css:DIFFERENT'));
        $this->assertFalse($cd->lookup('src/css/main.css:DIFFERENT'));
        $this->assertFalse($cd->lookup('nonexistent:asset'));
    }

    /**
     * Test parsing empty digest
     */
    public function testParseEmptyDigest(): void
    {
        $cd = CacheDigest::fromBase64('');
        $this->assertFalse($cd->isValid());
        $this->assertFalse($cd->lookup('anything'));
    }

    /**
     * Test parsing invalid base64
     */
    public function testParseInvalidBase64(): void
    {
        $cd = CacheDigest::fromBase64('not-valid-base64!!!');
        $this->assertFalse($cd->isValid());
    }

    /**
     * Test parsing digest with wrong version
     */
    public function testParseWrongVersion(): void
    {
        // Version 2 header (invalid)
        $cd = CacheDigest::fromBase64(base64_encode("\x02\x00\x04\x00\x00"));
        $this->assertFalse($cd->isValid());
    }

    /**
     * Test parsing truncated digest
     */
    public function testParseTruncatedDigest(): void
    {
        // Too short
        $cd = CacheDigest::fromBase64(base64_encode("\x01\x00"));
        $this->assertFalse($cd->isValid());
    }

    /**
     * Test URL-safe base64 handling
     */
    public function testUrlSafeBase64(): void
    {
        // Same digest with URL-safe characters (- instead of +, _ instead of /)
        $digest = 'AQAEAAQAAAAAAAAAAAXNB-UAAAAACT4NhgAAAAAAAAAAAAAAAA';
        $cd = CacheDigest::fromBase64($digest);

        $this->assertTrue($cd->isValid());
        $this->assertTrue($cd->lookup('src/css/critical.css:B20ictSB'));
    }
}
