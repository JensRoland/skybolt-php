<?php

declare(strict_types=1);

namespace Skybolt;

/**
 * Cache Digest - Cuckoo Filter implementation for compact cache state tracking
 *
 * A space-efficient probabilistic data structure that compresses cache state
 * tracking by ~85%, keeping cookies small even with many assets.
 *
 * Key properties:
 * - No false negatives: if an asset is cached, the filter will always report it
 * - Small false positive rate (~1-3%): occasionally reports uncached assets as cached
 * - Compact: ~2 bytes per asset vs ~40+ bytes for full serialization
 *
 * @package Skybolt
 */
class CacheDigest
{
    public const FINGERPRINT_BITS = 12;
    public const BUCKET_SIZE = 4;

    /** @var array<int, int>|null Cuckoo filter buckets */
    private ?array $buckets = null;

    /** @var int Number of buckets */
    private int $numBuckets = 0;

    /**
     * Create a CacheDigest from a base64-encoded cookie value
     *
     * @param string $digest Base64-encoded digest (URL-safe)
     * @return self
     */
    public static function fromBase64(string $digest): self
    {
        $instance = new self();
        $instance->parse($digest);
        return $instance;
    }

    /**
     * Check if an item might be in the filter
     *
     * @param string $item The item to look up (e.g., "src/css/main.css:Pw3rT8vL")
     * @return bool True if item might be present (possible false positive),
     *              False if item is definitely not present
     */
    public function lookup(string $item): bool
    {
        if ($this->buckets === null) {
            return false;
        }

        $fp = self::fingerprint($item);
        $i1 = $this->primaryBucket($item);
        $i2 = self::computeAlternateBucket($i1, $fp, $this->numBuckets);

        return $this->bucketContains($i1, $fp) || $this->bucketContains($i2, $fp);
    }

    /**
     * Check if the digest was successfully parsed
     *
     * @return bool True if digest is valid and loaded
     */
    public function isValid(): bool
    {
        return $this->buckets !== null;
    }

    /**
     * Parse a base64-encoded Cache Digest
     *
     * @param string $digest Base64-encoded digest (URL-safe)
     * @return bool True if parsed successfully
     */
    private function parse(string $digest): bool
    {
        if ($digest === '') {
            return false;
        }

        // Handle URL-safe base64
        $normalized = str_replace(['-', '_'], ['+', '/'], $digest);
        $normalized = str_pad($normalized, (int) (ceil(strlen($normalized) / 4) * 4), '=');

        $bytes = base64_decode($normalized, true);
        if ($bytes === false || strlen($bytes) < 5) {
            return false;
        }

        // Check version
        if (ord($bytes[0]) !== 1) {
            return false;
        }

        $this->numBuckets = (ord($bytes[1]) << 8) | ord($bytes[2]);
        $numFingerprints = $this->numBuckets * self::BUCKET_SIZE;

        $this->buckets = [];
        for ($i = 0; $i < $numFingerprints; $i++) {
            $offset = 5 + $i * 2;
            if ($offset + 1 < strlen($bytes)) {
                $this->buckets[$i] = (ord($bytes[$offset]) << 8) | ord($bytes[$offset + 1]);
            } else {
                $this->buckets[$i] = 0;
            }
        }

        return true;
    }

    /**
     * FNV-1a hash function (32-bit)
     *
     * @param string $str String to hash
     * @return int 32-bit hash value
     */
    public static function fnv1a(string $str): int
    {
        $hash = 2166136261;
        $len = strlen($str);
        for ($i = 0; $i < $len; $i++) {
            $hash ^= ord($str[$i]);
            $hash = ($hash * 16777619) & 0xFFFFFFFF;
        }
        return $hash;
    }

    /**
     * Generate fingerprint from string
     *
     * @param string $str String to fingerprint
     * @return int Fingerprint value (1 to 2^FINGERPRINT_BITS - 1)
     */
    public static function fingerprint(string $str): int
    {
        $hash = self::fnv1a($str);
        $fp = $hash & ((1 << self::FINGERPRINT_BITS) - 1);
        return $fp === 0 ? 1 : $fp;
    }

    /**
     * Compute primary bucket index
     *
     * @param string $str String to hash
     * @return int Bucket index
     */
    private function primaryBucket(string $str): int
    {
        return self::fnv1a($str) % $this->numBuckets;
    }

    /**
     * Compute alternate bucket using partial-key cuckoo hashing
     *
     * @param int $bucket Primary bucket index
     * @param int $fp Fingerprint
     * @param int $numBuckets Number of buckets
     * @return int Alternate bucket index
     */
    public static function computeAlternateBucket(int $bucket, int $fp, int $numBuckets): int
    {
        $fpHash = self::fnv1a((string) $fp);
        $bucketMask = $numBuckets - 1;
        $offset = ($fpHash | 1) & $bucketMask;
        return ($bucket ^ $offset) & $bucketMask;
    }

    /**
     * Check if bucket contains fingerprint
     *
     * @param int $bucketIndex Bucket index
     * @param int $fp Fingerprint to find
     * @return bool True if found
     */
    private function bucketContains(int $bucketIndex, int $fp): bool
    {
        $offset = $bucketIndex * self::BUCKET_SIZE;
        for ($i = 0; $i < self::BUCKET_SIZE; $i++) {
            if (($this->buckets[$offset + $i] ?? 0) === $fp) {
                return true;
            }
        }
        return false;
    }
}
