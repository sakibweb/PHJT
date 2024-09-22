<?php

/**
 * PHJT - PHP JWT Token Class
 * Author: Sakibur Rahman @sakibweb
 * This class provides methods for generating, verifying, and managing JWT tokens.
 * It supports multiple algorithms (HS256, HS384, HS512) and handles key rotation and algorithm setting.
 */
class PHJT {

    /**
     * Default algorithm.
     * @var string
     */
    private static $defaultAlgorithm = 'HS256';

    /**
     * Secret key for signing the token.
     * @var string
     */
    private static $secretKey = 'default_key';

    /**
     * Supported symmetric algorithms (HMAC).
     * @var array
     */
    private static $supportedAlgs = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    ];

    /**
     * Base64URL encoding without padding
     *
     * @param string $data Data to be encoded
     * @return string Base64URL encoded data
     */
    private static function base64UrlEncode($data) {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }

    /**
     * Base64URL decoding
     *
     * @param string $data Data to be decoded
     * @return string Decoded data
     */
    private static function base64UrlDecode($data) {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(str_replace(['-', '_'], ['+', '/'], $data));
    }

    /**
     * Create a JWT token with claims
     *
     * @param array $payload The payload data
     * @param int $expiresIn Expiration time in seconds (default is 3600)
     * @param string|null $algorithm The algorithm to use (default HS256)
     * @return array Token creation result with status, message, and token
     */
    public static function create($payload, $expiresIn = 3600, $algorithm = null) {
        $algorithm = $algorithm ?? self::$defaultAlgorithm;

        if (!isset(self::$supportedAlgs[$algorithm])) {
            return ['status' => false, 'message' => 'Unsupported algorithm', 'data' => null];
        }

        $header = [
            'alg' => $algorithm,
            'typ' => 'JWT',
        ];

        // Add standard claims
        $payload['iat'] = time(); // Issued at
        $payload['exp'] = time() + $expiresIn; // Expiration time
        $payload['jti'] = bin2hex(random_bytes(16)); // Unique JWT ID

        // Encode header and payload
        $headerEncoded = self::base64UrlEncode(json_encode($header));
        $payloadEncoded = self::base64UrlEncode(json_encode($payload));

        // Create the signature
        $signature = self::sign("$headerEncoded.$payloadEncoded", $algorithm);

        // Combine header, payload, and signature into JWT token
        $token = "$headerEncoded.$payloadEncoded.$signature";

        return ['status' => true, 'message' => 'Token created successfully', 'data' => $token];
    }

    /**
     * Sign the token using the specified algorithm
     *
     * @param string $data The data to sign
     * @param string $algorithm The algorithm to use
     * @return string The generated signature
     */
    private static function sign($data, $algorithm) {
        return self::base64UrlEncode(hash_hmac(self::$supportedAlgs[$algorithm], $data, self::$secretKey, true));
    }

    /**
     * Verify and decode the JWT token
     *
     * @param string $jwt The token to verify
     * @param string|null $algorithm The algorithm to use (default HS256)
     * @return array Verification result with status, message, and payload
     */
    public static function verify($jwt, $algorithm = null) {
        $algorithm = $algorithm ?? self::$defaultAlgorithm;

        try {
            // Split JWT into parts
            $parts = explode('.', $jwt);
            if (count($parts) !== 3) {
                return ['status' => false, 'message' => 'Invalid token format', 'data' => null];
            }

            [$headerEncoded, $payloadEncoded, $signatureProvided] = $parts;

            // Recreate the signature with the header and payload
            $signatureGenerated = self::sign("$headerEncoded.$payloadEncoded", $algorithm);

            // Check if the signatures match using constant-time comparison
            if (!hash_equals($signatureGenerated, $signatureProvided)) {
                return ['status' => false, 'message' => 'Signature verification failed', 'data' => null];
            }

            // Decode the payload
            $payload = json_decode(self::base64UrlDecode($payloadEncoded), true);

            // Verify expiration time
            if (isset($payload['exp']) && time() >= $payload['exp']) {
                return ['status' => false, 'message' => 'Token has expired', 'data' => null];
            }

            return ['status' => true, 'message' => 'Token is valid', 'data' => $payload];
        } catch (Exception $e) {
            // Catch unexpected exceptions and return the error message
            return ['status' => false, 'message' => 'Verification failed: ' . $e->getMessage(), 'data' => null];
        }
    }

    /**
     * Rotate the secret key (for key rotation)
     *
     * @param string $newSecretKey The new secret key
     * @return array Result of the key rotation
     */
    public static function rotate($newSecretKey) {
        self::$secretKey = $newSecretKey;
        return ['status' => true, 'message' => 'Secret key rotated successfully', 'data' => null];
    }

    /**
     * Set a new default algorithm for signing
     *
     * @param string $newAlgorithm The new algorithm to set as default
     * @return array Result of setting the algorithm
     */
    public static function algorithm($newAlgorithm) {
        if (!isset(self::$supportedAlgs[$newAlgorithm])) {
            return ['status' => false, 'message' => 'Unsupported algorithm', 'data' => null];
        }
        self::$defaultAlgorithm = $newAlgorithm;
        return ['status' => true, 'message' => 'Default algorithm updated successfully', 'data' => null];
    }

    /**
     * Set a new secret key for signing
     *
     * @param string $newSecretKey The new secret key
     * @return array Result of setting the new key
     */
    public static function key($newSecretKey) {
        self::$secretKey = $newSecretKey;
        return ['status' => true, 'message' => 'Secret key updated successfully', 'data' => null];
    }
}

?>
