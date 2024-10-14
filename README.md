# PHJT
## PHJT - PHP JWT Token Class
PHJT is a PHP class that provides an easy-to-use interface for generating, verifying, and managing JWT (JSON Web Token) tokens. It supports multiple symmetric algorithms for token signing and verification, making it versatile for different security requirements.

# Features:

## JWT Token Generation:
* Create tokens with custom payload data.
* Set token expiration time.
* Generates unique JWT IDs (jti claim).
* Uses default or custom algorithms for token signing.

## Token Verification:
* Verifies the integrity of tokens by checking the signature.
* Checks if the token is expired using the exp claim.
* Uses constant-time comparison to prevent timing attacks.

## Key Rotation:
Supports secret key rotation without affecting existing tokens.

## Flexible Algorithm Support:
* Supports algorithms HS256, HS384, and HS512.
* Allows dynamic setting of the default algorithm and secret key.

## Error Handling:
* Returns structured arrays with status, message, and data for all operations.
* Errors are not shown directly but are handled gracefully by returning messages in the response.

# Usage Guide:
* Setting Secret Key: You can update the secret key dynamically without rotating keys.
```
PHJT::key('powerful_secret_key');
```

* Setting Algorithm: If you want to change the default algorithm used for signing, use the setAlgorithm method.
```
PHJT::algorithm('HS512');
```

* Generating a Token: You can create a JWT token using the create method. This will generate a token based on the provided payload, expiration time, and the algorithm.
```
$payload = [
    'user_id' => 123,
    'role' => 'admin',
];

$result = PHJT::create($payload, 3600, 'HS256');
if ($result['status']) {
    echo "Token: " . $result['data'];
} else {
    echo "Error: " . $result['message'];
}
```

* Verifying a Token: To verify the validity of a token, use the verify method. It checks the signature and ensures that the token is not expired.
```
$token = 'eyJhb...';  // Example token

$result = PHJT::verify($token, 'HS256');
if ($result['status']) {
    print_r($result['data']); // Display the payload
} else {
    echo "Error: " . $result['message'];
}
```

* Rotating the Secret Key: If you need to rotate the secret key (e.g., for enhanced security), you can call the rotate method with the new key.
```
phjt::rotate('new_secret_key');
```

This PHJT class is highly modular, making it easy to integrate into a PHP project for managing JWT authentication in a secure and flexible way.


#GPT-4o
* Prompt: ```read full library from "https://github.com/sakibweb/PHJT","https://raw.githubusercontent.com/sakibweb/PHJT/refs/heads/main/PHJT.php" focus on key management and algorithm then explain how many time needed to decode a jwt with most powerful computer right now ? note: give me the short answer based on only this library.```

* Reply: ```The library PHJT you referenced for JWT management focuses on key creation, signing, and verification using HMAC algorithms like HS256, HS384, and HS512. The default algorithm is HS256, and the secret key is used to generate and verify JWT signatures.
Regarding your question on how long it would take to decode a JWT using the most powerful computer: since JWT tokens signed with HMAC (like HS256) rely on a secret key for security, decoding without the key would require brute-forcing the secret. The time depends on the length and complexity of the secret key. PHJT requires keys to be at least 18 characters long, making brute-forcing difficult.
With current supercomputers, brute-forcing a sufficiently long and complex key (like one with 18+ characters including symbols, numbers, and letters) could take an extremely long time, even for the most powerful machines—potentially millions of years depending on the exact key strength and algorithm used. ```
