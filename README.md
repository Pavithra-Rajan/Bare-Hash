# BareSHA-256
This repository conatins all the deliverables related to the mini project of CS4035D Computer Security.

## Abstract
The Secure Hash Algorithm 256 (SHA-256) is a widely used cryptographic hash function that produces a fixed-size output of 256 bits, commonly known as the SHA256 checksum. Despite its widespread use, few cryptographers delve into the low-level implementation details of the SHA256 checksum algorithm.

This project aims to develop a barebone implementation of the SHA256 checksum, using only basic programming constructs and no in-built libraries. The implementation will be tested for correctness and performance against known test vectors.

Furthermore, this project will explore the vulnerability of the SHA256 checksum algorithm to a length extension attack. In this type of attack, an attacker who has access to the SHA256 checksum output of a message can append additional data to it, without knowing the message or the key used in the original checksum. The project will also simulate a length extension attack on the SHA256 checksum implementation and evaluate its security. This project will provide a better understanding of the inner workings of the SHA256 checksum algorithm and its limitations, and will be useful for researchers, developers, and practitioners in the field of cryptography.

Avalanche effect which refers to the degree of change in the output of a cryptographic function due to a small change in the input will also be observed through this project.

## Learnings
- Constants: The first 32 bits of the fractional parts of the cube roots of the first 64 prime numbers is defined. As per reading, we found that this approach is used in some cryptographic applications, specifically in the construction of the SHA-256 hash function. These values are used to "mix" the input message in a way that makes it difficult to reverse-engineer the original message from the output hash. The specific choice of the first 32 bits of the fractional part of the cube roots of the first 64 prime numbers was likely made for a few reasons.
    * Cube roots were chosen because they provide a good balance between randomness and predictability, making them suitable for use in a cryptographic algorithm. 
    * Using the fractional part of the cube roots ensures that the resulting values are uniformly distributed between 0 and 1, which is important for maintaining the security properties of the algorithm. 
    * Using the first 64 prime numbers ensures that the resulting values are large and unlikely to repeat, further enhancing the security of the algorithm.

[primes.py](prime.py) returns the first 32 bits of the fractional parts of the cube roots of the first 64 prime numbers. 


## Team members
|S.L. No.| Name | Roll number | GitHub ID |
| ----- | -------- | -------- | -------- |
|1|Joel Mathew Cherian|B190664CS|[@JoelMathewC](https://github.com/JoelMathewC)|
|2|Pavithra Rajan|B190632CS|[@Pavithra-Rajan](https://github.com/Pavithra-Rajan)|
|3|Cliford Joshy|B190539CS|[@clifordjoshy](https://github.com/clifordjoshy)|


