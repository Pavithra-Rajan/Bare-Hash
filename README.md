This repository contains all the deliverables related to the mini project of CS4035D Computer Security.

# SHA256

## Abstract

The Secure Hash Algorithm 256 (SHA-256) is a widely used cryptographic hash function that produces a fixed-size output of 256 bits, commonly known as the SHA256 checksum. Despite its widespread use, few cryptographers delve into the low-level implementation details of the SHA256 checksum algorithm.

This project aims to develop a barebone implementation of the SHA256 checksum, using only basic programming constructs and no in-built libraries. The implementation will be tested for correctness and performance against known test vectors.

Furthermore, this project will explore the vulnerability of the SHA256 checksum algorithm to a length extension attack. In this type of attack, an attacker who has access to the SHA256 checksum output of a message can append additional data to it, without knowing the message or the key used in the original checksum. The project will also simulate a length extension attack on the SHA256 checksum implementation and evaluate its security. This project will provide a better understanding of the inner workings of the SHA256 checksum algorithm and its limitations, and will be useful for researchers, developers, and practitioners in the field of cryptography.

Avalanche effect which refers to the degree of change in the output of a cryptographic function due to a small change in the input will also be observed through this project.

## Learnings

- Constants: The first 32 bits of the fractional parts of the cube roots of the first 64 prime numbers is defined. As per reading, we found that this approach is used in some cryptographic applications, specifically in the construction of the SHA-256 hash function. These values are used to "mix" the input message in a way that makes it difficult to reverse-engineer the original message from the output hash. The specific choice of the first 32 bits of the fractional part of the cube roots of the first 64 prime numbers was likely made for a few reasons.
  - Cube roots were chosen because they provide a good balance between randomness and predictability, making them suitable for use in a cryptographic algorithm.
  - Using the fractional part of the cube roots ensures that the resulting values are uniformly distributed between 0 and 1, which is important for maintaining the security properties of the algorithm.
  - Using the first 64 prime numbers ensures that the resulting values are large and unlikely to repeat, further enhancing the security of the algorithm.

## Implementation

### To run SHA256 checksum of a file:

#### Help menu:

```console
$ python3 sha256.py -h
```

```console
usage: sha256.py [-h] -f F

options:
  -h, --help  show this help message and exit
  -f F        Name of the file to find the checksum
```

#### Run with a test file:

```console
$ python3 sha256.py -f tests/test1.pdf
```

```console
7e2903a8c60bf957824c330707617e8cc32283b5287bb9362acb2f45550810c1
```

# MD5

## Abstract

The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value. Despite its widespread use, few cryptographers delve into the low-level implementation details of the SHA256 checksum algorithm.

This project aims to develop a barebone implementation of the MD5 checksum, using only basic programming constructs and no in-built libraries. The implementation will be tested for correctness and performance against known test vectors.

## Implementation

### To run MD5 checksum of a file:

#### Help menu:

```console
$ python3 md5.py -h
```

```console
usage: md5.py [-h] -f F

options:
  -h, --help  show this help message and exit
  -f F        Name of the file to find the checksum
```

#### Run with a test file:

```console
$ python3 md5.py -f tests/test1.pdf
```

```console
e2726c121bdb725e83cab7c0166438c0
```

# Testing

Using the command line utilities, `sha256sum` and `md5sum`, we can compare the sha256 hash and md5 hash generated by this implementation and verify if it matches.

Download Nessus via:

```console
curl --request GET \
  --url 'https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.5.0-ubuntu1404_amd64.deb' \
  --output 'tests/Nessus.deb'
```

```console
$ ./test.sh
```

```console
--- SHA256 Test ---
Passed: tests/test1.pdf  Time taken: 2.74931 seconds
Passed: tests/test2.txt  Time taken: 0.0456512 seconds
Passed: tests/Nessus.deb  Time taken: 0.0420008 seconds
-------------------

--- MD5 Test ---
Passed: tests/test1.pdf  Time taken: 0.795163 seconds
Passed: tests/test2.txt  Time taken: 0.0367074 seconds
Passed: tests/Nessus.deb  Time taken: 0.0352709 seconds
----------------
```

Here, three files are given as test cases and the hash generated by our implementations from scratch matches the one generated by the built-in utilities.

## Team members

| S.L. No. | Name                | Roll number | GitHub ID                                            |
| -------- | ------------------- | ----------- | ---------------------------------------------------- |
| 1        | Joel Mathew Cherian | B190664CS   | [@JoelMathewC](https://github.com/JoelMathewC)       |
| 2        | Pavithra Rajan      | B190632CS   | [@Pavithra-Rajan](https://github.com/Pavithra-Rajan) |
| 3        | Cliford Joshy       | B190539CS   | [@clifordjoshy](https://github.com/clifordjoshy)     |
