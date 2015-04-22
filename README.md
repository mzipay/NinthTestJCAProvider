# NinthTest JCA Security Provider

The NinthTest JCA Provider is a security provider for the
[Java™ Cryptography Architecture](http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html),
focused on supporting candidate, reference, academic, and experimental
cryptographic algorithms and security services.

**Because the services provided by the NinthTest JCA Provider are
exploratory/provisional in nature, the NinthTest JCA Provider is _not_
recommended for use in security-critical applications or environments.**

Algorithms and services currently supported by the NinthTest JCA Provider:

| Algorithm	| Service             |
| --------- | ------------------- |
| Helix	    | Cipher              |
|           | Mac                 |
|           | KeyGenerator        |
|           | SecretKeyFactory    |
|           | AlgorithmParameters |
|           | SecureRandom        |

## Documentation

http://ninthtest.net/java-security-provider/

## Download

Due to a JCA code-signing requirement, the binary (JAR) form is recommended
unless you intend to contribute or create a derivative work (or just want to
explore the source).

### Source

```bash
$ git clone https://github.com/mzipay/NinthTestJCAProvider.git
```

### Binary

Download packaged (signed) JARs from
https://sourceforge.net/projects/ninthtest-jca-provider/files/

Read the *Install the NinthTest JCA Provider* section from
[Downloading and installing the NinthTest JCA Provider](http://ninthtest.net/java-security-provider/download.html)!

