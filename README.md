# Zero-Header Secure Container Architecture

An advanced, cryptographically secure, high-entropy container system designed to prevent disk layout profiling, frequency analysis, and metadata leakage. This repository documents the architecture, algorithms, and pseudocode for a headerless encrypted container that uses memory-hard key derivation, per-block subkeys, authenticated encryption, and entropy-matched decoy blocks.

> Note: This repository contains design and pseudocode. It is not an audited, production implementation. Cryptographic design must be reviewed by experts before use.

---

## Table of Contents

- Introduction
- System architecture (overview)
- Subsystems and pseudocode
  - Key expansion & derivation
  - Entropy-matched decoy engine
  - Container encryption pipeline
  - Decryption & reconstruction
- Security analysis
- License

---

## Introduction

This design aims to provide an encrypted container format with no identifiable file headers or signatures on disk. It combines:

- Argon2id for memory-hard passphrase hashing
- HKDF-SHA256 for per-block key derivation
- AES-256-GCM for authenticated encryption
- AES-256-CTR-generated decoy blocks to match entropy distribution
- Key-seeded permutation to obfuscate block ordering

The resulting container is a concatenation of AES-GCM ciphertext blocks (each including its authentication tag) with no global header or magic bytes.

---

## System architecture (overview)

```mermaid
graph TB
  subgraph KDF [Key Expansion & Derivation]
    P[Passphrase]
    S[Salt (CSPRNG, 16B)]
    A[Argon2id -> Master Key]
    H[HKDF-Expand -> Block/Subkeys]
    P --> A --> H
  end

  subgraph DECOY [Entropy-Matched Decoy Engine]
    Dk[Decoy Seed]
    CTR[AES-CTR Zero-Stream]
    D[Decoy Blocks]
    Dk --> CTR --> D
  end

  subgraph ENC [Container Encryption Pipeline]
    F[Input File]
    Ch[Chunker (1MB)]
    Hd[Inner Metadata Header]
    Sh[Keyed Shuffle]
    G[AES-256-GCM Encrypt]
    F --> Ch --> Hd --> Sh --> G
  end

  subgraph DEC [Decryption & Reconstruction]
    R[Encrypted Container]
    Parse[Block Parser]
    Auth[AES-GCM Verify]
    Purge[Discard Decoys]
    Reorder[Unshuffle & Sort]
    Restore[Reconstruct File]
    R --> Parse --> Auth --> Purge --> Reorder --> Restore
  end

  H -.-> Dk
  H -.-> G
  D -.-> Sh
```

---

## Subsystems & Pseudocode

### 1) Key Expansion & Derivation

- Use Argon2id to derive a 32-byte master key from passphrase and salt.
- Use HKDF-SHA256 (RFC 5869) to derive per-round, per-block 32-byte subkeys.

Master key derivation (formula):

K_master = Argon2id(P, S, t=3, m=65536 KiB, p=4, L=32)

HKDF subkey expansion (PRK = HKDF-Extract(S, K_master)) and:

K_{R,i} = HKDF-Expand(PRK, Info = "Round_R_Block_i", 32)

Pseudocode:

```text
Procedure DeriveBlockKeys(Passphrase P, Salt S, TotalBlocks N, R_max):
  PRK <- HKDF_Extract(S, Argon2id(P, S, t=3, m=65536, p=4, L=32))
  For R from 1 to R_max:
    For i from 0 to N-1:
      Info <- "Round_" || ToString(R) || "_Block_" || ToString(i)
      K[R][i] <- HKDF_Expand(PRK, Info, 32)
  Return K
```

---

### 2) Entropy-Matched Decoy Engine

- Derive a decoy seed from PRK via HKDF.
- Generate decoy blocks by encrypting an all-zero buffer with AES-256-CTR using the decoy key and per-block IVs.
- Insert decoy blocks so that ciphertext entropy distribution closely matches real data.

Pseudocode:

```text
Procedure GenerateDecoyBlocks(PRK, NumDecoys, BlockSize):
  K_decoy <- HKDF_Expand(PRK, "Decoy_Seed_Matrix", 32)
  ZeroBuffer <- array of size BlockSize filled with 0x00
  For j from 0 to NumDecoys-1:
    IV_j <- DeriveIV(K_decoy, j)
    DecoyArray[j] <- AES_256_CTR_Encrypt(K_decoy, IV_j, ZeroBuffer)
  Return DecoyArray
```

---

### 3) Container Encryption Pipeline

- Split the payload into fixed-size blocks (e.g., 1 MiB).
- Prepend each block with an inner metadata header (sequence number, round id, IV).
- Generate a set of decoy blocks and unify with the real blocks.
- Shuffle all blocks using a key-seeded Fisher-Yates permutation.
- Encrypt each block with its derived AES-256-GCM key and IV.
- Concatenate ciphertext blocks into a headerless container file.

Pseudocode:

```text
Procedure EncryptContainer(File F, Passphrase P, Salt S, NumDecoys):
  Chunks <- Split F into 1MiB blocks
  PRK <- HKDF_Extract(S, Argon2id(P, S, ...))
  For i from 0 to len(Chunks)-1:
    Header_i <- BuildHeader(SeqNum=i, RoundID=1, IV=CSPRNG(12))
    RealBlocks[i] <- Header_i || Chunks[i]
  DecoyBlocks <- GenerateDecoyBlocks(PRK, NumDecoys, BlockSize=1MiB + |Header|)
  UnifiedArray <- RealBlocks U DecoyBlocks
  Seed_shuffle <- HKDF_Expand(PRK, "Matrix_Permutation_Seed", 32)
  PermutedArray <- KeyedFisherYatesShuffle(UnifiedArray, Seed_shuffle)
  For k from 0 to len(PermutedArray)-1:
    K_k <- HKDF_Expand(PRK, BuildInfo(k), 32)
    EncryptedBlocks[k] <- AES_256_GCM_Encrypt(K_k, IV_k, PermutedArray[k])
  C_final <- Concatenate(EncryptedBlocks)
  Return C_final
```

---

### 4) Decryption & Reconstruction

- Split the container into ciphertext blocks (each containing a 16B GCM tag).
- For each block, derive the expected subkey and attempt AES-256-GCM decryption.
- Valid blocks yield inner headers with sequence numbers; invalid blocks are discarded as decoys.
- Sort valid blocks by sequence number and concatenate payloads to recover the original file.

Pseudocode:

```text
Procedure DecryptAndReconstruct(Container, Passphrase P, Salt S):
  PRK <- HKDF_Extract(S, Argon2id(P, S, ...))
  Chunks <- Split Container into ciphertext blocks (cipher + 16B tag)
  RealBlocks <- []
  For k from 0 to len(Chunks)-1:
    K_sub <- HKDF_Expand(PRK, BuildInfo("Round_1_Block_" || k), 32)
    Plaintext, TagStatus <- AES_256_GCM_Decrypt(K_sub, Chunks[k])
    If TagStatus == VALID:
      Header, RawData <- ExtractHeader(Plaintext)
      RealBlocks.Append({SeqNum: Header.SeqNum, Data: RawData})
  Sort RealBlocks by SeqNum
  F <- Concatenate RealBlocks.Data
  Return F
```

---

## Security analysis (high level)

| Parameter | Mechanism | Benefit |
|---|---:|---|
| Passphrase hashing | Argon2id (memory-hard) | Resists GPU/ASIC brute force |
| Key diversification | HKDF-SHA256 | Eliminates single-key reuse across blocks |
| Authenticated encryption | AES-256-GCM | Tamper detection via 128-bit tag |
| Layout obfuscation | Keyed permutation + decoys | Makes block boundaries and ordering indistinguishable |

---

## Disclaimer

This repository contains specification and pseudocode only. This design must be reviewed and tested by cryptography and security experts before any real-world usage. Incorrect implementations can lead to catastrophic data loss.

---

## License

Specify your license here (e.g., MIT). Replace this with a proper LICENSE file as needed.
