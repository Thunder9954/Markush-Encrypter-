
---

## 1. Key Derivation & Expansion Engine

### 1.1 Master Key Derivation
To protect against brute-force attacks and hardware acceleration (ASIC/GPU), the master key $K_{\text{master}}$ is produced via Argon2id using a variable passphrase $P$ and a cryptographically secure 16-byte random salt $S$.

$$K_{\text{master}} = \text{Argon2id}\left(P, S, t=3, m=64\text{MB}, p=4\right)$$

### 1.2 HKDF Block-Key Expansion
A two-stage HMAC-SHA256 Key Derivation Function (RFC 5869) expands $K_{\text{master}}$ into unique **256-bit subkeys** for every individual block and round.

First, extract a high-entropy pseudorandom key $\text{PRK}$:

$$\text{PRK} = \text{HMAC-SHA256}\left(S, K_{\text{master}}\right)$$

Next, derive the block key $K_{R, i}$ for block index $i$ in escalation round $R$:

$$K_{R, i} = \text{HKDF-Expand}\left(\text{PRK}, \text{Info}_{R, i}, 32\right)$$

$$\text{Info}_{R, i} = \text{"Round\_"} \parallel R \parallel \text{"\_Block\_"} \parallel i$$

```text
Algorithm 1: DeriveBlockKeys
Input : Passphrase P, Salt S, BlockCount N, MaxRounds R_max
Output: Subkey Matrix K

PRK <- HKDF_Extract(S, Argon2id(P, S, t=3, m=64MB, p=4))

for R = 1 to R_max do
    for i = 0 to N - 1 do
        Info <- "Round_" + String(R) + "_Block_" + String(i)
        K[R][i] <- HKDF_Expand(PRK, Info, 32)
    end for
end for

return K
```

---

## 2. Decoy Generation & Entropy Matching Engine

### 2.1 Theoretical Entropy Target
To evade automated entropy detection, decoy blocks match the byte distribution of AES ciphertext ($H \approx 8.0000 \text{ bits/byte}$).

$$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i) \approx 7.9999$$

### 2.2 Ciphertext-Indistinguishable Synthetic Stream
Decoy blocks $D_j$ are synthesized by passing a zero-filled memory block $\mathbf{0}^M$ through AES-256 in Counter (CTR) mode using a seed key $K_{\text{decoy}}$:

$$K_{\text{decoy}} = \text{HKDF-Expand}\left(\text{PRK}, \text{"Decoy\_Seed"}, 32\right)$$

$$D_j = \text{AES-256-CTR}\left(K_{\text{decoy}}, \text{IV}_j, \mathbf{0}^{M}\right)$$

```text
Algorithm 2: GenerateDecoyBlocks
Input : PRK, Count NumDecoys, BlockSize M
Output: Array Decoys

K_decoy <- HKDF_Expand(PRK, "Decoy_Seed", 32)
ZeroBuffer <- MemoryBuffer(Size: M, Fill: 0x00)

for j = 0 to NumDecoys - 1 do
    IV_j <- CSPRNG_Bytes(12)
    Decoys[j] <- AES_CTR_Encrypt(K_decoy, IV_j, ZeroBuffer)
end for

return Decoys
```

---

## 3. Zero-Header Container & Permutation Engine

### 3.1 Inline Header Injection
Every real data chunk $B_i^{\text{payload}}$ of size **1 MB** receives an internal metadata prefix prior to encryption:

$$B_i^{\text{meta}} = \text{SeqNum}_i \parallel \text{RoundID}_i \parallel \text{IV}_i \parallel B_i^{\text{payload}}$$

### 3.2 Matrix Permutation
Real blocks $B^{\text{meta}}$ and synthetic decoys $D$ are combined into a single matrix $V = B^{\text{meta}} \cup D$ of total length $N$. The matrix is shuffled using a key-seeded Fisher-Yates algorithm:

$$S_{\text{shuffle}} = \text{HKDF-Expand}\left(\text{PRK}, \text{"Shuffle\_Seed"}, 32\right)$$

$$\text{For } k = N-1 \text{ down to } 1: \quad r \leftarrow \text{PRNG}(S_{\text{shuffle}}) \pmod{k+1}, \quad \text{Swap}(V_k, V_r)$$

### 3.3 Authenticated AEAD Encryption
Each element $V_k$ in the permuted matrix is encrypted with **AES-256-GCM**, producing ciphertext $C_k$ and a **16-byte authentication tag** $T_k$:

$$E_k = \text{AES-256-GCM-Encrypt}\left(K_{R, k}, \text{IV}_k, V_k\right) \parallel T_k$$

The final container on disk is a continuous binary stream with no global headers:

$$C_{\text{final}} = \bigoplus_{k=0}^{N-1} E_k = E_0 \parallel E_1 \parallel \dots \parallel E_{N-1}$$

---

## 4. Decryption & Reconstruction Engine

### 4.1 Automated Decoy Filtering Decision Rule
During extraction, every chunk $E_k$ undergoes GCM authentication verification using subkey $K_{R, k}$.

Let $\mathbb{V}(E_k)$ be the binary validation state:

$$\mathbb{V}(E_k) = \begin{cases} 1 & \text{if } \text{GCM-Tag-Verify}(T_k) = \text{VALID} \implies \text{Retain \& Extract Metadata} \\ 0 & \text{if } \text{GCM-Tag-Verify}(T_k) = \text{INVALID} \implies \text{Purge Decoy Block} \end{cases}$$

```text
Algorithm 3: ReconstructPayload
Input : EncryptedContainer C_final, Passphrase P, Salt S
Output: Restored File Payload

PRK <- HKDF_Extract(S, Argon2id(P, S, t=3, m=64MB, p=4))
Chunks <- SplitContainer(C_final, ChunkSize = 1MB + HeaderSize + 16B)
RealBlocks <- EmptyList()

for k = 0 to Length(Chunks) - 1 do
    K_sub <- HKDF_Expand(PRK, "Round_1_Block_" + String(k), 32)
    Plaintext, Valid <- AES_GCM_Decrypt(K_sub, Chunks[k])
    
    if Valid is TRUE then
        Header, Data <- UnpackMetadata(Plaintext)
        RealBlocks.Append(SequenceNumber = Header.SeqNum, Payload = Data)
    else
        // Failed GCM tag indicates a decoy block; discard silently
        Continue
    end if
end for

SortedBlocks <- SortAscending(RealBlocks, Key = SequenceNumber)
return ConcatenatePayloads(SortedBlocks)
```

---

## 5. Security & Primitive Matrix

| Component | Primitive | Modern Cryptographic Role |
| :--- | :--- | :--- |
| **Passphrase KDF** | Argon2id | Memory-hard defense against ASIC, GPU, and dictionary attacks |
| **Subkey Expansion** | HKDF-Expand (HMAC-SHA256) | Eliminates key reuse by guaranteeing distinct 256-bit subkeys per block |
| **Decoy Generator** | AES-256-CTR PRF | Generates high-entropy noise ($H \approx 7.9999$) indistinguishable from ciphertext |
| **Matrix Permutation** | Key-Seeded Fisher-Yates | $N!$ layout randomization to prevent structural spatial analysis |
| **Container Encryption**| AES-256-GCM | Authenticated Encryption (AEAD) ensuring integrity and silent decoy filtering |
| **Disk Signature** | Headerless Byte-Stream | Zero magic bytes, zero plaintext headers, and zero identifiable disk artifacts |
