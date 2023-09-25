---
title: "Optee_template"
date: 2023-09-25T11:38:20+08:00
draft: false
tags: ["tee", "optee"]
categories: ["tee"]
---

## ta

```c
//------------------------------------------------
//--- 010 Editor v10.0.2 Binary Template
//
//      File:
//   Authors:
//   Version:
//   Purpose:
//  Category:
// File Mask:
//  ID Bytes:
//   History:
//------------------------------------------------
#define TEE_FS_HTREE_IV_SIZE 16
#define TEE_FS_HTREE_TAG_SIZE 16
#define TEE_FS_HTREE_FEK_SIZE 16

typedef struct _tee_fs_htree_meta {
	UINT64 length;
}tee_fs_htree_meta;

typedef struct _tee_fs_htree_imeta {
	struct tee_fs_htree_meta meta;
	UINT32 max_node_id;
    UINT32 nop;
}tee_fs_htree_imeta;

typedef struct _tee_fs_htree_image {
	UCHAR iv[TEE_FS_HTREE_IV_SIZE];
	UCHAR tag[TEE_FS_HTREE_TAG_SIZE];
	UCHAR enc_fek[TEE_FS_HTREE_FEK_SIZE];
	UCHAR imeta[sizeof(struct tee_fs_htree_imeta)];
	UINT32 counter;
}tee_fs_htree_image;

#define TEE_FS_HTREE_HASH_SIZE		32
#define TEE_FS_HTREE_IV_SIZE 16
#define TEE_FS_HTREE_TAG_SIZE 16
typedef struct _tee_fs_htree_node_image {
	/* Note that calc_node_hash() depends on hash first in struct */
	UCHAR hash[TEE_FS_HTREE_HASH_SIZE];
	UCHAR iv[TEE_FS_HTREE_IV_SIZE];
	UCHAR tag[TEE_FS_HTREE_TAG_SIZE];
	USHORT flags;
}tee_fs_htree_node_image;

//--------------------------------------
LittleEndian();

tee_fs_htree_image  ver0_head;
tee_fs_htree_image  ver1_head;
FSeek(0x1000);
tee_fs_htree_node_image ver0_root_node;
tee_fs_htree_node_image ver1_root_node;
FSeek(0x2000);
```

## encrypted ta

```c
//------------------------------------------------
//--- 010 Editor v10.0.2 Binary Template
//
//      File:
//   Authors:
//   Version:
//   Purpose:
//  Category:
// File Mask:
//  ID Bytes:
//   History:
//------------------------------------------------
enum shdr_img_type {
        SHDR_TA = 0,
        SHDR_BOOTSTRAP_TA = 1,
        SHDR_ENCRYPTED_TA = 2,
};

#define SHDR_MAGIC      0x4f545348

/**
 * struct shdr - signed header
 * @magic:      magic number must match SHDR_MAGIC
 * @img_type:   image type, values defined by enum shdr_img_type
 * @img_size:   image size in bytes
 * @algo:       algorithm, defined by public key algorithms TEE_ALG_*
 *              from TEE Internal API specification
 * @hash_size:  size of the signed hash
 * @sig_size:   size of the signature
 * @hash:       hash of an image
 * @sig:        signature of @hash
 */
struct shdr {
        UINT32 magic;
        UINT32 img_type;
        UINT32 img_size;
        UINT32 algo;
        USHORT hash_size;
        USHORT sig_size;
        /*
         * Commented out element used to visualize the layout dynamic part
         * of the struct.
         *
         * hash is accessed through the macro SHDR_GET_HASH and
         * signature is accessed through the macro SHDR_GET_SIG
         *
         * UCHAR hash[hash_size];
         * UCHAR sig[sig_size];
         */
};

/**
 * struct shdr_bootstrap_ta - bootstrap TA subheader
 * @uuid:       UUID of the TA
 * @ta_version: Version of the TA
 */
struct shdr_bootstrap_ta {
        UCHAR uuid[16];
        UINT32 ta_version;
};

/**
 * struct shdr_encrypted_ta - encrypted TA header
 * @enc_algo:   authenticated encyption algorithm, defined by symmetric key
 *              algorithms TEE_ALG_* from TEE Internal API
 *              specification
 * @flags:      authenticated encyption flags
 * @iv_size:    size of the initialization vector
 * @tag_size:   size of the authentication tag
 * @iv:         initialization vector
 * @tag:        authentication tag
 */
struct shdr_encrypted_ta {
        UINT32 enc_algo;
        UINT32 flags;
        USHORT iv_size;
        USHORT tag_size;
        /*
         * Commented out element used to visualize the layout dynamic part
         * of the struct.
         *
         * iv is accessed through the macro SHDR_ENC_GET_IV and
         * tag is accessed through the macro SHDR_ENC_GET_TAG
         *
         * UCHAR iv[iv_size];
         * UCHAR tag[tag_size];
         */
};

#define SHDR_ENC_KEY_TYPE_MASK  0x1

enum shdr_enc_key_type {
        SHDR_ENC_KEY_DEV_SPECIFIC = 0,
        SHDR_ENC_KEY_CLASS_WIDE = 1,
};

#define HASH_SIZE   32
#define TAG_SIZE    16
#define SIG_SIZE    256
#define IV_SIZE     12
/*
nonce = <unique random value>
ciphertext, tag = AES_GCM(<stripped ELF>)
hash = H(<struct shdr> || <struct shdr_bootstrap_ta> ||
         <struct shdr_encrypted_ta> || <nonce> || <tag> || <stripped ELF>)
signature = RSA-Sign(<hash>)
encrypted_binary = <struct shdr> || <hash> || <signature> ||
                   <struct shdr_bootstrap_ta> ||
                   <struct shdr_encrypted_ta> || <nonce> || <tag> ||
                   <ciphertext>
*/

LittleEndian();
shdr head_shdr;
UCHAR hash[HASH_SIZE];
UCHAR sig[SIG_SIZE];
shdr_bootstrap_ta bootstrap_ta;
shdr_encrypted_ta encrypted_ta;
UCHAR nonce[IV_SIZE];
UCHAR tag[TAG_SIZE];
```

## decrypt script

```c
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import struct
import sys

f = open(sys.argv[1], 'rb')
shdr = f.read(20)
(magic, img_type, img_size, algo, digest_len,
    sig_len) = struct.unpack('<IIIIHH', shdr)
# private key
key = 'b64d239b1f3c7d3b06506229cd8ff7c8af2bb4db2168621ac62c84948468c4f4'
# 
hash = f.read(32)
sig = f.read(256)
shdr_bootstrap_ta = f.read(20)
shdr_encrypted_ta = f.read(12)
nonce = f.read(12)
tag = f.read(16)
cipher = f.read()
print(len(cipher))
f.close()

print(f"nonce: {nonce}")
print(f"tag: {tag}")

gcm = AESGCM(bytes.fromhex(key))
plain = gcm.decrypt(nonce, cipher+tag, None)
f = open('dec.ta', 'wb')
f.write(plain)
f.close()
```

## ida

```c
typedef unsigned int size_t;

enum TEEC_ParamType {
    TEEC_NONE = 0x0,  /* unused parameter */
    TEEC_VALUE_INPUT = 0x01,  /* input type of value, refer TEEC_Value */
    TEEC_VALUE_OUTPUT = 0x02, /* output type of value, refer TEEC_Value */
    TEEC_VALUE_INOUT = 0x03,  /* value is used as both input and output, refer TEEC_Value */
    TEEC_MEMREF_TEMP_INPUT = 0x05,  /* input type of temp memory reference, refer TEEC_TempMemoryReference */
    TEEC_MEMREF_TEMP_OUTPUT = 0x06, /* output type of temp memory reference, refer TEEC_TempMemoryReference */
    TEEC_MEMREF_TEMP_INOUT = 0x07,  /* temp memory reference used as both input and output,
                                       refer TEEC_TempMemoryReference */
    TEEC_ION_INPUT = 0x08,  /* input type of icon memory reference, refer TEEC_IonReference */
    TEEC_ION_SGLIST_INPUT = 0x09, /* input type of ion memory block reference, refer TEEC_IonSglistReference */
    TEEC_MEMREF_SHARED_INOUT = 0x0a, /* no copy mem */
    TEEC_MEMREF_WHOLE = 0xc, /* use whole memory block, refer TEEC_RegisteredMemoryReference */
    TEEC_MEMREF_PARTIAL_INPUT = 0xd, /* input type of memory reference, refer TEEC_RegisteredMemoryReference */
    TEEC_MEMREF_PARTIAL_OUTPUT = 0xe, /* output type of memory reference, refer TEEC_RegisteredMemoryReference */
    TEEC_MEMREF_PARTIAL_INOUT = 0xf /* memory reference used as both input and output,
                                        refer TEEC_RegisteredMemoryReference */
};

struct TEE_VALUE_Param
{
    size_t a;
    size_t b;
};

struct TEE_MEMREF_Param
{
    void *buffer;
    size_t size;
};

union TEE_Param
{
    struct TEE_VALUE_Param value;
    struct TEE_MEMREF_Param memref;
};
```