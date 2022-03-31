#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_recovery.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "keccak-tiny.h"
#include "random.h"
#include "rlp_serializer.h"

static int sign(unsigned char *seckey, unsigned char *data, unsigned char *out, int *recid) {
  unsigned char randomize[32];
  //unsigned char serialized_signature[65];
  secp256k1_ecdsa_recoverable_signature sig;

  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  if (!fill_random(randomize, sizeof(randomize))) {
    secp256k1_context_destroy(ctx);
    return -1;
  }

  if (!secp256k1_ec_seckey_verify(ctx, (const unsigned char*)seckey)) {
    secp256k1_context_destroy(ctx);
    return -2;
  }

  if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig, (const unsigned char*)data, (const unsigned char*)seckey, NULL, NULL)) {
    secp256k1_context_destroy(ctx);
    return -3;
  }

  if(!secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, out, recid, &sig)) {
    secp256k1_context_destroy(ctx);
    return -4;
  }

  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, out, *recid)) {
    secp256k1_context_destroy(ctx);
    return -5;
  }

  secp256k1_context_destroy(ctx);
  return 1;
}

static int l_sign(lua_State *L) {
  luaL_argcheck(L, lua_isstring(L, 1), 1, "must be seckey");
  luaL_argcheck(L, lua_isstring(L, 2), 2, "must be data");

  size_t data_len;
  const char *seckey = lua_tostring(L, 1);
  const char *data = lua_tolstring(L, 2, &data_len);
  unsigned char serialized_signature[64];
  int recid;

  int ret_val = sign((unsigned char *)seckey, (unsigned char*)data, serialized_signature, &recid);
  if (ret_val != 1) {
    lua_pushnil(L);
    switch (ret_val) {
      case -1: lua_pushstring(L, "error generate randomles");
      break;
      case -2: lua_pushstring(L, "bad seckey");
      break;
      case -3: lua_pushstring(L, "signing error");
      break;
      case -4: lua_pushstring(L, "signature serialization error");
      break;
      case -5: lua_pushstring(L, "signature parsing error");
      break;
      default: lua_pushstring(L, "undefined error");
    }
    return 2;
  }

  lua_pushlstring(L, (const char*)serialized_signature, (size_t)64);
  return 1;
}

static int l_get_pubkey(lua_State *L) {
  luaL_argcheck(L, lua_isstring(L, 1), 1, "must be seckey");

  const char *seckey = lua_tostring(L, 1);
  unsigned char randomize[32];
  unsigned char uncompressed_pubkey[65];
  secp256k1_pubkey pubkey;

  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  if (!fill_random(randomize, sizeof(randomize))) {
    secp256k1_context_destroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "failed to generate randomness");
    return 2;
  }

  if (!secp256k1_ec_seckey_verify(ctx, (unsigned char *)seckey)) {
    secp256k1_context_destroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "invalid secret key");
    return 2;
  }

  if (!secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char*)seckey)) {
    secp256k1_context_destroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "error pubkey creating");
    return 2;
  }

  size_t len = sizeof(uncompressed_pubkey);
  if (!secp256k1_ec_pubkey_serialize(ctx, uncompressed_pubkey, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
    secp256k1_context_destroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "Failed compressing the public key");
    return 2;
  }

  secp256k1_context_destroy(ctx);

  lua_pushlstring(L, (const char*)uncompressed_pubkey, len);
  return 1;
}

static int l_gen_seckey(lua_State *L) {
  unsigned char seckey[32];
  unsigned char randomize[32];

  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  if (!fill_random(randomize, sizeof(randomize))) {
    lua_pushnil(L);
    lua_pushstring(L, "failed to generate randomness");
    return 2;
  }

  while (1) {
    if (!fill_random(seckey, sizeof(seckey))) {
      secp256k1_context_destroy(ctx);
      lua_pushnil(L);
      lua_pushstring(L, "failed to generate randomles");
      return 2;
    }
    if (secp256k1_ec_seckey_verify(ctx, seckey)) {
      break;
    }
  }

  secp256k1_context_destroy(ctx);

  lua_pushlstring(L, (const char*)seckey, (size_t)32);
  return 1;
}

static int l_keccak256(lua_State *L) {
  unsigned char hash[32];
  size_t in_len;
  const char *input = lua_tolstring(L, 1, &in_len);

  keccak_256((uint8_t*)hash, (size_t)32, (const uint8_t*)input, in_len);

  lua_pushlstring(L, (const char *)hash, (size_t)32);
  return 1;
}

static RlpElement_t *l_torlp(lua_State *L, const char *key) {
  RlpElement_t *out = malloc(sizeof(RlpElement_t));
  lua_getfield(L, 1, key);
  int t = lua_type(L, 2);
  switch (t) {
    case LUA_TNUMBER: {
      out->len = sizeof(int);
      int num = lua_tointeger(L, 2);
      out->buff = (uint8_t *)malloc(sizeof(int));
      memcpy((void*)out->buff, &num, sizeof(int));
      out->type = (out->len == 4) ? RLP_TYPE_INT32 : RLP_TYPE_INT64;
      break;
    }
    case LUA_TSTRING: {
      const char *str = lua_tolstring(L, 2, &out->len);
      out->buff = (uint8_t *)calloc(out->len, sizeof(char));
      memcpy((void*)out->buff, str, out->len);
      out->type = RLP_TYPE_BYTE_ARRAY;
      break;
    }
    default: {
      out->len = 0;
      out->buff = NULL;
      out->type = RLP_TYPE_BYTE_ARRAY;
    }
  }

  lua_remove(L, 2);
  return out;
}

static void free_rlplist(const RlpElement_t *const *list, size_t n) {
  for (int i = 0; i < n; i++) {
    RlpElement_t *el = (RlpElement_t *)list[i];
    if (el->len > 0) {
      free((void*)el->buff);
    }
    free((void *)el);
  }
}

static int l_serialize_rlp (lua_State *L) {
  luaL_argcheck(L, lua_istable(L, 1), 1, "must be table of transaction");

  uint8_t *rawtx = calloc(4096, sizeof(uint8_t));

  RlpElement_t *nonce = l_torlp(L, "nonce");
  RlpElement_t *gas_price = l_torlp(L, "gasPrice");
  RlpElement_t *gas_limit = l_torlp(L, "gasLimit");
  RlpElement_t *to = l_torlp(L, "to");
  RlpElement_t *value = l_torlp(L, "value");
  RlpElement_t *data = l_torlp(L, "data");
  RlpElement_t *v = l_torlp(L, "v");
  RlpElement_t *r = l_torlp(L, "r");
  RlpElement_t *s = l_torlp(L, "s");

  RlpElement_t const *const txList[] = {
    nonce,
    gas_price,
    gas_limit,
    to,
    value,
    data,
    v, r, s
  };
  
  int outlen = 0;
  outlen = rlp_encode_list(rawtx, (size_t)4096, txList, sizeof(txList)/sizeof(txList[0]));
  
  free_rlplist(txList, sizeof(txList)/sizeof(txList[0]));

  if (outlen < 0) {
    lua_pushnumber(L, outlen);
    return 1;
  }

  lua_pushlstring(L, (const char *)rawtx, outlen);
  return 1;
}


static const struct luaL_Reg crypto [] = {
  {
    "sign",
    l_sign
  },
  {
    "sha3",
    l_keccak256
  },
  {
    "new_seckey",
    l_gen_seckey
  },
  {
    "sec_to_pub",
    l_get_pubkey
  },
  {
    "serializeTx",
    l_serialize_rlp
  },
  {
    NULL,
    NULL
  }
  /* sentinel */
};

int luaopen_crypto(lua_State *L) {
  luaL_newlib(L, crypto);
  return 1;
}