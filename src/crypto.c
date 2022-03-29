#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>
#include "keccak-tiny.h"
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include "random.h"

static int l_sign(lua_State *L)
{
  luaL_argcheck(L, lua_isstring(L, 1), 1, "must be seckey");
  luaL_argcheck(L, lua_isstring(L, 2), 2, "must be data");
  
  size_t data_len;
  const char *seckey = lua_tostring(L, 1);
  const char *data = lua_tolstring(L, 2, &data_len);
  unsigned char randomize[32];
  unsigned char serialized_signature[64];
  secp256k1_ecdsa_signature sig;
  
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  if (!fill_random(randomize, sizeof(randomize)))
  {
    secp256k1_context_destroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "failed to generate randomness");
    return 2;
  }
  
  if (!secp256k1_ec_seckey_verify(ctx, (const unsigned char*)seckey))
  {
    secp256k1_context_destroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "invalid secret key");
    return 2;
  }
  
  if (!secp256k1_ecdsa_sign(ctx, &sig, (const unsigned char*)data, (const unsigned char*)seckey, NULL, NULL))
  {
    secp256k1_context_destroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "signing error");
    return 2;
  }
  
  if(!secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, &sig))
  {
    secp256k1_context_destroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "signature serialization error");
    return 2;
  }
  
  if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, serialized_signature)) 
  {
    secp256k1_context_destroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "Failed parsing the signature");
    return 2;
  }
  
  secp256k1_context_destroy(ctx);
  
  lua_pushlstring(L, (const char*)serialized_signature, (size_t)64);
  return 1;
}

static int l_get_pubkey(lua_State *L)
{
  luaL_argcheck(L, lua_isstring(L, 1), 1, "must be seckey");
  
  const char *seckey = lua_tostring(L, 1);
  unsigned char randomize[32];
  unsigned char uncompressed_pubkey[65];
  secp256k1_pubkey pubkey;
  
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY );
  if (!fill_random(randomize, sizeof(randomize)))
  {
    secp256k1_context_destroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "failed to generate randomness");
    return 2;
  }
  
  if (!secp256k1_ec_seckey_verify(ctx, (unsigned char *)seckey)) 
  {
    secp256k1_context_destroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "invalid secret key");
    return 2;
  }
  
  if (!secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char*)seckey))
  {
    secp256k1_context_destroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "error pubkey creating");
    return 2;
  }
  
  size_t len = sizeof(uncompressed_pubkey);
  if (!secp256k1_ec_pubkey_serialize(ctx, uncompressed_pubkey, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED))
  {
    secp256k1_context_destroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "Failed compressing the public key");
    return 2;
  }
  
  secp256k1_context_destroy(ctx);
  
  lua_pushlstring(L, (const char*)uncompressed_pubkey, len);
  return 1;
}

static int l_gen_seckey(lua_State *L)
{
  unsigned char seckey[32];
  unsigned char randomize[32];
    
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  if (!fill_random(randomize, sizeof(randomize))) {
    lua_pushnil(L);
    lua_pushstring(L, "failed to generate randomness");
    return 2;
  }
  
  while (1) {
    if (!fill_random(seckey, sizeof(seckey))) 
    {
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

static int l_keccak256(lua_State *L)
{
  unsigned char hash[32];
  size_t in_len;
  const char *input = lua_tolstring(L, 1, &in_len);
  
  keccak_256((uint8_t*)hash, (size_t)32, (const uint8_t*)input, in_len);
  
  lua_pushlstring(L, (const char *)hash, (size_t)32);
  return 1;
}

static const struct luaL_Reg crypto [] = {
  {"sign", l_sign},
  {"keccak256", l_keccak256},
  {"new_seckey", l_gen_seckey},
  {"sec_to_pub", l_get_pubkey},
  {NULL, NULL}
  /* sentinel */
};

int luaopen_crypto(lua_State *L)
{
  luaL_newlib(L, crypto);
  return 1;
}