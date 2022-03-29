package = "lua-blockchain-crypto"
version = "dev-1"
source = {
   url = "git+https://github.com/MrSyabro/web3.lua.git" -- We don't have one yet
}
description = {
   summary = "Blockchain crypto library",
   homepage = "https://github.com/MrSyabro/web3.lua", -- We don't have one yet
   license = "MIT/X11" -- or whatever you like
}
dependencies = {
   "lua >= 5.2",
   -- If you depend on other rocks, add them here
}
build = {
	type = "builtin",
	modules = {
		crypto = {
		  sources = {
		    "src/keccak-tiny.c",
		    "src/crypto.c"
		  },
		  libraries = {"libsecp256k1"},
		  incdirs = {"$(LIBSECP256K1_INCDIR)"},
      libdirs = {"$(LIBSECP256K1_LIBDIR)"}
		}
	}
	-- Now we need to tell it what to build.
}
