package = "lua-blockchain-crypto"
version = "dev-1"
source = {
   url = "git+https://github.com/MrSyabro/lua-blockchain-crypto.git" -- We don't have one yet
}
description = {
   summary = "Blockchain crypto library",
   detailed = [[This is the binding of the libsecp256k1
   library.  Allows you to sign messages using the secp256k1
   curve, as well as calculate the keccak256 hash.
   ]], 
   homepage = "https://github.com/MrSyabro/lua-blockchain-crypto", -- We don't have one yet
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
		  libraries = {"secp256k1"},
		  incdirs = {"$(LIBSECP256K1_INCDIR)"},
      libdirs = {"$(LIBSECP256K1_LIBDIR)"}
		}
	}
	-- Now we need to tell it what to build.
}

external_dependencies = {
   LIBSECP256K1 = {
      header = "secp256k1.h"
   }
}
