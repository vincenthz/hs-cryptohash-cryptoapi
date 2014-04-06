{-# LANGUAGE CPP #-}
{-# LANGUAGE MultiParamTypeClasses #-}
-- |
-- Module      : Crypto.Hash.CryptoAPI
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Cryptohash API exported through crypto-api.
--
-- Note: Current version (0.10) of crypto-api suffers a small performance problem.
-- see <http://tab.snarc.org/others/benchmark-cryptohash-0.8.html>.
-- Hopefully, future versions will fix this.
--
module Crypto.Hash.CryptoAPI
    ( MD2
    , MD4
    , MD5
    , SHA1
    , SHA224
    , SHA256
    , SHA384
    , SHA512
    , Skein256_256
    , Skein512_512
    , RIPEMD160
    , Tiger
    , Whirlpool
    , Hash(..)
    -- * Contexts
    , CTXMD2, CTXMD4, CTXMD5, CTXRIPEMD160, CTXSHA1, CTXSHA224
    , CTXSHA256, CTXSHA384, CTXSHA512, CTXSkein256_256, CTXSkein512_512
    , CTXTiger, CTXWhirlpool
    ) where

import qualified Crypto.Hash.MD2 as MD2 (Ctx(..), init, update, finalize, hash, hashlazy)
import qualified Crypto.Hash.MD4 as MD4 (Ctx(..), init, update, finalize, hash, hashlazy)
import qualified Crypto.Hash.MD5 as MD5 (Ctx(..), init, update, finalize, hash, hashlazy)
import qualified Crypto.Hash.SHA1 as SHA1 (Ctx(..), init, update, finalize, hash, hashlazy)
import qualified Crypto.Hash.SHA224 as SHA224 (Ctx(..), init, update, finalize, hash, hashlazy)
import qualified Crypto.Hash.SHA256 as SHA256 (Ctx(..), init, update, finalize, hash, hashlazy)
import qualified Crypto.Hash.SHA384 as SHA384 (Ctx(..), init, update, finalize, hash, hashlazy)
import qualified Crypto.Hash.SHA512 as SHA512 (Ctx(..), init, update, finalize, hash, hashlazy)
import qualified Crypto.Hash.SHA512t as SHA512t (Ctx(..), init, update, finalize, hash, hashlazy)
import qualified Crypto.Hash.SHA3 as SHA3 (Ctx(..), init, update, finalize, hash, hashlazy)
import qualified Crypto.Hash.RIPEMD160 as RIPEMD160 (Ctx(..), init, update, finalize, hash, hashlazy)
import qualified Crypto.Hash.Tiger as Tiger (Ctx(..), init, update, finalize, hash, hashlazy)
import qualified Crypto.Hash.Skein256 as Skein256 (Ctx(..), init, update, finalize, hash, hashlazy)
import qualified Crypto.Hash.Skein512 as Skein512 (Ctx(..), init, update, finalize, hash, hashlazy)
import qualified Crypto.Hash.Whirlpool as Whirlpool (Ctx(..), init, update, finalize, hash, hashlazy)

import Control.Monad (liftM)
import Data.ByteString (ByteString)
import Data.Serialize (Serialize(..))
import Data.Serialize.Get (getByteString)
import Data.Serialize.Put (putByteString)
import Data.Tagged (Tagged(..))
import Crypto.Classes (Hash(..), hash, hash')

-- 
-- need to redefine a context wrapper to not clash with the already existing
-- and avoid the "function dependencies conflict between instance declaration" error.
--
-- unfortunately haskell uses cpp in traditional mode to avoid problem, but traditional mode
-- doesn't do proper token concatenation, so need to define the ctxname in the macro
--

#define DEFINE_TYPE_AND_INSTANCES_SIMPLE(CTXNAME, MODULENAME, OUTPUTLEN, BLOCKLEN)    \
    DEFINE_TYPE_AND_INSTANCES(CTXNAME, MODULENAME, MODULENAME, OUTPUTLEN, BLOCKLEN)

#define DEFINE_TYPE_AND_INSTANCES(CTXNAME, NAME, MODULENAME, OUTPUTLEN, BLOCKLEN)    \
\
newtype CTXNAME = CTXNAME MODULENAME.Ctx; \
\
data NAME = NAME !ByteString deriving (Eq,Ord,Show); \
\
instance Serialize NAME where \
   { get          = liftM NAME (getByteString OUTPUTLEN) \
   ; put (NAME d) = putByteString d \
   }; \
\
instance Serialize CTXNAME where \
  { get                              = liftM (CTXNAME . MODULENAME.Ctx) get \
  ; put (CTXNAME (MODULENAME.Ctx c)) = put c \
  }; \
\
instance Hash CTXNAME NAME where \
   { outputLength    = Tagged (OUTPUTLEN * 8) \
   ; blockLength     = Tagged (BLOCKLEN * 8)  \
   ; initialCtx      = CTXNAME MODULENAME.init        \
   ; updateCtx (CTXNAME ctx) = CTXNAME . MODULENAME.update ctx      \
   ; finalize (CTXNAME ctx) bs = NAME $ MODULENAME.finalize (MODULENAME.update ctx bs) \
   ; hash  = NAME . MODULENAME.hashlazy

#define DEFINE_TYPE_AND_INSTANCES_WITHLEN(CTXNAME, NAME, ILEN, MODULENAME, OUTPUTLEN, BLOCKLEN)    \
\
newtype CTXNAME = CTXNAME MODULENAME.Ctx; \
\
data NAME = NAME !ByteString deriving (Eq,Ord,Show); \
\
instance Serialize NAME where \
   { get          = liftM NAME (getByteString OUTPUTLEN) \
   ; put (NAME d) = putByteString d \
   }; \
\
instance Hash CTXNAME NAME where \
   { outputLength    = Tagged (OUTPUTLEN * 8) \
   ; blockLength     = Tagged (BLOCKLEN * 8)  \
   ; initialCtx      = CTXNAME (MODULENAME.init ILEN) \
   ; updateCtx (CTXNAME ctx) = CTXNAME . MODULENAME.update ctx      \
   ; finalize (CTXNAME ctx) bs = NAME $ MODULENAME.finalize (MODULENAME.update ctx bs) \
   ; hash  = NAME . MODULENAME.hashlazy OUTPUTLEN


DEFINE_TYPE_AND_INSTANCES_SIMPLE(CTXMD2, MD2, 16, 16)
   ; hash' = MD2 . MD2.hash
   };

DEFINE_TYPE_AND_INSTANCES_SIMPLE(CTXMD4, MD4, 16, 64)
   ; hash' = MD4 . MD4.hash
   };

DEFINE_TYPE_AND_INSTANCES_SIMPLE(CTXMD5, MD5, 16, 64)
   ; hash' = MD5 . MD5.hash
   };

DEFINE_TYPE_AND_INSTANCES_SIMPLE(CTXSHA1, SHA1, 20, 64)
   ; hash' = SHA1 . SHA1.hash
   };

DEFINE_TYPE_AND_INSTANCES_SIMPLE(CTXSHA224, SHA224, 28, 64)
   ; hash' = SHA224 . SHA224.hash
   };

DEFINE_TYPE_AND_INSTANCES_SIMPLE(CTXSHA256, SHA256, 32, 64)
   ; hash' = SHA256 . SHA256.hash
   };

DEFINE_TYPE_AND_INSTANCES_SIMPLE(CTXSHA384, SHA384, 48, 128)
   ; hash' = SHA384 . SHA384.hash
   };

DEFINE_TYPE_AND_INSTANCES_SIMPLE(CTXSHA512, SHA512, 64, 128)
   ; hash' = SHA512 . SHA512.hash
   };

DEFINE_TYPE_AND_INSTANCES_SIMPLE(CTXRIPEMD160, RIPEMD160, 20, 64)
   ; hash' = RIPEMD160 . RIPEMD160.hash
   };

DEFINE_TYPE_AND_INSTANCES_SIMPLE(CTXTiger, Tiger, 24, 64)
   ; hash' = Tiger . Tiger.hash
   };

DEFINE_TYPE_AND_INSTANCES_SIMPLE(CTXWhirlpool, Whirlpool, 64, 64)
   ; hash' = Whirlpool . Whirlpool.hash
   };

DEFINE_TYPE_AND_INSTANCES_WITHLEN(CTXSkein256_256, Skein256_256, 256, Skein256, 32, 32)
   ; hash' = Skein256_256 . Skein256.hash 32
   };

DEFINE_TYPE_AND_INSTANCES_WITHLEN(CTXSkein512_512, Skein512_512, 512, Skein512, 64, 64)
   ; hash' = Skein512_512 . Skein512.hash 64
   };

