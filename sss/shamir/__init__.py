"""Merged SSS package: Shamir secret sharing and variants.

Modules:
    core         -- Shamir (t+1,n) sharing over GF(p), byte mode, Lagrange
    gf           -- prime field GF(p, q, g, h) with Pedersen commitments
    gf256        -- GF(256) byte field
    format       -- wire format for share blobs (session, checksum, digest)
    vss          -- Feldman (1987) + Pedersen (1991) verifiable sharing
    robust       -- Berlekamp-Welch error correction + Rabin-Ben-Or MACs
    proactive    -- Herzberg et al. (1995) refresh / share recovery
    dkg          -- Pedersen (1991) distributed key generation
    pvss         -- Schoenmakers (1999) publicly verifiable sharing
    hybrid       -- Krawczyk (1994) hybrid (encrypt-then-share) scheme
    multisecret  -- Yang-Chang-Hwang (2004) multi-secret sharing
    weighted     -- weighted thresholds via Shamir virtualization
    hierarchical -- Tassa (2007) Birkhoff derivative hierarchical sharing
    reshare      -- Desmedt-Jarecki (1993) verifiable redistribution
    unified      -- one construction absorbing the lineage: Pedersen shares +
                    Rabin-Ben-Or MACs + Berlekamp-Welch + digest point +
                    refresh + redistribution + BGW addition/multiplication +
                    threshold exponentiation + batch verification + share
                    re-issuance + ZK share proofs + seal/open
"""

from . import (core, dkg, format, gf, gf256, hierarchical, hybrid,
               multisecret, proactive, pvss, reshare, robust, unified, vss)

__version__ = "0.1.0"
