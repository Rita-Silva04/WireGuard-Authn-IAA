from cryptography.hazmat.primitives import hashes, hmac

def hash_data( algorithm, data ):
    h = hashes.Hash( algorithm )
    h.update( data )
    return h.finalize()

def hmac_data( key, algorithm, data ):
    h = hmac.HMAC( key, algorithm )
    h.update( data )
    return h.finalize()
