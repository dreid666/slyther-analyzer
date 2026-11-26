OP_CHECKSIG = 0xac

def validate(script):
    return OP_CHECKSIG in script
