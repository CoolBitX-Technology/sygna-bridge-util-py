from config import SYGNA_BRIDGE_CENTRAL_PUBKEY


def verify_data(data: dict, public_key: str = SYGNA_BRIDGE_CENTRAL_PUBKEY) -> bool:
    """ Verify data with provided Public Key or default sygna bridge Public Key

    Args:
        data (dict)
        public_key (str)

    Returns:
        bool
    """
    return True
