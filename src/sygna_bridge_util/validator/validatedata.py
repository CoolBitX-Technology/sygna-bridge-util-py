def validate_private_key(private_key: str) -> None:
    if type(private_key) is not str:
        raise TypeError('Expect {0} to be {1}, got {2}'.format(
            'private_key',
            str,
            type(private_key))
        )

    if len(private_key) < 1:
        raise ValueError('private_key is too short')


def validate_transfer_id(transfer_id: str) -> None:
    if type(transfer_id) is not str:
        raise TypeError('Expect {0} to be {1}, got {2}'.format(
            'transfer_id',
            str,
            type(transfer_id))
        )

    if len(transfer_id) != 64:
        raise ValueError('transfer_id length should be 64')