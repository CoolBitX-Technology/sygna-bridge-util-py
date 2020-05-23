import pytest
from sygna_bridge_util.validator import validate_private_key, validate_transfer_id


def test_validate_private_key():
    """should raise exception if private_key is not valid"""
    with pytest.raises(TypeError) as excinfo:
        validate_private_key(123)
    assert "Expect private_key to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    with pytest.raises(TypeError) as excinfo:
        validate_private_key({'key': 'value'})
    assert "Expect private_key to be <class 'str'>, got <class 'dict'>" == str(
        excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        validate_private_key('')
    assert "private_key is too short" == str(
        excinfo.value)

    try:
        validate_private_key('123')
        validate_private_key('1')
    except (TypeError, ValueError):
        pytest.fail("Unexpected TypeError or ValueError")


def test_validate_transfer_id():
    """should raise exception if transfer_id is not valid"""
    with pytest.raises(TypeError) as excinfo:
        validate_transfer_id(123)
    assert "Expect transfer_id to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    with pytest.raises(TypeError) as excinfo:
        validate_transfer_id({'key': 'value'})
    assert "Expect transfer_id to be <class 'str'>, got <class 'dict'>" == str(
        excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        validate_transfer_id('')
    assert "transfer_id length should be 64" == str(
        excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        validate_transfer_id('6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b1')  # len =65
    assert "transfer_id length should be 64" == str(
        excinfo.value)

    try:
        validate_transfer_id('6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b')  # len =64
    except (TypeError, ValueError):
        pytest.fail("Unexpected TypeError or ValueError")


if __name__ == '__main__':
    test_validate_private_key()
    test_validate_transfer_id()