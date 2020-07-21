import pytest
from sygna_bridge_util.validator import validate_private_key


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


if __name__ == '__main__':
    test_validate_private_key()
