import pytest
from sygna_bridge_util.validator import validate_private_key, validate_transfer_id, validate_expire_date
from sygna_bridge_util.config import EXPIRE_DATE_MIN_OFFSET
from freezegun import freeze_time


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


def test_validate_expire_date():
    """should raise exception if expire_date is not valid"""
    with pytest.raises(TypeError) as excinfo:
        validate_expire_date('123')
    assert "Expect expire_date to be <class 'int'>, got <class 'str'>" == str(
        excinfo.value)

    with pytest.raises(TypeError) as excinfo:
        validate_expire_date({'key': 'value'})
    assert "Expect expire_date to be <class 'int'>, got <class 'dict'>" == str(
        excinfo.value)

    freezer = freeze_time("2020-02-28 09:30:28")
    freezer.start()
    with pytest.raises(ValueError) as excinfo:
        validate_expire_date(1582885828)  # GMT 2020-02-28 10:30:28
    assert "expire_date should be at least {0} seconds away from the current time.".format(
        EXPIRE_DATE_MIN_OFFSET / 1000) == str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        validate_expire_date(1582882365000)  # GMT 2020-02-28 09:32:45:000
    assert "expire_date should be at least {0} seconds away from the current time.".format(
        EXPIRE_DATE_MIN_OFFSET / 1000) == str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        validate_expire_date(1582876947000)  # GMT 2020-02-28 08:02:27:000
    assert "expire_date should be at least {0} seconds away from the current time.".format(
        EXPIRE_DATE_MIN_OFFSET / 1000) == str(excinfo.value)

    try:
        validate_expire_date(1582885828000)  # GMT 2020-02-28 10:30:28:000
        validate_expire_date(1582882408000)  # GMT 2020-02-28 09:33:28:000
    except (TypeError, ValueError):
        pytest.fail("Unexpected TypeError or ValueError")

    freezer.stop()


if __name__ == '__main__':
    test_validate_private_key()
    test_validate_transfer_id()
    test_validate_expire_date()
