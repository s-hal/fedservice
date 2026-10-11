from cryptojwt.jwt import utc_time_sans_frac

from fedservice.trust_mark_entity import FileDB


def test_add_and_find(tmp_path):
    file_name = str(tmp_path / 'sirtfi')

    _db = FileDB(**{
        "https://refeds.org/sirtfi": file_name
    })

    _db.add({
        'trust_mark_type': "https://refeds.org/sirtfi",
        "sub": "https://example.com",
        'iat': utc_time_sans_frac()}
    )

    res = _db.find(trust_mark_type="https://refeds.org/sirtfi", sub="https://example.com")
    assert res
