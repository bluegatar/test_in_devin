import base64
import json

from aliyun_m3u8_downloader import aliyun_api as api


def test_sign_strings():
    assert api._sign_str(api._SIGN1) == "493vpa"
    assert api._sign_str(api._SIGN2) == "ZZ"


def test_decode_plain_play_auth():
    payload = {"AccessKeyId": "ak", "AccessKeySecret": "secret"}
    token = base64.b64encode(json.dumps(payload).encode()).decode()
    assert json.loads(api.decode_play_auth(token)) == payload


def test_build_play_info_url_signed_query():
    payload = {
        "AccessKeyId": "ak",
        "AccessKeySecret": "secret",
        "AuthInfo": "{}",
        "Region": "cn-beijing",
        "VideoMeta": {"VideoId": "vid123"},
    }
    token = base64.b64encode(json.dumps(payload).encode()).decode()
    url = api.build_play_info_url("the-rand", token, api.PlayInfoOption())
    assert url.startswith("https://vod.cn-beijing.aliyuncs.com/?")
    assert "Action=GetPlayInfo" in url
    assert "VideoId=vid123" in url
    assert "Signature=" in url
    assert "Rand=the-rand" in url
