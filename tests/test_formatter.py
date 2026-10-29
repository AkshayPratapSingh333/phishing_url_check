import io

from src.formatter import Formatter


class Cp1252Stream(io.StringIO):
    encoding = "cp1252"


def test_formatter_uses_ascii_fallback_for_cp1252_stream():
    stream = Cp1252Stream()

    Formatter(stream=stream, use_colour=False).print_banner()

    output = stream.getvalue()
    assert "[shield]" in output
    assert output.isascii()
