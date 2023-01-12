import pytest
from decompiler.util.commandline import switch_to_dict


class TestSwitchToDict:
    """Test the function converting unused command line arguments to decompiler options."""

    @pytest.mark.parametrize(
        "commandline, result",
        [(("--category.name", "value"), {"category": {"name": "value"}}), (("--category.name",), {"category": {"name": True}})],
    )
    def test_conversion(self, commandline, result):
        assert switch_to_dict(list(commandline)) == result

    @pytest.mark.parametrize(
        "commandline",
        [
            ["test"],
            ["-pipeline.debug"],
            ["-debug"],
        ],
    )
    def test_error(self, commandline):
        """Check if the function raises an error on malformed command line arguments."""
        with pytest.raises(ValueError):
            switch_to_dict(commandline)
