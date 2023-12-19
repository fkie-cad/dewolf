import os

from decompiler.util.closeable_named_temporary_file import CloseableNamedTemporaryFile


class TestCloseableNamedTemporaryFile:
    def test_usage_after_closing(self):
        with CloseableNamedTemporaryFile(mode="w", encoding="utf-8") as file:
            file.write("test")
            file.close()
            with open(file.name, "r", encoding="utf-8") as reopened_file:
                assert reopened_file.read() == "test"

    def test_deletion_with_close(self):
        with CloseableNamedTemporaryFile(mode="w") as file:
            file.close()
        assert not os.path.exists(file.name)

    def test_deletion_without_close(self):
        with CloseableNamedTemporaryFile(mode="w") as file:
            pass
        assert not os.path.exists(file.name)

    def test_close_after_delete(self):
        with CloseableNamedTemporaryFile(mode="w") as file:
            pass
        file.close()
