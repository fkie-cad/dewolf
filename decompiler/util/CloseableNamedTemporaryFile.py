import os
from contextlib import contextmanager
from tempfile import NamedTemporaryFile


@contextmanager
def closeable_temporary_file(**kwargs):
    """
    Context manager wrapper for NamedTemporaryFile, which allows
    closing the file handle without deleting the underling file.
    Deletion is delegated to the context manager closing.

    Note: With Python 3.12, a new parameter 'delete_on_close' is introduced
    for NamedTemporaryFile which accomplishes the same thing. Consequently,
    this api should be replaced when the code is updated to 3.12.
    """

    kwargs["delete"] = False
    with NamedTemporaryFile(**kwargs) as file:
        try:
            yield file
        finally:
            os.remove(file.name)
