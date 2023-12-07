import os
from contextlib import contextmanager
from tempfile import NamedTemporaryFile


@contextmanager
def CloseableNamedTemporaryFile(**kwargs):
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
            # Close the file to be sure that it can be removed.
            # It's ok if the file was already closed because NamedTemporaryFile's close method is idempotent.
            file.close()
            # If file was already deleted outside of this contextmanager, this will crash
            # (just like the original NamedTemporaryFile).
            # On NT, this might also crash if another handle to this file is still open
            os.remove(file.name)
