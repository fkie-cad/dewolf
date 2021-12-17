"""Module testing whether dewolf is still threadsafe and z3 does not generate segmentationfaults anymore."""
import faulthandler
from concurrent.futures import ThreadPoolExecutor

from decompile import Decompiler

faulthandler.enable()


decompiler = Decompiler.from_path("tests/samples/bin/systemtests/32/0/test_loop")
results = []

with ThreadPoolExecutor(max_workers=2) as executor:
    for function in decompiler._frontend.get_all_function_names():
        results.append(executor.submit(decompiler.decompile, function))

for future in results:
    future.exception()
