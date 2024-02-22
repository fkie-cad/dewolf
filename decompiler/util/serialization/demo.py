# Demo for AST serialization
# Move me to the top level directory of the decompiler to make me work

# Get something decompiled to get its data
from decompile import Decompiler

decompiler = Decompiler.from_path("tests/samples/bin/systemtests/32/0/test_loop")
result = decompiler.decompile(["test7"])
task = result.tasks[0]

# Serialize an AST
from decompiler.util.serialization.ast_serializer import AstSerializer

serializer = AstSerializer()
data = serializer.serialize(task.syntax_tree)

# Save the serialized data to disk (compressed)
from gzip import open as gopen
from json import dumps

with gopen("ast.gz", "wb") as buffer:
    buffer.write(dumps(data).encode("utf-8"))

# Load the serialized data from disk
from json import load

with gopen("ast.gz", "rb") as buffer:
    data = load(buffer)

# Load an AST from serialized data
ast = serializer.deserialize(data)

# Plot it nicely
from decompiler.util.decoration import DecoratedAST

DecoratedAST.from_ast(task.syntax_tree).export_plot("before")
DecoratedAST.from_ast(ast).export_plot("after")

assert ast == task.syntax_tree
