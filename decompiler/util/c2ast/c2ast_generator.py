import os
import sys

sys.path.append(".") # for decompiler package imports

from c2ast_visitor import PyCNodeVisitor
from decompiler.task import DecompilerTask
from pycparser import c_parser, parse_file
from pycparser.c_ast import FileAST, FuncDef

FAKE_LIBC_INCLUDE = "-I" + os.path.dirname(__file__) + "/" + "fake_libc_include"

def _getSubAstForFunction(head: FileAST, functionName: str) -> FuncDef:
    for node in head.ext:
        if isinstance(node, FuncDef) and node.decl.name == functionName:
            return node
    raise Exception(f"Function '{functionName}' is not in ast")


class C2DeWolfASTGenerator:
    """"""
    @classmethod
    def generateFromFile(cls, file: str, method: str) -> DecompilerTask:
        pycAst = parse_file(file, use_cpp=True, cpp_args=FAKE_LIBC_INCLUDE)
        return cls._convertToDeWolfAst(_getSubAstForFunction(pycAst, method))

    @classmethod
    def generateFromString(cls, code: str, method: str) -> DecompilerTask:
        parser = c_parser.CParser()
        pycAst = parser.parse(code, filename="<none>")
        return cls._convertToDeWolfAst(_getSubAstForFunction(pycAst, method))

    @classmethod
    def _convertToDeWolfAst(cls, pycAst: FuncDef) -> DecompilerTask:
        visitor = PyCNodeVisitor()
        visitor.visit(pycAst)
        return DecompilerTask(
            cfg=None,
            options=None,
            ast=visitor._ast,
            name=visitor._function_name,
            function_parameters=visitor._function_params,
            function_return_type=visitor._return_type,
        )


from decompiler.util.decoration import DecoratedAST

if __name__ == '__main__':
    task = C2DeWolfASTGenerator.generateFromFile("/home/neoquix/Git-Repos/_DeWolfTesting/main.c", "main")
    DecoratedAST.from_ast(task._ast).export_plot("/tmp/AST.png")
    #DecoratedAST.print_ascii(task._ast)
