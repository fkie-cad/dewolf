import os
import sys

sys.path.append(".") # for decompiler package imports

from c2ast_visitor import PyCNodeVisitor
from decompiler.task import DecompilerTask
from pycparser import c_parser, parse_file
from pycparser.c_ast import Decl, FileAST, FuncDef, Typedef

FAKE_LIBC_INCLUDE = "-I" + os.path.dirname(__file__) + "/" + "fake_libc_include"


class C2DeWolfASTGenerator:
    """ Wrapper for PyCASTVisitor. Needs to be an object for typedefs to work."""

    def __init__(self) -> None:
        self._visitor = PyCNodeVisitor()


    def _getSubAstForFunction(self, head: FileAST, functionName: str) -> FuncDef:
        """Iterate over every node in the file. Parse typedefs into visitor + return function node"""
        for node in head.ext:
            #if isinstance(node, Typedef):
            #    self._visitor.visit(node) # Can be enabled if structs and enums are supported, otherwise it does not work
            if isinstance(node, Decl):
                self._visitor.visit(node)
            if isinstance(node, FuncDef) and node.decl.name == functionName:
                return node
        raise Exception(f"Function '{functionName}' is not in ast")


    def generateFromFile(self, file: str, method: str) -> DecompilerTask:
        """Generate DeWolf-AST from a given file with methodname"""
        pycAst = parse_file(file, use_cpp=True, cpp_args=FAKE_LIBC_INCLUDE)
        return self._convertToDeWolfAst(self._getSubAstForFunction(pycAst, method))


    def generateFromString(self, code: str, method: str) -> DecompilerTask:
        """Generate DeWolf-AST from a given string of code with methodname"""
        parser = c_parser.CParser()
        pycAst = parser.parse(code, filename="<none>")
        return self._convertToDeWolfAst(self._getSubAstForFunction(pycAst, method))


    def _convertToDeWolfAst(self, pycAst: FuncDef) -> DecompilerTask:
        """Visit every node in the function and create DecompilerTask"""
        self._visitor.visit(pycAst)
        return DecompilerTask(
            cfg=None,
            options=None,
            ast=self._visitor._ast,
            name=self._visitor._function_name,
            function_parameters=self._visitor._function_params,
            function_return_type=self._visitor._return_type,
        )


from decompiler.util.decoration import DecoratedAST

if __name__ == '__main__':
    task = C2DeWolfASTGenerator().generateFromFile("/home/neoquix/Git-Repos/_DeWolfTesting/main.c", "main")
    DecoratedAST.from_ast(task._ast).export_plot("/tmp/AST.png")
    DecoratedAST.print_ascii(task._ast)
