import os
import sys

sys.path.append(".") # for decompiler package imports (if started from repo root)

import tarfile
from tempfile import TemporaryDirectory

from c2ast_visitor import PyCNodeVisitor
from decompiler.task import DecompilerTask
from pycparser import c_parser, parse_file
from pycparser.c_ast import Decl, FileAST, FuncDef

FAKE_LIBC_ZIP= os.path.dirname(__file__) + "/fake_libc_include.tar.gz"


class C2DeWolfASTGenerator:
    """ Wrapper for PyCASTVisitor. Usage stuff:
        - you need to have every variable (including globals) defines, otherwise the code does not work
            - don't use global strings, they will NOT be resolved 
        - typedefs are not accounted for, therefore they will yield a CustomType
        - if you get a parser error from pycparser then throw your input in cpp
        """

    def __init__(self) -> None:
        self._visitor = PyCNodeVisitor()


    def _getSubAstForFunction(self, head: FileAST, functionName: str) -> FuncDef:
        """Iterate over every node in the file. Return declarations, typedefs and the requested method to the visitor"""
        for node in head.ext:
            # Can be enabled if structs and enums are supported, otherwise it does not work
            #if isinstance(node, Typedef):
            #    self._visitor.visit(node) 
            if isinstance(node, Decl):
                self._visitor.visit(node)
            if isinstance(node, FuncDef) and node.decl.name == functionName:
                return node
        raise ValueError(f"Function '{functionName}' is not in ast")


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


    def generateFromFile(self, file: str, method: str) -> DecompilerTask:
        """Generate DeWolf-AST from a given file with methodname"""
        with tarfile.open(FAKE_LIBC_ZIP, "r:gz") as tgz, TemporaryDirectory() as dir:
            tgz.extractall(dir)
            pycAst = parse_file(file, use_cpp=True, cpp_args="-I" + dir + "/fake_libc_include")
        return self._convertToDeWolfAst(self._getSubAstForFunction(pycAst, method))


    def generateFromString(self, code: str, method: str) -> DecompilerTask:
        """Generate DeWolf-AST from a given string of code with methodname"""
        parser = c_parser.CParser()
        pycAst = parser.parse(code, filename="<none>")
        return self._convertToDeWolfAst(self._getSubAstForFunction(pycAst, method))


from decompiler.util.decoration import DecoratedAST

CODE = r"""
int sub_10b2c() {
    unsigned int uiVar15;
    int iVar14;
    sub_10caf("eax: ");
    iVar14 = data_12000;
    sub_10cc7(iVar14);
    sub_10caf(data_10dcb);
    sub_10caf("ebx: ");
    iVar14 = data_12004;
    sub_10cc7(iVar14);
    sub_10caf(data_10dcb);
    sub_10caf("ecx: ");
    iVar14 = data_12008;
    sub_10cc7(iVar14);
    sub_10caf(data_10dcb);
    sub_10caf("edx: ");
    iVar14 = data_1200c;
    sub_10cc7(iVar14);
    sub_10caf(data_10dcd);
    sub_10caf("esi: ");
    iVar14 = data_12010;
    sub_10cc7(iVar14);
    sub_10caf(data_10dcb);
    sub_10caf("edi: ");
    iVar14 = data_12014;
    sub_10cc7(iVar14);
    sub_10caf(data_10dcb);
    sub_10caf("esp: ");
    iVar14 = data_12018;
    sub_10cc7(iVar14);
    sub_10caf(data_10dcb);
    sub_10caf("ebp: ");
    iVar14 = data_1201c;
    sub_10cc7(iVar14);
    sub_10caf(data_10dcd);
    sub_10caf("idt: ");
    uiVar15 = (unsigned short)data_12020;
    sub_10cc7(uiVar15);
    sub_10caf(data_10dcb);
    iVar14 = data_12022;
    sub_10cc7(iVar14);
    sub_10caf(data_10dcd);
    sub_10caf("gdt: ");
    uiVar15 = (unsigned short)data_12026;
    sub_10cc7(uiVar15);
    sub_10caf(data_10dcb);
    iVar14 = data_12028;
    sub_10cc7(iVar14);
    iVar14 = sub_10caf(data_10dcd);
    return iVar14;
}

"""

if __name__ == '__main__':
    task = C2DeWolfASTGenerator().generateFromString(CODE, "sub_10b2c")
    #task = C2DeWolfASTGenerator().generateFromFile("/home/neoquix/Git-Repos/_DeWolfTesting/main.c", "main")
    DecoratedAST.from_ast(task._ast).export_plot("/tmp/AST.png")
    DecoratedAST.print_ascii(task._ast)