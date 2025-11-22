#-----------------------------------------------------------------
# pycparser: func_calls.py
#
# Using pycparser for printing out all the calls of some function
# in a C file.
#
# Eli Bendersky [https://eli.thegreenplace.net/]
# License: BSD
#-----------------------------------------------------------------
import sys

# This is not required if you've installed pycparser into
# your site-packages/ with setup.py
sys.path.extend(['.', '..'])
from pycparser import c_ast, parse_file, c_generator

class FuncDefVisitor(c_ast.NodeVisitor):
#    def visit_FuncDef(self, node):
#       print('%s at %s' % (node.decl.name, node.decl.coord))

    def visit_FuncDecl(self, node):
        #print((node))
        try:
            print(node.type.declname)
        except Exception as e:
            print(node.type.type.declname)

        # print function declaration
        generator = c_generator.CGenerator()
        print(generator.visit(node))
        # exit()

        #print('%s at %s' % (node.name, node.decl.coord))

# A visitor with some state information (the funcname it's looking for)
class FuncCallVisitor(c_ast.NodeVisitor):
    def __init__(self, funcname):
        self.funcname = funcname

    def visit_FuncCall(self, node):
        print('%s called at %s' % (node.name.name, node.name.coord))
        node.name.name = "asdf"
        #if node.name.name == self.funcname:
        #    print('%s called at %s' % (self.funcname, node.name.coord))
        # Visit args in case they contain more func calls.
        if node.args:
            self.visit(node.args)


def show_func_calls(filename, funcname):
    #ast = parse_file(filename, use_cpp=True, cpp_path="x86_64-w64-mingw32-cpp")
    #ast = parse_file(filename, use_cpp=False, cpp_path="x86_64-w64-mingw32-cpp")
    ast = parse_file(filename, use_cpp=True, cpp_path="x86_64-w64-mingw32-cpp")
#    ast.show(showcoord=True)
#    v = FuncCallVisitor(funcname)
 #   v.visit(ast)

    v = FuncDefVisitor()
    v.visit(ast)

#    generator = c_generator.CGenerator()
#    print(generator.visit(ast))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        filename = sys.argv[1]
        func = "" #sys.argv[2]
    else:
        filename = 'examples/c_files/basic.c'
        func = 'foo'

    show_func_calls(filename, func)



