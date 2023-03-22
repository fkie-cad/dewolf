from decompiler.pipeline.controlflowanalysis.restructuring_commons.loop_structurer import LoopStructurer
from decompiler.pipeline.controlflowanalysis.restructuring_commons.loop_structuring_rules import NestedDoWhileLoopRule, SequenceRule
from decompiler.structures.ast.ast_comparator import ASTComparator
from decompiler.structures.ast.condition_symbol import ConditionHandler, ConditionSymbol
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import Assignment, BinaryOperation, Break, Condition, Constant, Continue, Integer, OperationType, Variable

var_c = Variable("c", Integer.int32_t())
const_0 = Constant(0, Integer.int32_t())
const_3 = Constant(3, Integer.int32_t())
const_5 = Constant(5, Integer.int32_t())
const_10 = Constant(10, Integer.int32_t())


def logic_cond(name: str, context) -> LogicCondition:
    return LogicCondition.initialize_symbol(name, context)


assignment_c_equal_0 = Assignment(var_c, const_0)
assignment_c_equal_5 = Assignment(var_c, const_5)
assignment_c_plus_3 = Assignment(var_c, BinaryOperation(OperationType.plus, [var_c, const_3]))
assignment_c_plus_5 = Assignment(var_c, BinaryOperation(OperationType.plus, [var_c, const_5]))
assignment_c_plus_10 = Assignment(var_c, BinaryOperation(OperationType.plus, [var_c, const_10]))


def condition_handler1(context):
    return ConditionHandler(
        {logic_cond("a", context): ConditionSymbol(Condition(OperationType.equal, [var_c, const_5]), logic_cond("a", context), None)}
    )


def condition_handler2(context):
    return ConditionHandler(
        {
            logic_cond("a", context): ConditionSymbol(Condition(OperationType.equal, [var_c, const_5]), logic_cond("a", context), None),
            logic_cond("b", context): ConditionSymbol(Condition(OperationType.equal, [var_c, const_3]), logic_cond("b", context), None),
        }
    )


def test_while_loop_rule():
    """
    While Loop restructuring (WhileLoopRule)

    while(true){        while(!a){
        if(a){              c = c + 5
            break           c = c + 10
        }               }
        c = c + 5
        c = c + 10
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_seq_node()
    children = [
        ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context)),
        ast.factory.create_code_node([assignment_c_plus_5.copy()]),
        ast.factory.create_code_node([assignment_c_plus_10.copy()]),
    ]
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.factory.create_code_node(stmts=[Break()])
    ast._add_nodes_from([root, body, children[0], children[1], children[2], true_branch, true_branch_child])
    ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (body, children[2]),
            (children[0], true_branch),
            (true_branch, true_branch_child),
        ]
    )
    ast._code_node_reachability_graph.add_reachability_from(
        ((true_branch_child, children[1]), (true_branch_child, children[2]), (children[1], children[2]))
    )
    body.sort_children()

    LoopStructurer.refine_loop(ast, root)

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_while_loop_node(~logic_cond("a", transformed_ast.factory.logic_context))
    body = transformed_ast.factory.create_seq_node()
    children = [
        transformed_ast.factory.create_code_node([assignment_c_plus_5.copy()]),
        transformed_ast.factory.create_code_node([assignment_c_plus_10.copy()]),
    ]
    transformed_ast._add_nodes_from([root, body, children[0], children[1]])
    transformed_ast._add_edges_from([(root, body), (body, children[0]), (body, children[1])])
    transformed_ast._code_node_reachability_graph.add_reachability(children[0], children[1])
    body.sort_children()

    assert ASTComparator.compare(ast, transformed_ast)


def test_while_loop_rule_empty_body():
    """
    While Loop restructuring (WhileLoopRule)

    while(true){        while(!a){
        if(a){          }
            break
        }
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context))
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.add_code_node(ast.factory.create_code_node(stmts=[Break()]))
    ast._add_nodes_from([root, body, true_branch])
    ast._add_edges_from([(root, body), (body, true_branch), (true_branch, true_branch_child)])

    LoopStructurer.refine_loop(ast, root)

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_while_loop_node(~logic_cond("a", transformed_ast.factory.logic_context))
    body = transformed_ast.add_code_node()
    transformed_ast._add_node(root)
    transformed_ast._add_edge(root, body)

    assert ASTComparator.compare(ast, transformed_ast)


def test_do_while_loop_rule():
    """
    DoWhileLoop restructuring (DoWhileLoopRule)

    while(true){        dowhile(!a){
        c = c + 5           c = c + 5
        c = c + 10          c = c + 10
        if(a){          }
            break
        }
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_seq_node()
    children = [
        ast.factory.create_code_node(stmts=[assignment_c_plus_5.copy()]),
        ast.factory.create_code_node(stmts=[assignment_c_plus_10.copy()]),
        ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context)),
    ]
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.factory.create_seq_node()
    true_branch_code = ast.factory.create_code_node(stmts=[Break()])
    ast._add_nodes_from([root, body, children[0], children[1], children[2], true_branch, true_branch_child, true_branch_code])
    ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (body, children[2]),
            (children[2], true_branch),
            (true_branch, true_branch_child),
            (true_branch_child, true_branch_code),
        ]
    )
    ast._code_node_reachability_graph.add_reachability_from(
        ((children[0], children[1]), (children[0], true_branch_code), (children[1], true_branch_code))
    )
    true_branch_child.sort_children()
    body.sort_children()

    LoopStructurer.refine_loop(ast, root)

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_do_while_loop_node(~logic_cond("a", transformed_ast.factory.logic_context))
    body = transformed_ast.factory.create_seq_node()
    children = [
        transformed_ast.factory.create_code_node([assignment_c_plus_5.copy()]),
        transformed_ast.factory.create_code_node([assignment_c_plus_10.copy()]),
    ]
    transformed_ast._add_nodes_from([root, body, children[0], children[1]])
    transformed_ast._add_edges_from([(root, body), (body, children[0]), (body, children[1])])
    transformed_ast._code_node_reachability_graph.add_reachability(children[0], children[1])
    body.sort_children()

    assert ASTComparator.compare(ast, transformed_ast)


def test_nested_dowhile_loop_rule_1():
    """
    Nested-DoWhile Restructuring (NestedDoWhileLoopRule)

    while(true){        while(true){
        c = c + 5           dowhile(!a){
        c = c + 10              c = c + 5
        if(a){                  c = c + 10
            c = 0           }
        }                   c = 0
    }                   }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_seq_node()
    children = [
        ast.factory.create_code_node([assignment_c_plus_5.copy()]),
        ast.factory.create_code_node([assignment_c_plus_10.copy()]),
        ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context)),
    ]
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.factory.create_code_node(stmts=[assignment_c_equal_0.copy()])
    ast._add_nodes_from([root, body, children[0], children[1], children[2], true_branch, true_branch_child])
    ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (body, children[2]),
            (children[2], true_branch),
            (true_branch, true_branch_child),
        ]
    )
    ast._code_node_reachability_graph.add_reachability_from(
        ((children[0], children[1]), (children[0], true_branch_child), (children[1], true_branch_child))
    )
    body.sort_children()

    LoopStructurer.refine_loop(ast, root)

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_endless_loop_node()
    body = transformed_ast.factory.create_seq_node()
    children = [
        transformed_ast.factory.create_do_while_loop_node(~logic_cond("a", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_code_node(stmts=[assignment_c_equal_0.copy()]),
    ]
    nested_loop_body = transformed_ast.factory.create_seq_node()
    nested_loop_body_children = [
        transformed_ast.factory.create_code_node([assignment_c_plus_5.copy()]),
        transformed_ast.factory.create_code_node([assignment_c_plus_10.copy()]),
    ]
    transformed_ast._add_nodes_from(
        [root, body, children[0], children[1], nested_loop_body, nested_loop_body_children[0], nested_loop_body_children[1]]
    )
    transformed_ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (children[0], nested_loop_body),
            (nested_loop_body, nested_loop_body_children[0]),
            (nested_loop_body, nested_loop_body_children[1]),
        ]
    )
    transformed_ast._code_node_reachability_graph.add_reachability_from(
        (
            (nested_loop_body_children[0], nested_loop_body_children[1]),
            (nested_loop_body_children[0], children[1]),
            (nested_loop_body_children[1], children[1]),
        )
    )
    nested_loop_body.sort_children()
    body.sort_children()

    assert ASTComparator.compare(ast, transformed_ast)


def test_nested_dowhile_loop_rule_interruption():
    """
    Nested-DoWhile Restructuring (NestedDoWhileLoopRule) should not transform!

    while(true){
        c = c + 5
        c = c + 10
        if(b){
            continue
        }
        if(a){
            c = 0
        }
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_seq_node()
    children = [
        ast.factory.create_code_node([assignment_c_plus_5.copy()]),
        ast.factory.create_code_node([assignment_c_plus_10.copy()]),
        ast.factory.create_condition_node(condition=logic_cond("b", ast.factory.logic_context)),
        ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context)),
    ]
    true_branch_x = ast.factory.create_true_node()
    true_branch_child_x = ast.factory.create_code_node(stmts=[Continue()])
    true_branch_a = ast.factory.create_true_node()
    true_branch_child_a = ast.factory.create_code_node(stmts=[assignment_c_equal_0.copy()])
    ast._add_nodes_from(
        [
            root,
            body,
            children[0],
            children[1],
            children[2],
            children[3],
            true_branch_x,
            true_branch_child_x,
            true_branch_a,
            true_branch_child_a,
        ]
    )
    ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (body, children[2]),
            (body, children[3]),
            (children[2], true_branch_x),
            (true_branch_x, true_branch_child_x),
            (children[3], true_branch_a),
            (true_branch_a, true_branch_child_a),
        ]
    )
    ast._code_node_reachability_graph.add_reachability_from(
        (
            (children[0], children[1]),
            (children[0], true_branch_child_x),
            (children[1], true_branch_child_x),
            (true_branch_child_x, true_branch_child_a),
            (children[0], true_branch_child_a),
            (children[1], true_branch_child_a),
        )
    )
    body.sort_children()

    assert NestedDoWhileLoopRule.can_be_applied(root) is False


def test_nested_dowhile_loop_rule_interruption_in_loop():
    """
    Nested-DoWhile Restructuring (NestedDoWhileLoopRule) should not transform!

    while(true){        while(true){
        c = c + 5           dowhile(!a){
        c = c + 10              c = c + 5
        while(b){               c = c + 10
            c = c + 3           while(b){
            if(a){                  c = c + 3
                break               if(a){
            }                           break
        }                           }
        if(a){                  }
            c = 0           }
        }                   c = 0
    }                   }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_seq_node()
    children = [
        ast.factory.create_code_node([assignment_c_plus_5.copy()]),
        ast.factory.create_code_node([assignment_c_plus_10.copy()]),
        ast.factory.create_while_loop_node(condition=logic_cond("b", ast.factory.logic_context)),
        ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context)),
    ]
    loop_body = ast.factory.create_seq_node()
    loop_children = [
        ast.factory.create_code_node([assignment_c_plus_3.copy()]),
        ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context)),
    ]
    true_branch_x = ast.factory.create_true_node()
    true_branch_child_x = ast.factory.create_code_node(stmts=[Break()])
    true_branch_a = ast.factory.create_true_node()
    true_branch_child_a = ast.factory.create_code_node(stmts=[assignment_c_equal_0.copy()])
    ast._add_nodes_from(
        [
            root,
            body,
            children[0],
            children[1],
            children[2],
            children[3],
            loop_body,
            loop_children[0],
            loop_children[1],
            true_branch_x,
            true_branch_child_x,
            true_branch_a,
            true_branch_child_a,
        ]
    )
    ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (body, children[2]),
            (body, children[3]),
            (children[2], loop_body),
            (loop_body, loop_children[0]),
            (loop_body, loop_children[1]),
            (loop_children[1], true_branch_x),
            (true_branch_x, true_branch_child_x),
            (children[3], true_branch_a),
            (true_branch_a, true_branch_child_a),
        ]
    )
    ast._code_node_reachability_graph.add_reachability_from(
        (
            (children[0], children[1]),
            (children[0], loop_children[0]),
            (children[0], true_branch_child_x),
            (children[0], true_branch_child_a),
            (children[1], loop_children[0]),
            (children[1], true_branch_child_x),
            (children[1], true_branch_child_a),
            (loop_children[0], true_branch_child_x),
            (loop_children[0], true_branch_child_a),
            (true_branch_child_x, true_branch_child_a),
        )
    )
    body.sort_children()
    loop_body.sort_children()

    LoopStructurer.refine_loop(ast, root)

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_endless_loop_node()
    body = transformed_ast.factory.create_seq_node()
    children = [
        transformed_ast.factory.create_do_while_loop_node(~logic_cond("a", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_code_node(stmts=[assignment_c_equal_0.copy()]),
    ]
    nested_loop_body = transformed_ast.factory.create_seq_node()
    nested_loop_body_children = [
        transformed_ast.factory.create_code_node([assignment_c_plus_5.copy()]),
        transformed_ast.factory.create_code_node([assignment_c_plus_10.copy()]),
        transformed_ast.factory.create_while_loop_node(logic_cond("b", transformed_ast.factory.logic_context)),
    ]
    loop_body = transformed_ast.factory.create_seq_node()
    loop_children = [
        transformed_ast.factory.create_code_node([assignment_c_plus_3.copy()]),
        transformed_ast.factory.create_condition_node(condition=logic_cond("a", transformed_ast.factory.logic_context)),
    ]
    true_branch_x = transformed_ast.factory.create_true_node()
    true_branch_child_x = transformed_ast.factory.create_code_node(stmts=[Break()])

    transformed_ast._add_nodes_from(
        [
            root,
            body,
            children[0],
            children[1],
            nested_loop_body,
            nested_loop_body_children[0],
            nested_loop_body_children[1],
            nested_loop_body_children[2],
            loop_body,
            loop_children[0],
            loop_children[1],
            true_branch_x,
            true_branch_child_x,
        ]
    )
    transformed_ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (children[0], nested_loop_body),
            (nested_loop_body, nested_loop_body_children[0]),
            (nested_loop_body, nested_loop_body_children[1]),
            (nested_loop_body, nested_loop_body_children[2]),
            (nested_loop_body_children[2], loop_body),
            (loop_body, loop_children[0]),
            (loop_body, loop_children[1]),
            (loop_children[1], true_branch_x),
            (true_branch_x, true_branch_child_x),
        ]
    )
    transformed_ast._code_node_reachability_graph.add_reachability_from(
        (
            (nested_loop_body_children[0], nested_loop_body_children[1]),
            (nested_loop_body_children[0], loop_children[0]),
            (nested_loop_body_children[0], true_branch_child_x),
            (nested_loop_body_children[0], children[1]),
            (nested_loop_body_children[1], loop_children[0]),
            (nested_loop_body_children[1], true_branch_child_x),
            (nested_loop_body_children[1], children[1]),
            (loop_children[0], true_branch_child_x),
            (loop_children[0], children[1]),
            (true_branch_child_x, children[1]),
        )
    )
    loop_body.sort_children()
    nested_loop_body.sort_children()
    body.sort_children()

    assert ASTComparator.compare(ast, transformed_ast)


def test_nested_dowhile_loop_rule_2():
    """
    Nested-DoWhile Restructuring (NestedDoWhileLoopRule)

    while(true){          while(true){
        c = c + 5             dowhile(!a){
        while(true){            c = c + 5
            c = c + 10          while(true){
            if(b){                  c = c + 10
                break               if(b){
            }                           break
            c = 0                   }
        }                           c = 0
        if(a){                  }
            c = c + 3           c = c + 3
        }                 }
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_seq_node()
    children = [
        ast.factory.create_code_node([assignment_c_plus_5.copy()]),
        ast.factory.create_endless_loop_node(),
        ast.factory.create_condition_node(logic_cond("a", ast.factory.logic_context)),
    ]
    nested_loop_body = ast.factory.create_seq_node()
    nested_loop_body_children = [
        ast.factory.create_code_node([assignment_c_plus_10.copy()]),
        ast.factory.create_condition_node(logic_cond("b", ast.factory.logic_context)),
        ast.factory.create_code_node([assignment_c_equal_0.copy()]),
    ]
    true_branch_in_loop = ast.factory.create_true_node()
    true_branch_child_in_loop = ast.factory.create_code_node(stmts=[Break()])
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.factory.create_code_node(stmts=[assignment_c_plus_3.copy()])

    ast._add_nodes_from(
        [
            root,
            body,
            children[0],
            children[1],
            children[2],
            nested_loop_body,
            nested_loop_body_children[0],
            nested_loop_body_children[1],
            nested_loop_body_children[2],
            true_branch_in_loop,
            true_branch_child_in_loop,
            true_branch,
            true_branch_child,
        ]
    )
    ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (body, children[2]),
            (children[1], nested_loop_body),
            (nested_loop_body, nested_loop_body_children[0]),
            (nested_loop_body, nested_loop_body_children[1]),
            (nested_loop_body, nested_loop_body_children[2]),
            (nested_loop_body_children[1], true_branch_in_loop),
            (true_branch_in_loop, true_branch_child_in_loop),
            (children[2], true_branch),
            (true_branch, true_branch_child),
        ]
    )
    ast._code_node_reachability_graph.add_reachability_from(
        (
            (children[0], nested_loop_body_children[0]),
            (children[0], true_branch_child_in_loop),
            (children[0], nested_loop_body_children[2]),
            (children[0], true_branch_child),
            (nested_loop_body_children[0], true_branch_child),
            (nested_loop_body_children[0], true_branch_child_in_loop),
            (nested_loop_body_children[0], nested_loop_body_children[2]),
            (true_branch_child_in_loop, nested_loop_body_children[2]),
            (nested_loop_body_children[2], true_branch_child),
        )
    )
    nested_loop_body.sort_children()
    body.sort_children()

    LoopStructurer.refine_loop(ast, root)

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_endless_loop_node()
    body = transformed_ast.factory.create_seq_node()
    children = [
        transformed_ast.factory.create_do_while_loop_node(~logic_cond("a", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_code_node(stmts=[assignment_c_plus_3.copy()]),
    ]
    nested_do_loop_body = transformed_ast.factory.create_seq_node()
    nested_do_loop_children = [
        transformed_ast.factory.create_code_node([assignment_c_plus_5.copy()]),
        transformed_ast.factory.create_endless_loop_node(),
    ]
    nested_loop_body = transformed_ast.factory.create_seq_node()
    nested_loop_body_children = [
        transformed_ast.factory.create_code_node([assignment_c_plus_10.copy()]),
        transformed_ast.factory.create_condition_node(logic_cond("b", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_code_node([assignment_c_equal_0.copy()]),
    ]
    true_branch_in_loop = transformed_ast.factory.create_true_node()
    true_branch_child_in_loop = transformed_ast.factory.create_code_node(stmts=[Break()])
    transformed_ast._add_nodes_from(
        [
            root,
            body,
            children[0],
            children[1],
            nested_do_loop_body,
            nested_do_loop_children[0],
            nested_do_loop_children[1],
            nested_loop_body,
            nested_loop_body_children[0],
            nested_loop_body_children[1],
            nested_loop_body_children[2],
            true_branch_in_loop,
            true_branch_child_in_loop,
        ]
    )
    transformed_ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (children[0], nested_do_loop_body),
            (nested_do_loop_body, nested_do_loop_children[0]),
            (nested_do_loop_body, nested_do_loop_children[1]),
            (nested_do_loop_children[1], nested_loop_body),
            (nested_loop_body, nested_loop_body_children[0]),
            (nested_loop_body, nested_loop_body_children[1]),
            (nested_loop_body, nested_loop_body_children[2]),
            (nested_loop_body_children[1], true_branch_in_loop),
            (true_branch_in_loop, true_branch_child_in_loop),
        ]
    )
    transformed_ast._code_node_reachability_graph.add_reachability_from(
        (
            (nested_do_loop_children[0], nested_loop_body_children[0]),
            (nested_do_loop_children[0], true_branch_child_in_loop),
            (nested_do_loop_children[0], nested_loop_body_children[2]),
            (nested_do_loop_children[0], children[1]),
            (nested_loop_body_children[0], true_branch_child_in_loop),
            (nested_loop_body_children[0], nested_loop_body_children[2]),
            (nested_loop_body_children[0], children[1]),
            (true_branch_child_in_loop, nested_loop_body_children[2]),
            (nested_loop_body_children[2], children[1]),
        )
    )
    nested_loop_body.sort_children()
    body.sort_children()

    assert ASTComparator.compare(ast, transformed_ast)


def test_loop_to_sequence_rule_1():
    """
    Restructure Loop to sequence (SequenceRule) -> Last node is condition node where both branches end with break

    while(true){        c = c + 5
        c = c + 5       if(!a){
        if(a){              c = c + 10
            break       }
        }
        else{
            c = c + 10
            break
        }
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_seq_node()
    children = [
        ast.factory.create_code_node(stmts=[assignment_c_plus_5.copy()]),
        ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context)),
    ]
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.factory.create_code_node(stmts=[Break()])
    false_branch = ast.factory.create_false_node()
    false_branch_child = ast.factory.create_code_node(stmts=[assignment_c_plus_10.copy(), Break()])
    ast._add_nodes_from([root, body, children[0], children[1], true_branch, true_branch_child, false_branch, false_branch_child])
    ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (children[1], true_branch),
            (true_branch, true_branch_child),
            (children[1], false_branch),
            (false_branch, false_branch_child),
        ]
    )
    ast._code_node_reachability_graph.add_reachability_from(((children[0], false_branch_child), (children[0], true_branch_child)))
    body.sort_children()

    new_root = LoopStructurer.refine_loop(ast, root)

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_seq_node()
    children = [
        transformed_ast.factory.create_code_node(stmts=[assignment_c_plus_5.copy()]),
        transformed_ast.factory.create_condition_node(condition=~logic_cond("a", transformed_ast.factory.logic_context)),
    ]
    true_branch = transformed_ast.factory.create_true_node()
    true_branch_child = transformed_ast.factory.create_code_node(stmts=[assignment_c_plus_10.copy()])
    transformed_ast._add_nodes_from([root, children[0], children[1], true_branch, true_branch_child])
    transformed_ast._add_edges_from(
        [(root, children[0]), (root, children[1]), (children[1], true_branch), (true_branch, true_branch_child)]
    )
    transformed_ast._code_node_reachability_graph.add_reachability(children[0], true_branch_child)
    root.sort_children()

    assert new_root == root
    assert ASTComparator.compare(ast, transformed_ast)


def test_loop_to_sequence_rule_2():
    """
    Restructure Loop to sequence (SequenceRule) -> Last node is a code-node that ends with break

    while(true){        c = c + 5
        c = c + 5       c = c + 10
        c = c + 10
        break
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_seq_node()
    children = [
        ast.factory.create_code_node([assignment_c_plus_5.copy()]),
        ast.factory.create_code_node([assignment_c_plus_10.copy(), Break()]),
    ]
    ast._add_nodes_from([root, body, children[0], children[1]])
    ast._add_edges_from([(root, body), (body, children[0]), (body, children[1])])
    ast._code_node_reachability_graph.add_reachability(children[0], children[1])
    body.sort_children()

    new_root = LoopStructurer.refine_loop(ast, root)

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_seq_node()
    children = [
        transformed_ast.factory.create_code_node(stmts=[assignment_c_plus_5.copy()]),
        transformed_ast.factory.create_code_node(stmts=[assignment_c_plus_10.copy()]),
    ]
    transformed_ast._add_nodes_from([root, children[0], children[1]])
    transformed_ast._add_edges_from([(root, children[0]), (root, children[1])])
    transformed_ast._code_node_reachability_graph.add_reachability(children[0], children[1])
    root.sort_children()

    assert len(roots := ast.get_roots) == 2 and any(root == new_root for root in roots)
    assert ASTComparator.compare(ast, transformed_ast)


def test_loop_to_sequence_rule__3():
    """
    First, NestedDoWhile and then node to sequence (NestedDoWhileRule, SequenceRule)

    while(true){          while(true){          dowhile(a){
        c = c + 5             dowhile(a){           c = c + 5
        if(a){                    c = c + 5     }
            continue          }                 c = c + 10
        }                     c = c + 10
        else{                 break
            c = c + 10    }
            break
        }
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_seq_node()
    children = [
        ast.factory.create_code_node(stmts=[assignment_c_plus_5.copy()]),
        ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context)),
    ]
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.factory.create_code_node(stmts=[Continue()])
    false_branch = ast.factory.create_false_node()
    false_branch_child = ast.factory.create_code_node(stmts=[assignment_c_plus_10.copy(), Break()])
    ast._add_nodes_from([root, body, children[0], children[1], true_branch, true_branch_child, false_branch, false_branch_child])
    ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (children[1], true_branch),
            (true_branch, true_branch_child),
            (children[1], false_branch),
            (false_branch, false_branch_child),
        ]
    )
    ast._code_node_reachability_graph.add_reachability_from(((children[0], false_branch_child), (children[0], true_branch_child)))
    body.sort_children()

    new_root = LoopStructurer.refine_loop(ast, root)

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_seq_node()
    children = [
        transformed_ast.factory.create_do_while_loop_node(condition=logic_cond("a", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_code_node(stmts=[assignment_c_plus_10.copy()]),
    ]
    nested_body = transformed_ast.factory.create_code_node(stmts=[assignment_c_plus_5.copy()])
    transformed_ast._add_nodes_from([root, children[0], children[1], nested_body])
    transformed_ast._add_edges_from([(root, children[0]), (root, children[1]), (children[0], nested_body)])
    transformed_ast._code_node_reachability_graph.add_reachability(nested_body, children[1])
    root.sort_children()

    assert len(roots := ast.get_roots) == 2 and any(root == new_root for root in roots)
    assert ASTComparator.compare(ast, transformed_ast)


def test_loop_to_sequence_rule_not_possible_continue():
    """
    Can not restructure as Loop to Sequence, because the loop-body contains a continue.

    while(true){
        c = c + 5
        if(a){
            continue
        }
        c = c + 10
        break
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_seq_node()
    children = [
        ast.factory.create_code_node(stmts=[assignment_c_plus_5.copy()]),
        ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context)),
        ast.factory.create_code_node(stmts=[assignment_c_plus_10.copy(), Break()]),
    ]
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.factory.create_code_node(stmts=[Continue()])
    ast._add_nodes_from([root, body, children[0], children[1], children[2], true_branch, true_branch_child])
    ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (body, children[2]),
            (children[1], true_branch),
            (true_branch, true_branch_child),
        ]
    )
    ast._code_node_reachability_graph.add_reachability_from(
        ((children[0], true_branch_child), (children[0], children[2]), (true_branch_child, children[2]))
    )
    body.sort_children()

    assert SequenceRule.can_be_applied(root) is False


def test_loop_to_sequence_rule_continue_in_inner_loop():
    """
    Restructure as Loop to Sequence, because the loop-body contains only a continue in another loop

    while(true){            c = c + 5
        c = c + 5           while(a){
        while(a){               c = c + 10
            c = c + 10          if(b){
            if(b){                  continue
                continue        }
            }                   c = 0
            c = 0           }
        c = c + 3           c = c + 3
        break
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_seq_node()
    children = [
        ast.factory.create_code_node([assignment_c_plus_5.copy()]),
        ast.factory.create_while_loop_node(logic_cond("a", ast.factory.logic_context)),
        ast.factory.create_code_node(stmts=[assignment_c_plus_3.copy(), Break()]),
    ]
    nested_loop_body = ast.factory.create_seq_node()
    nested_loop_body_children = [
        ast.factory.create_code_node([assignment_c_plus_10.copy()]),
        ast.factory.create_condition_node(logic_cond("b", ast.factory.logic_context)),
        ast.factory.create_code_node([assignment_c_equal_0.copy()]),
    ]
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.factory.create_code_node(stmts=[Continue()])
    ast._add_nodes_from(
        [
            root,
            body,
            children[0],
            children[1],
            children[2],
            nested_loop_body,
            nested_loop_body_children[0],
            nested_loop_body_children[1],
            nested_loop_body_children[2],
            true_branch,
            true_branch_child,
        ]
    )
    ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (body, children[2]),
            (children[1], nested_loop_body),
            (nested_loop_body, nested_loop_body_children[0]),
            (nested_loop_body, nested_loop_body_children[1]),
            (nested_loop_body, nested_loop_body_children[2]),
            (nested_loop_body_children[1], true_branch),
            (true_branch, true_branch_child),
        ]
    )
    ast._code_node_reachability_graph.add_reachability_from(
        (
            (children[0], nested_loop_body_children[0]),
            (children[0], true_branch_child),
            (children[0], nested_loop_body_children[2]),
            (children[0], children[2]),
            (nested_loop_body_children[0], children[2]),
            (nested_loop_body_children[0], true_branch_child),
            (nested_loop_body_children[0], nested_loop_body_children[2]),
            (true_branch_child, nested_loop_body_children[2]),
            (nested_loop_body_children[2], children[2]),
        )
    )
    nested_loop_body.sort_children()
    body.sort_children()

    LoopStructurer.refine_loop(ast, root)

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_seq_node()
    children = [
        transformed_ast.factory.create_code_node([assignment_c_plus_5.copy()]),
        transformed_ast.factory.create_while_loop_node(logic_cond("a", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_code_node(stmts=[assignment_c_plus_3.copy()]),
    ]
    nested_loop_body = transformed_ast.factory.create_seq_node()
    nested_loop_body_children = [
        transformed_ast.factory.create_code_node([assignment_c_plus_10.copy()]),
        transformed_ast.factory.create_condition_node(logic_cond("b", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_code_node([assignment_c_equal_0.copy()]),
    ]
    true_branch = transformed_ast.factory.create_true_node()
    true_branch_child = transformed_ast.factory.create_code_node(stmts=[Continue()])
    transformed_ast._add_nodes_from(
        [
            root,
            children[0],
            children[1],
            children[2],
            nested_loop_body,
            nested_loop_body_children[0],
            nested_loop_body_children[1],
            nested_loop_body_children[2],
            true_branch,
            true_branch_child,
        ]
    )
    transformed_ast._add_edges_from(
        [
            (root, children[0]),
            (root, children[1]),
            (root, children[2]),
            (children[1], nested_loop_body),
            (nested_loop_body, nested_loop_body_children[0]),
            (nested_loop_body, nested_loop_body_children[1]),
            (nested_loop_body, nested_loop_body_children[2]),
            (nested_loop_body_children[1], true_branch),
            (true_branch, true_branch_child),
        ]
    )
    transformed_ast._code_node_reachability_graph.add_reachability_from(
        (
            (children[0], nested_loop_body_children[0]),
            (children[0], true_branch_child),
            (children[0], nested_loop_body_children[2]),
            (children[0], children[2]),
            (nested_loop_body_children[0], children[2]),
            (nested_loop_body_children[0], true_branch_child),
            (nested_loop_body_children[0], nested_loop_body_children[2]),
            (true_branch_child, nested_loop_body_children[2]),
            (nested_loop_body_children[2], children[2]),
        )
    )
    nested_loop_body.sort_children()
    root.sort_children()

    assert ASTComparator.compare(ast, transformed_ast)


def test_loop_to_sequence_rule_not_possible_break():
    """
    Can not restructure as Loop to Sequence, because the loop-body contains another break then at the end-node.

    while(true){
        c = c + 5
        if(a){
            break
        }
        c = c + 10
        break
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler1(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_seq_node()
    children = [
        ast.factory.create_code_node(stmts=[assignment_c_plus_5.copy()]),
        ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context)),
        ast.factory.create_code_node(stmts=[assignment_c_plus_10.copy(), Break()]),
    ]
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.factory.create_code_node(stmts=[Break()])
    ast._add_nodes_from([root, body, children[0], children[1], children[2], true_branch, true_branch_child])
    ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (body, children[2]),
            (children[1], true_branch),
            (true_branch, true_branch_child),
        ]
    )
    ast._code_node_reachability_graph.add_reachability_from(
        ((children[0], true_branch_child), (children[0], children[2]), (true_branch_child, children[2]))
    )
    body.sort_children()

    assert SequenceRule.can_be_applied(root) is False


def test_loop_to_sequence_rule_break_in_inner_loop_1():
    """
    Restructure as Loop to Sequence, because the loop-body contains only a break in another loop

    while(true){            c = c + 5
        c = c + 5           while(a){
        while(a){               c = c + 10
            c = c + 10          if(b){
            if(b){                  break
                break           }
            }                   c = 0
            c = 0           }
        c = c + 3           c = c + 3
        break
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_seq_node()
    children = [
        ast.factory.create_code_node([assignment_c_plus_5.copy()]),
        ast.factory.create_while_loop_node(logic_cond("a", ast.factory.logic_context)),
        ast.factory.create_code_node(stmts=[assignment_c_plus_3.copy(), Break()]),
    ]
    nested_loop_body = ast.factory.create_seq_node()
    nested_loop_body_children = [
        ast.factory.create_code_node([assignment_c_plus_10.copy()]),
        ast.factory.create_condition_node(logic_cond("b", ast.factory.logic_context)),
        ast.factory.create_code_node([assignment_c_equal_0.copy()]),
    ]
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.factory.create_code_node(stmts=[Break()])
    ast._add_nodes_from(
        [
            root,
            body,
            children[0],
            children[1],
            children[2],
            nested_loop_body,
            nested_loop_body_children[0],
            nested_loop_body_children[1],
            nested_loop_body_children[2],
            true_branch,
            true_branch_child,
        ]
    )
    ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (body, children[2]),
            (children[1], nested_loop_body),
            (nested_loop_body, nested_loop_body_children[0]),
            (nested_loop_body, nested_loop_body_children[1]),
            (nested_loop_body, nested_loop_body_children[2]),
            (nested_loop_body_children[1], true_branch),
            (true_branch, true_branch_child),
        ]
    )
    ast._code_node_reachability_graph.add_reachability_from(
        (
            (children[0], nested_loop_body_children[0]),
            (children[0], true_branch_child),
            (children[0], nested_loop_body_children[2]),
            (children[0], children[2]),
            (nested_loop_body_children[0], children[2]),
            (nested_loop_body_children[0], true_branch_child),
            (nested_loop_body_children[0], nested_loop_body_children[2]),
            (true_branch_child, nested_loop_body_children[2]),
            (nested_loop_body_children[2], children[2]),
        )
    )
    nested_loop_body.sort_children()
    body.sort_children()

    LoopStructurer.refine_loop(ast, root)

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_seq_node()
    children = [
        transformed_ast.factory.create_code_node([assignment_c_plus_5.copy()]),
        transformed_ast.factory.create_while_loop_node(logic_cond("a", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_code_node(stmts=[assignment_c_plus_3.copy()]),
    ]
    nested_loop_body = transformed_ast.factory.create_seq_node()
    nested_loop_body_children = [
        transformed_ast.factory.create_code_node([assignment_c_plus_10.copy()]),
        transformed_ast.factory.create_condition_node(logic_cond("b", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_code_node([assignment_c_equal_0.copy()]),
    ]
    true_branch = transformed_ast.factory.create_true_node()
    true_branch_child = transformed_ast.factory.create_code_node(stmts=[Break()])
    transformed_ast._add_nodes_from(
        [
            root,
            children[0],
            children[1],
            children[2],
            nested_loop_body,
            nested_loop_body_children[0],
            nested_loop_body_children[1],
            nested_loop_body_children[2],
            true_branch,
            true_branch_child,
        ]
    )
    transformed_ast._add_edges_from(
        [
            (root, children[0]),
            (root, children[1]),
            (root, children[2]),
            (children[1], nested_loop_body),
            (nested_loop_body, nested_loop_body_children[0]),
            (nested_loop_body, nested_loop_body_children[1]),
            (nested_loop_body, nested_loop_body_children[2]),
            (nested_loop_body_children[1], true_branch),
            (true_branch, true_branch_child),
        ]
    )
    transformed_ast._code_node_reachability_graph.add_reachability_from(
        (
            (children[0], nested_loop_body_children[0]),
            (children[0], true_branch_child),
            (children[0], nested_loop_body_children[2]),
            (children[0], children[2]),
            (nested_loop_body_children[0], children[2]),
            (nested_loop_body_children[0], true_branch_child),
            (nested_loop_body_children[0], nested_loop_body_children[2]),
            (true_branch_child, nested_loop_body_children[2]),
            (nested_loop_body_children[2], children[2]),
        )
    )
    nested_loop_body.sort_children()
    root.sort_children()

    assert ASTComparator.compare(ast, transformed_ast)


def test_loop_to_sequence_rule_not_possible_break_non_end_node():
    """
    Can not restructure as Loop to Sequence, because the loop-body contains break in a non-end-node.

    while(true){
        c = c + 5
        if(a){
            if(b){
                break
            }
            c = c + 10
            break
        }else{
            break
        }
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    code_node_c_plus_5 = ast.add_code_node([assignment_c_plus_5])
    code_node_break_in_b = ast.add_code_node([Break()])
    code_node_break_in_a = ast.add_code_node([Break()])
    code_node_c_plus_10_break = ast.add_code_node([assignment_c_plus_10, Break()])
    condition_node_b = ast._add_condition_node_with(logic_cond("b", ast.factory.logic_context), code_node_break_in_b)
    ast._add_node(true_branch := ast.factory.create_seq_node())
    ast._add_edges_from((true_branch, child) for child in [condition_node_b, code_node_c_plus_10_break])
    condition_node_a = ast._add_condition_node_with(logic_cond("a", ast.factory.logic_context), true_branch, code_node_break_in_a)
    ast._add_node(loop_body := ast.factory.create_seq_node())
    ast._add_edges_from((loop_body, child) for child in [code_node_c_plus_5, condition_node_a])
    root = ast.add_endless_loop_with_body(loop_body)
    ast._code_node_reachability_graph.add_reachability_from(
        (
            (code_node_c_plus_5, code_node_break_in_b),
            (code_node_c_plus_5, code_node_c_plus_10_break),
            (code_node_c_plus_5, code_node_break_in_a),
            (code_node_break_in_b, code_node_c_plus_10_break),
        )
    )
    true_branch.sort_children()
    loop_body.sort_children()

    ast.set_current_root(root)

    assert SequenceRule.can_be_applied(root) is False


def test_loop_to_sequence_rule_break_in_inner_loop_2():
    """
    Restructure as Loop to Sequence, because the loop-body contains only a break in another loop

    while(true){            c = c + 5
        c = c + 5           if(a){
        if(a){                  while(true){
            while(true){            c = c + 10
                c = c + 10          if(b){
                if(b){                  break
                    break           }
                }                   c = 0
                c = 0           }
            }                   c = c + 3
            c = c + 3       }
            break
        else{
            break
        }
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    code_node_c_plus_3_break = ast.add_code_node([assignment_c_plus_3, Break()])
    code_node_c_plus_5 = ast.add_code_node([assignment_c_plus_5])
    code_node_c_plus_10 = ast.add_code_node([assignment_c_plus_10])
    code_node_c_equal_0 = ast.add_code_node([assignment_c_equal_0])
    code_node_break_in_b = ast.add_code_node([Break()])
    code_node_break_in_a = ast.add_code_node([Break()])
    condition_node_b = ast._add_condition_node_with(logic_cond("b", ast.factory.logic_context), code_node_break_in_b)
    ast._add_node(inner_loop_body := ast.factory.create_seq_node())
    ast._add_edges_from((inner_loop_body, child) for child in [code_node_c_plus_10, condition_node_b, code_node_c_equal_0])
    inner_loop = ast.add_endless_loop_with_body(inner_loop_body)
    ast._add_node(true_branch := ast.factory.create_seq_node())
    ast._add_edges_from((true_branch, child) for child in [inner_loop, code_node_c_plus_3_break])
    condition_node_a = ast._add_condition_node_with(logic_cond("a", ast.factory.logic_context), true_branch, code_node_break_in_a)
    ast._add_node(loop_body := ast.factory.create_seq_node())
    ast._add_edges_from((loop_body, child) for child in [code_node_c_plus_5, condition_node_a])
    root = ast.add_endless_loop_with_body(loop_body)
    ast._code_node_reachability_graph.add_reachability_from(
        (
            (code_node_c_plus_5, code_node_c_plus_10),
            (code_node_c_plus_5, code_node_break_in_b),
            (code_node_c_plus_5, code_node_c_equal_0),
            (code_node_c_plus_5, code_node_c_plus_3_break),
            (code_node_c_plus_5, code_node_break_in_a),
            (code_node_c_plus_10, code_node_break_in_b),
            (code_node_c_plus_10, code_node_c_equal_0),
            (code_node_c_plus_10, code_node_c_plus_3_break),
            (code_node_break_in_b, code_node_c_equal_0),
            (code_node_break_in_b, code_node_c_plus_3_break),
            (code_node_c_equal_0, code_node_c_plus_3_break),
        )
    )
    inner_loop_body.sort_children()
    true_branch.sort_children()
    loop_body.sort_children()

    ast.set_current_root(root)
    SequenceRule(ast).restructure()
    ast.remove_current_root()

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    code_node_c_plus_3 = transformed_ast.add_code_node([assignment_c_plus_3])
    code_node_c_plus_5 = transformed_ast.add_code_node([assignment_c_plus_5])
    code_node_c_plus_10 = transformed_ast.add_code_node([assignment_c_plus_10])
    code_node_c_equal_0 = transformed_ast.add_code_node([assignment_c_equal_0])
    code_node_break_in_b = transformed_ast.add_code_node([Break()])
    condition_node_b = transformed_ast._add_condition_node_with(
        logic_cond("b", transformed_ast.factory.logic_context), code_node_break_in_b
    )
    transformed_ast._add_node(inner_loop_body := transformed_ast.factory.create_seq_node())
    transformed_ast._add_edges_from((inner_loop_body, child) for child in [code_node_c_plus_10, condition_node_b, code_node_c_equal_0])
    inner_loop = transformed_ast.add_endless_loop_with_body(inner_loop_body)
    transformed_ast._add_node(true_branch := transformed_ast.factory.create_seq_node())
    transformed_ast._add_edges_from((true_branch, child) for child in [inner_loop, code_node_c_plus_3])
    condition_node_a = transformed_ast._add_condition_node_with(logic_cond("a", transformed_ast.factory.logic_context), true_branch)
    transformed_ast._add_node(loop_body := transformed_ast.factory.create_seq_node())
    transformed_ast._add_edges_from((loop_body, child) for child in [code_node_c_plus_5, condition_node_a])
    transformed_ast._code_node_reachability_graph.add_reachability_from(
        (
            (code_node_c_plus_5, code_node_c_plus_10),
            (code_node_c_plus_5, code_node_break_in_b),
            (code_node_c_plus_5, code_node_c_equal_0),
            (code_node_c_plus_5, code_node_c_plus_3),
            (code_node_c_plus_10, code_node_break_in_b),
            (code_node_c_plus_10, code_node_c_equal_0),
            (code_node_c_plus_10, code_node_c_plus_3),
            (code_node_break_in_b, code_node_c_equal_0),
            (code_node_break_in_b, code_node_c_plus_3),
            (code_node_c_equal_0, code_node_c_plus_3),
        )
    )

    assert ASTComparator.compare(ast, transformed_ast)


def test_condition_to_sequence_rule_one_step():
    """
    Restructure Loop to Condition to sequence (ConditionToSeqRule) -> only one iteration

    while(true){          while(true){
        if(a){                while(a){
            c = c + 5             c = c + 5
            c = c + 10            c = c + 10
        }                     }
        else{                 c = 5
            c = 5             if(b){
            if(b){                c = 0
                c = 0             break
                break         }
            }             }
        }
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context))
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.factory.create_code_node(stmts=[assignment_c_plus_5.copy(), assignment_c_plus_10.copy()])
    false_branch = ast.factory.create_false_node()
    false_branch_child = ast.factory.create_seq_node()
    children = [
        ast.factory.create_code_node(stmts=[assignment_c_equal_5.copy()]),
        ast.factory.create_condition_node(condition=logic_cond("b", ast.factory.logic_context)),
    ]
    nested_true_branch = ast.factory.create_true_node()
    nested_true_branch_child = ast.factory.create_code_node(stmts=[assignment_c_equal_0.copy(), Break()])

    ast._add_nodes_from(
        [
            root,
            body,
            true_branch,
            true_branch_child,
            false_branch,
            false_branch_child,
            children[0],
            children[1],
            nested_true_branch,
            nested_true_branch_child,
        ]
    )
    ast._add_edges_from(
        [
            (root, body),
            (body, true_branch),
            (body, false_branch),
            (true_branch, true_branch_child),
            (false_branch, false_branch_child),
            (false_branch_child, children[0]),
            (false_branch_child, children[1]),
            (children[1], nested_true_branch),
            (nested_true_branch, nested_true_branch_child),
        ]
    )
    ast._code_node_reachability_graph.add_reachability(children[0], nested_true_branch_child)
    false_branch_child.sort_children()

    ast.set_current_root(root)
    loop_structurer = LoopStructurer(ast)
    loop_structurer._processor.preprocess_loop()
    loop_structuring_rule = loop_structurer.match_restructurer()
    loop_structuring_rule.restructure()
    loop_structurer._processor.preprocess_loop()
    loop_structurer._processor.postprocess_loop()
    ast.remove_current_root()

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_endless_loop_node()
    body = transformed_ast.factory.create_seq_node()
    children = [
        transformed_ast.factory.create_while_loop_node(condition=logic_cond("a", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_code_node([assignment_c_equal_5.copy()]),
        transformed_ast.factory.create_condition_node(condition=logic_cond("b", transformed_ast.factory.logic_context)),
    ]
    loop_body = transformed_ast.factory.create_code_node([assignment_c_plus_5.copy(), assignment_c_plus_10.copy()])
    true_branch = transformed_ast.factory.create_true_node()
    true_branch_child = transformed_ast.factory.create_code_node([assignment_c_equal_0.copy(), Break()])
    transformed_ast._add_nodes_from([root, body, children[0], children[1], children[2], loop_body, true_branch, true_branch_child])
    transformed_ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (body, children[2]),
            (children[0], loop_body),
            (children[2], true_branch),
            (true_branch, true_branch_child),
        ]
    )
    transformed_ast._code_node_reachability_graph.add_reachability_from(
        ((loop_body, children[1]), (loop_body, true_branch_child), (children[1], true_branch_child))
    )
    body.sort_children()

    assert ASTComparator.compare(ast, transformed_ast)


def test_condition_to_sequence_rule():
    """
    Restructure Loop to Condition to sequence (ConditionToSeqRule)

    while(true){          while(true){         while(true){
        if(a){                while(a){            while(a){
            c = c + 5             c = c + 5            c = c + 5
            c = c + 10            c = c + 10           c = c + 10
        }                     }                    }
        else{                 if(b){               if(b){
            if(b){                break                break
                break         }                    }
            }                 c = 5                c = 5
            c = 5         }                     }
        }
    }
    """

    ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context))
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.factory.create_code_node(stmts=[assignment_c_plus_5.copy(), assignment_c_plus_10.copy()])
    false_branch = ast.factory.create_false_node()
    false_branch_child = ast.factory.create_seq_node()
    children = [
        ast.factory.create_condition_node(condition=logic_cond("b", ast.factory.logic_context)),
        ast.factory.create_code_node(stmts=[assignment_c_equal_5.copy()]),
    ]
    nested_true_branch = ast.factory.create_true_node()
    nested_true_branch_child = ast.factory.create_code_node(stmts=[Break()])
    ast._add_nodes_from(
        [
            root,
            body,
            true_branch,
            true_branch_child,
            false_branch,
            false_branch_child,
            children[0],
            children[1],
            nested_true_branch,
            nested_true_branch_child,
        ]
    )
    ast._add_edges_from(
        [
            (root, body),
            (body, true_branch),
            (body, false_branch),
            (true_branch, true_branch_child),
            (false_branch, false_branch_child),
            (false_branch_child, children[0]),
            (false_branch_child, children[1]),
            (children[0], nested_true_branch),
            (nested_true_branch, nested_true_branch_child),
        ]
    )
    ast._code_node_reachability_graph.add_reachability(nested_true_branch_child, children[1])
    false_branch_child.sort_children()

    new_root = LoopStructurer.refine_loop(ast, root)

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_endless_loop_node()
    body = transformed_ast.factory.create_seq_node()
    children = [
        transformed_ast.factory.create_while_loop_node(condition=logic_cond("a", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_condition_node(condition=logic_cond("b", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_code_node([assignment_c_equal_5.copy()]),
    ]
    loop_body = transformed_ast.factory.create_code_node([assignment_c_plus_5.copy(), assignment_c_plus_10.copy()])
    true_branch = transformed_ast.factory.create_true_node()
    true_branch_child = transformed_ast.factory.create_code_node([Break()])
    transformed_ast._add_nodes_from([root, body, children[0], children[1], children[2], loop_body, true_branch, true_branch_child])
    transformed_ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (body, children[2]),
            (children[0], loop_body),
            (children[1], true_branch),
            (true_branch, true_branch_child),
        ]
    )
    transformed_ast._code_node_reachability_graph.add_reachability_from(
        ((loop_body, children[2]), (loop_body, true_branch_child), (true_branch_child, children[2]))
    )
    body.sort_children()

    assert new_root == root
    assert ASTComparator.compare(ast, transformed_ast)


def test_condition_to_sequence_rule_switch_branches_one_step():
    """
    Restructure Loop to Condition to sequence but have to switch branches (ConditionToSeqRule) -> only one iteration

    while(true){          while(true){
        if(a){                while(!a){
            c = 5                c = c + 5
            if(b){               c = c + 10
                c = 0         }
                break         c = 5
            }                 if(b){
        }                         c = 0
        else{                     break
            c = c + 5         }
            c = c + 10    }
        }
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context))
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.factory.create_seq_node()
    false_branch = ast.factory.create_false_node()
    false_branch_child = ast.factory.create_code_node(stmts=[assignment_c_plus_5.copy(), assignment_c_plus_10.copy()])
    children = [
        ast.factory.create_code_node(stmts=[assignment_c_equal_5.copy()]),
        ast.factory.create_condition_node(condition=logic_cond("b", ast.factory.logic_context)),
    ]
    nested_true_branch = ast.factory.create_true_node()
    nested_true_branch_child = ast.factory.create_code_node(stmts=[assignment_c_equal_0.copy(), Break()])
    ast._add_nodes_from(
        [
            root,
            body,
            true_branch,
            true_branch_child,
            false_branch,
            false_branch_child,
            children[0],
            children[1],
            nested_true_branch,
            nested_true_branch_child,
        ]
    )
    ast._add_edges_from(
        [
            (root, body),
            (body, true_branch),
            (body, false_branch),
            (true_branch, true_branch_child),
            (false_branch, false_branch_child),
            (true_branch_child, children[0]),
            (true_branch_child, children[1]),
            (children[1], nested_true_branch),
            (nested_true_branch, nested_true_branch_child),
        ]
    )
    ast._code_node_reachability_graph.add_reachability(children[0], nested_true_branch_child)
    true_branch_child.sort_children()

    ast.set_current_root(root)
    loop_structurer = LoopStructurer(ast)
    loop_structurer._processor.preprocess_loop()
    loop_structuring_rule = loop_structurer.match_restructurer()
    loop_structuring_rule.restructure()
    loop_structurer._processor.preprocess_loop()
    loop_structurer._processor.postprocess_loop()
    ast.remove_current_root()

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_endless_loop_node()
    body = transformed_ast.factory.create_seq_node()
    children = [
        transformed_ast.factory.create_while_loop_node(condition=~logic_cond("a", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_code_node([assignment_c_equal_5.copy()]),
        transformed_ast.factory.create_condition_node(condition=logic_cond("b", transformed_ast.factory.logic_context)),
    ]
    loop_body = transformed_ast.factory.create_code_node([assignment_c_plus_5.copy(), assignment_c_plus_10.copy()])
    true_branch = transformed_ast.factory.create_true_node()
    true_branch_child = transformed_ast.factory.create_code_node([assignment_c_equal_0.copy(), Break()])
    transformed_ast._add_nodes_from([root, body, children[0], children[1], children[2], loop_body, true_branch, true_branch_child])
    transformed_ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (body, children[2]),
            (children[0], loop_body),
            (children[2], true_branch),
            (true_branch, true_branch_child),
        ]
    )
    transformed_ast._code_node_reachability_graph.add_reachability_from(
        ((loop_body, children[1]), (loop_body, true_branch_child), (children[1], true_branch_child))
    )
    body.sort_children()

    assert ASTComparator.compare(ast, transformed_ast)


def test_condition_to_sequence_rule_switch_branches():
    """
    Restructure Loop to Condition to sequence, but have to switch branches (ConditionToSeqRule)

    while(true){          while(true){
        if(a){                while(!a){
            if(b){               c = c + 5
                break            c = c + 10
            }                 }
            c = 5             if(b){
        }                         break
        else{                 }
            c = c + 5         c = 5
            c = c + 10    }
        }
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context))
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.factory.create_seq_node()
    false_branch = ast.factory.create_false_node()
    false_branch_child = ast.factory.create_code_node(stmts=[assignment_c_plus_5.copy(), assignment_c_plus_10.copy()])
    children = [
        ast.factory.create_condition_node(condition=logic_cond("b", ast.factory.logic_context)),
        ast.factory.create_code_node(stmts=[assignment_c_equal_5.copy()]),
    ]
    nested_true_branch = ast.factory.create_true_node()
    nested_true_branch_child = ast.factory.create_code_node(stmts=[Break()])
    ast._add_nodes_from(
        [
            root,
            body,
            true_branch,
            true_branch_child,
            false_branch,
            false_branch_child,
            children[0],
            children[1],
            nested_true_branch,
            nested_true_branch_child,
        ]
    )
    ast._add_edges_from(
        [
            (root, body),
            (body, true_branch),
            (body, false_branch),
            (true_branch, true_branch_child),
            (false_branch, false_branch_child),
            (true_branch_child, children[0]),
            (true_branch_child, children[1]),
            (children[0], nested_true_branch),
            (nested_true_branch, nested_true_branch_child),
        ]
    )
    ast._code_node_reachability_graph.add_reachability(nested_true_branch_child, children[1])
    true_branch_child.sort_children()

    new_ast = LoopStructurer.refine_loop(ast, root)

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_endless_loop_node()
    body = transformed_ast.factory.create_seq_node()
    children = [
        transformed_ast.factory.create_while_loop_node(condition=~logic_cond("a", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_condition_node(condition=logic_cond("b", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_code_node([assignment_c_equal_5.copy()]),
    ]
    loop_body = transformed_ast.factory.create_code_node([assignment_c_plus_5.copy(), assignment_c_plus_10.copy()])
    true_branch = transformed_ast.factory.create_true_node()
    true_branch_child = transformed_ast.factory.create_code_node([Break()])
    transformed_ast._add_nodes_from([root, body, children[0], children[1], children[2], loop_body, true_branch, true_branch_child])
    transformed_ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (body, children[2]),
            (children[0], loop_body),
            (children[1], true_branch),
            (true_branch, true_branch_child),
        ]
    )
    transformed_ast._code_node_reachability_graph.add_reachability_from(
        ((loop_body, children[2]), (loop_body, true_branch_child), (true_branch_child, children[2]))
    )
    body.sort_children()

    assert new_ast == root
    assert ASTComparator.compare(ast, transformed_ast)


def test_condition_to_sequence_rule_with_inner_loop():
    """
    Restructure Loop to Condition to sequence (ConditionToSeqRule)

    while(true){          while(true){
        if(a){                while(!a){
            if(b){            }
                break         if(b){
            }                     break
            c = 5             }
        }                     c = 5
        }                 }
    }
    """
    ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = ast.factory.create_endless_loop_node()
    body = ast.factory.create_condition_node(condition=logic_cond("a", ast.factory.logic_context))
    true_branch = ast.factory.create_true_node()
    true_branch_child = ast.factory.create_seq_node()
    children = [
        ast.factory.create_condition_node(condition=logic_cond("b", ast.factory.logic_context)),
        ast.factory.create_code_node(stmts=[assignment_c_equal_5.copy()]),
    ]
    nested_true_branch = ast.factory.create_true_node()
    nested_true_branch_child = ast.factory.create_code_node(stmts=[Break()])
    ast._add_nodes_from(
        [
            root,
            body,
            true_branch,
            true_branch_child,
            children[0],
            children[1],
            nested_true_branch,
            nested_true_branch_child,
        ]
    )
    ast._add_edges_from(
        [
            (root, body),
            (body, true_branch),
            (true_branch, true_branch_child),
            (true_branch_child, children[0]),
            (true_branch_child, children[1]),
            (children[0], nested_true_branch),
            (nested_true_branch, nested_true_branch_child),
        ]
    )
    ast._code_node_reachability_graph.add_reachability(nested_true_branch_child, children[1])
    true_branch_child.sort_children()

    new_ast = LoopStructurer.refine_loop(ast, root)

    transformed_ast = AbstractSyntaxForest(condition_handler=condition_handler2(LogicCondition.generate_new_context()))
    root = transformed_ast.factory.create_endless_loop_node()
    body = transformed_ast.factory.create_seq_node()
    children = [
        transformed_ast.factory.create_while_loop_node(condition=~logic_cond("a", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_condition_node(condition=logic_cond("b", transformed_ast.factory.logic_context)),
        transformed_ast.factory.create_code_node([assignment_c_equal_5.copy()]),
    ]
    loop_body = transformed_ast.factory.create_code_node([])
    true_branch = transformed_ast.factory.create_true_node()
    true_branch_child = transformed_ast.factory.create_code_node([Break()])
    transformed_ast._add_nodes_from([root, body, children[0], children[1], children[2], loop_body, true_branch, true_branch_child])
    transformed_ast._add_edges_from(
        [
            (root, body),
            (body, children[0]),
            (body, children[1]),
            (body, children[2]),
            (children[0], loop_body),
            (children[1], true_branch),
            (true_branch, true_branch_child),
        ]
    )
    transformed_ast._code_node_reachability_graph.add_reachability_from(
        ((loop_body, children[2]), (loop_body, true_branch_child), (true_branch_child, children[2]))
    )
    body.sort_children()

    assert new_ast == root
    assert ASTComparator.compare(ast, transformed_ast)
