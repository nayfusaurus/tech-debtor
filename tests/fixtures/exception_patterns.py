"""Test fixtures for exception handling patterns."""
# ruff: noqa: F401, F841

import math


# ============================================================================
# CWE-703: Bare except - SHOULD FLAG
# ============================================================================


def bare_except_bad():
    """Bare except clause catches everything including SystemExit."""
    try:
        risky_operation()
    except:  # Should flag: CWE-703 bare except
        pass  # Should also flag: swallowed exception


def bare_except_with_logging_still_bad():
    """Even with logging, bare except is dangerous."""
    try:
        risky_operation()
    except:  # Should flag: CWE-703 bare except
        print("Error occurred")


# ============================================================================
# CWE-703: Bare except - SHOULD NOT FLAG
# ============================================================================


def bare_except_good():
    """Specific exception handling is safe."""
    try:
        risky_operation()
    except ValueError as e:  # Should NOT flag
        logger.error(f"Error: {e}")
        raise


def bare_except_multiple_types():
    """Multiple specific exceptions is safe."""
    try:
        risky_operation()
    except (ValueError, TypeError) as e:  # Should NOT flag
        handle_error(e)


# ============================================================================
# CWE-703: Broad exception - SHOULD FLAG
# ============================================================================


def broad_except_exception():
    """Catching Exception is too broad."""
    try:
        risky_operation()
    except Exception as e:  # Should flag: CWE-703 broad except
        log(e)


def broad_except_base_exception():
    """Catching BaseException is extremely broad."""
    try:
        risky_operation()
    except BaseException as e:  # Should flag: CWE-703 broad except
        log(e)


# ============================================================================
# CWE-703: Swallowed exception - SHOULD FLAG
# ============================================================================


def swallowed_exception_pass():
    """Exception silently swallowed."""
    try:
        risky_operation()
    except ValueError:  # Should flag: swallowed exception (pass only)
        pass


# ============================================================================
# CWE-772: Resource leak - SHOULD FLAG
# ============================================================================


def resource_leak_open():
    """File opened without context manager."""
    f = open("file.txt")  # Should flag: CWE-772
    data = f.read()
    return data


def resource_leak_socket():
    """Socket created without context manager."""
    import socket

    s = socket.socket()  # Should flag: CWE-772
    s.connect(("localhost", 8080))
    return s


def resource_leak_sqlite():
    """Database connection without context manager."""
    import sqlite3

    conn = sqlite3.connect("db.sqlite")  # Should flag: CWE-772
    return conn.cursor()


# ============================================================================
# CWE-772: Resource leak - SHOULD NOT FLAG
# ============================================================================


def resource_no_leak_with_statement():
    """Using context manager is safe."""
    with open("file.txt") as f:  # Should NOT flag
        return f.read()


def resource_no_leak_nested_with():
    """Nested with statements are safe."""
    with open("input.txt") as fin:  # Should NOT flag
        with open("output.txt", "w") as fout:  # Should NOT flag
            fout.write(fin.read())


# ============================================================================
# CWE-1077: Float comparison - SHOULD FLAG
# ============================================================================


def float_compare_equality():
    """Comparing floats with == is unreliable."""
    if 0.1 + 0.2 == 0.3:  # Should flag: CWE-1077
        return True


def float_compare_inequality():
    """Comparing floats with != is also unreliable."""
    x = 1.0 / 3.0
    if x != 0.333333:  # Should flag: CWE-1077
        return False


def float_compare_literal():
    """Direct float literal comparison."""
    value = compute_value()
    if value == 3.14159:  # Should flag: CWE-1077
        return True


# ============================================================================
# CWE-1077: Float comparison - SHOULD NOT FLAG
# ============================================================================


def float_compare_good():
    """Using math.isclose is the correct way."""
    if math.isclose(0.1 + 0.2, 0.3):  # Should NOT flag
        return True


def integer_compare_ok():
    """Integer comparison with == is fine."""
    if 1 + 2 == 3:  # Should NOT flag
        return True


# ============================================================================
# CWE-595: Object reference comparison - SHOULD FLAG
# ============================================================================


def object_compare_string():
    """Comparing strings with 'is' is wrong."""
    name = get_name()
    if name is "admin":  # Should flag: CWE-595
        return True


def object_compare_number():
    """Comparing numbers with 'is' is wrong."""
    count = get_count()
    if count is 5:  # Should flag: CWE-595
        return False


def object_compare_is_not():
    """Using 'is not' with non-singletons is also wrong."""
    value = get_value()
    if value is not "expected":  # Should flag: CWE-595
        return False


# ============================================================================
# CWE-595: Object reference comparison - SHOULD NOT FLAG
# ============================================================================


def object_compare_none():
    """Comparing with None using 'is' is correct."""
    value = get_value()
    if value is None:  # Should NOT flag (None is a singleton)
        return False


def object_compare_true_false():
    """Comparing with True/False using 'is' is acceptable."""
    flag = get_flag()
    if flag is True:  # Should NOT flag (True is a singleton)
        return True
    if flag is False:  # Should NOT flag (False is a singleton)
        return False


def object_compare_equality():
    """Using == for value comparison is correct."""
    name = get_name()
    if name == "admin":  # Should NOT flag
        return True


# ============================================================================
# CWE-369: Divide by zero - SHOULD FLAG
# ============================================================================


def divide_by_variable():
    """Division by variable without check."""
    x = get_number()
    y = get_divisor()
    return x / y  # Should flag: CWE-369


def modulo_by_variable():
    """Modulo by variable without check."""
    value = get_value()
    divisor = get_divisor()
    return value % divisor  # Should flag: CWE-369


def floor_divide_by_variable():
    """Floor division by variable without check."""
    total = get_total()
    count = get_count()
    return total // count  # Should flag: CWE-369


def divide_by_zero_literal():
    """Division by zero literal is critical error."""
    x = 10
    return x / 0  # Should flag: CWE-369 CRITICAL


# ============================================================================
# CWE-369: Divide by zero - SHOULD NOT FLAG
# ============================================================================


def divide_with_guard():
    """Division with proper guard condition."""
    x = get_number()
    y = get_divisor()
    if y != 0:  # Guard condition
        return x / y  # Should NOT flag
    return None


def divide_by_literal():
    """Division by non-zero literal is safe."""
    x = get_number()
    return x / 5  # Should NOT flag (literal is not zero)


def divide_with_positive_check():
    """Division with positive check."""
    x = get_number()
    y = get_divisor()
    if y > 0:  # Guard condition
        return x / y  # Should NOT flag
    return None


# ============================================================================
# Helper functions (not part of tests)
# ============================================================================


def risky_operation():
    """Dummy function for test cases."""
    pass


def get_name():
    return "user"


def get_value():
    return 42


def get_flag():
    return True


def get_number():
    return 100


def get_divisor():
    return 10


def get_count():
    return 5


def get_total():
    return 100


def compute_value():
    return 3.14159


def handle_error(e):
    pass


def log(msg):
    pass


logger = None
