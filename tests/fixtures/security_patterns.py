"""Test fixtures for security patterns."""
# ruff: noqa: F401, F811, F841, E722, S105, S108, S301, S307, S602, S608

import os
import subprocess
import pickle
import yaml
import json


# ============================================================================
# CWE-798: Hard-coded credentials - SHOULD FLAG
# ============================================================================


def hardcoded_password():
    password = "super_secret_123"
    return password


def hardcoded_db_password():
    db_password = "hunter2"
    return db_password


def hardcoded_api_key():
    api_key = "my-secret-api-key-12345"
    return api_key


def hardcoded_token():
    auth_token = "bearer_abc123def456"
    return auth_token


def hardcoded_secret():
    secret_key = "django-insecure-key"
    return secret_key


def aws_key_in_string():
    config = {"key": "AKIAIOSFODNN7EXAMPLE"}
    return config


def github_token_in_string():
    headers = {"Authorization": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}
    return headers


# ============================================================================
# CWE-798: Hard-coded credentials - SHOULD NOT FLAG
# ============================================================================


def env_password():
    password = os.getenv("DB_PASSWORD")
    return password


def empty_password():
    password = ""
    return password


def non_credential_string():
    name = "admin"
    message = "password reset requested"
    return name, message


# ============================================================================
# CWE-502: Unsafe deserialization - SHOULD FLAG
# ============================================================================


def unsafe_pickle_loads():
    data = pickle.loads(b"test data")  # noqa: S301
    return data


def unsafe_pickle_load():
    with open("data.pkl", "rb") as f:
        data = pickle.load(f)  # noqa: S301
    return data


def unsafe_yaml_load():
    data = yaml.load("key: value")
    return data


# ============================================================================
# CWE-502: Unsafe deserialization - SHOULD NOT FLAG
# ============================================================================


def safe_yaml_safe_load():
    data = yaml.safe_load("key: value")
    return data


def safe_yaml_load_safeloader():
    data = yaml.load("key: value", Loader=yaml.SafeLoader)
    return data


def safe_yaml_load_csafeloader():
    data = yaml.load("key: value", Loader=yaml.CSafeLoader)
    return data


def safe_json_loads():
    data = json.loads('{"key": "value"}')
    return data


# ============================================================================
# CWE-78: Command injection - SHOULD FLAG
# ============================================================================


def os_system_call():
    os.system("echo hello")


def os_popen_call():
    os.popen("ls /tmp")


def subprocess_shell_true():
    subprocess.run("echo hello", shell=True)


def subprocess_call_shell():
    subprocess.call("echo hello", shell=True)


def eval_call():
    result = eval("1 + 2")
    return result


def exec_call():
    exec("x = 1")


# ============================================================================
# CWE-78: Command injection - SHOULD NOT FLAG
# ============================================================================


def subprocess_list_args():
    subprocess.run(["ls", "-la"])


def subprocess_no_shell():
    subprocess.run(["echo", "hello"])


def subprocess_shell_false():
    subprocess.run("echo hello", shell=False)


# ============================================================================
# CWE-89: SQL injection - SHOULD FLAG
# ============================================================================

user_id = "1"
name = "admin"
email = "test@test.com"
uid = 1
token = "abc"


def sql_concat_injection():
    query = "SELECT * FROM users WHERE id=" + user_id
    return query


def sql_fstring_injection():
    query = f"SELECT * FROM users WHERE name='{name}'"
    return query


def sql_delete_concat():
    query = "DELETE FROM sessions WHERE token=" + token
    return query


def sql_update_fstring():
    query = f"UPDATE users SET email='{email}' WHERE id={uid}"
    return query


# ============================================================================
# CWE-89: SQL injection - SHOULD NOT FLAG
# ============================================================================


def sql_pure_literal_concat():
    query = "SELECT * " + "FROM users"
    return query


def sql_no_interpolation_fstring():
    query = f"SELECT * FROM users"
    return query


def non_sql_fstring():
    msg = f"Hello {name}, welcome!"
    return msg


# ============================================================================
# CWE-477: Deprecated/removed stdlib imports - SHOULD FLAG
# ============================================================================

import imp  # noqa: F401
import distutils  # noqa: F401
import optparse  # noqa: F401
from cgi import parse_header  # noqa: F401
from pipes import quote  # noqa: F401


# ============================================================================
# CWE-477: Current stdlib imports - SHOULD NOT FLAG
# ============================================================================

import importlib  # noqa: F401
import argparse  # noqa: F401
from pathlib import Path  # noqa: F401
import subprocess  # noqa: F811
