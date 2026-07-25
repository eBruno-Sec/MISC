"""Module SDK (§14).

Modules propose and run bounded tests; they never invoke other modules and never
confirm findings from tool severity. Cross-module progress flows only through
produced capabilities via the planner.
"""

from module_sdk.base import BaseModule, ModuleContext, load_contract, validate_output

__all__ = ["BaseModule", "ModuleContext", "load_contract", "validate_output"]
