import os
import yaml

from .LeaksLoader import LeaksLoader

__all__ = [
    "LeaksLoader",
    "read_state",
    "write_state",
]


def read_state(state_dir: str) -> dict:
    """
    Read state from file
    """
    state_file = os.path.join(state_dir, "leaks_state.state")
    state = {}
    if not os.path.exists(state_file):
        return {}
    with open(state_file, "r") as infile:
        try:
            state = yaml.safe_load(infile)
        except yaml.parser.ParserError as pe:
            raise Exception("State parsing error: " + str(pe.context_mark))
        except Exception as ex:
            raise Exception("State loading error:" + str(ex))
    return state


def write_state(state_dir: str, new_sate) -> None:
    """
    Save state in file
    """
    state_file = os.path.join(state_dir, "leaks_state.state")
    if not new_sate:
        raise Exception("Empty state")
    with open(state_file, "w") as yaml_file:
        yaml.dump(new_sate, yaml_file, default_flow_style=False)
