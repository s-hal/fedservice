import logging
from typing import List
from typing import Union

from fedservice.message import Constraints
from idpyoidc.message import Message

from fedservice import message

logger = logging.getLogger(__name__)

def remove_scheme(url):
    if url.startswith('https://'):
        return url[8:]
    elif url.startswith('http://'):
        return url[7:]
    else:
        raise ValueError('Wrong scheme: %s', url)


def more_specific(a, b):
    a_part = remove_scheme(a).split('.')
    b_part = remove_scheme(b).split('.')
    if len(a_part) >= len(b_part):
        a_part.reverse()
        b_part.reverse()
        for _x, _y in zip(a_part, b_part):
            if _x != _y:
                if _y == "":
                    return True
                return False
        return True
    return False


# def add_permitted(new_permitted, permitted):
#     _updated = []
#     for _new in new_permitted:
#         for _old in permitted:
#             if more_specific(_new, _old):
#                 _updated.append(_new)
#             else:
#                 _updated.append(_old)
#     return _updated


def update_specs(new_constraints: list, old_constraints: list):
    _updated = []
    _replaced = False
    for _old in old_constraints:
        _replaced = False
        for _new in new_constraints:
            if more_specific(_new, _old):
                _updated.append(_new)
                _replaced = True

        if not _replaced:
            _updated.append(_old)
    return _updated


def add_constraints(new_constraints: dict, naming_constraints: dict):
    for key in ['permitted', 'excluded']:
        if not naming_constraints[key]:
            if key in new_constraints and new_constraints[key]:
                naming_constraints[key] = new_constraints[key][:]

            continue
        else:
            if not new_constraints[key]:
                continue

        naming_constraints[key] = update_specs(new_constraints[key], naming_constraints[key])

    return naming_constraints


def update_naming_constraints(constraints: Union[dict, Message],
                              naming_constraints: Union[dict, Message]):
    try:
        new_constraints = constraints['naming_constraints']
    except KeyError:
        pass
    else:
        naming_constraints = add_constraints(new_constraints, naming_constraints)

    return naming_constraints


def excluded(subject_id: str, excluded_ids: List[str]):
    for excl in excluded_ids:
        if more_specific(subject_id, excl):
            return True
    return False


def permitted(subject_id: str, permitted_id: List[str]):
    for perm in permitted_id:
        if more_specific(subject_id, perm):
            return True
    return False


def meets_restrictions(trust_chain: List[message.EntityConfiguration]) -> bool:
    """
    Verifies that the trust chain fulfills the constraints specified in it.

    :param trust_chain: A sequence of entity statements. The order is such that the leaf's is the
        last. The trust anchor's the first.
    :return: True is the constraints are fulfilled. False otherwise
    """

    naming_constraints = {
        "permitted": None,
        "excluded": None
    }

    for index, statement in enumerate(trust_chain[:-1]):
        _constraints = statement.get('constraints')
        if _constraints is None:
            _constraints = Constraints()
        # Exclude the setter and the leaf's final Entity Configuration.
        intermediates = len(trust_chain) - index - 2
        max_path_length = _constraints.get('max_path_length')
        if max_path_length is not None and intermediates > max_path_length:
            return False

        naming_constraints = update_naming_constraints(_constraints, naming_constraints)

        # if explicitly excluded return False
        if 'excluded' in naming_constraints and naming_constraints['excluded']:
            if excluded(statement['sub'], naming_constraints['excluded']):
                return False

        # If there is a list of permitted it must be in there
        if 'permitted' in naming_constraints and naming_constraints['permitted']:
            if not permitted(statement['sub'], naming_constraints["permitted"]):
                return False

    # Now check the leaf entity
    statement = trust_chain[-1]
    # if explicitly excluded return False
    if 'excluded' in naming_constraints and naming_constraints['excluded']:
        if excluded(statement['sub'], naming_constraints['excluded']):
            return False

    # If there is a list of permitted it must be in there
    if 'permitted' in naming_constraints and naming_constraints['permitted']:
        if not permitted(statement['sub'], naming_constraints["permitted"]):
            return False

    return True
