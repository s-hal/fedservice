from fedservice.entity.function import PolicyError

POLICY_APPLICATION_ORDER = ['value', 'add', 'default', 'one_of', 'subset_of', 'superset_of', 'essential']


def union(val1, val2):
    if isinstance(val1, list):
        base = set(val1)
    else:
        base = {val1}

    if isinstance(val2, list):
        ext = set(val2)
    else:
        ext = {val2}
    return base.union(ext)


class PolicyOperator(object):
    name = ""
    default_next = ""

    def __init__(self, next=""):
        self.next = next or self.default_next

    def __call__(self, claim, metadata, metadata_policy):
        return self.next


class Value(PolicyOperator):
    name = "value"
    default_next = "essential"

    def __call__(self, claim, metadata, metadata_policy):
        if metadata_policy[claim][self.name] == None:
            if claim in metadata:
                del metadata[claim]
        else:
            # value overrides everything
            metadata[claim] = metadata_policy[claim][self.name]
        return self.next


class OneOf(PolicyOperator):
    name = "one_of"
    default_next = "essential"

    def __call__(self, claim, metadata, metadata_policy):
        if claim in metadata:
            if not isinstance(metadata[claim], str):
                raise PolicyError("one_of requires string metadata")
            if metadata[claim] not in metadata_policy[claim][self.name]:
                raise PolicyError("Metadata value not in one_of")
            return self.next


class Add(PolicyOperator):
    name = "add"
    default_next = "default"

    def __call__(self, claim, metadata, metadata_policy):
        values = metadata_policy[claim][self.name]
        current = metadata.get(claim, [])
        if (not isinstance(values, list) or not all(isinstance(val, str) for val in values)
                or not isinstance(current, list) or not all(isinstance(val, str) for val in current)):
            raise PolicyError("add requires arrays of strings")
        result = current[:]
        for val in values:
            if val not in result:
                result.append(val)
        metadata[claim] = result

class Default(PolicyOperator):
    name = "default"
    default_next = "one_of"

    def __call__(self, claim, metadata, metadata_policy):
        if claim not in metadata:
            metadata[claim] = metadata_policy[claim][self.name]


class SubsetOf(PolicyOperator):
    name = "subset_of"
    default_next = "superset_of"

    def __call__(self, claim, metadata, metadata_policy):
        allowed = metadata_policy[claim][self.name]
        if not isinstance(allowed, list) or not all(isinstance(value, str) for value in allowed):
            raise PolicyError("subset_of requires an array of strings")
        if claim in metadata:
            current = metadata[claim]
            if not isinstance(current, list) or not all(isinstance(value, str) for value in current):
                raise PolicyError("subset_of requires string-array metadata")
            result = []
            for value in current:
                if value in allowed and value not in result:
                    result.append(value)
            metadata[claim] = result


class SupersetOf(PolicyOperator):
    name = "superset_of"
    default_next = "essential"

    def __call__(self, claim, metadata, metadata_policy):
        if claim in metadata:
            required = metadata_policy[claim][self.name]
            current = metadata[claim]
            if (not isinstance(current, list) or not all(isinstance(val, str) for val in current)
                    or not isinstance(required, list) or not all(isinstance(val, str) for val in required)):
                raise PolicyError("superset_of requires arrays of strings")
            if set(required).difference(current):
                raise PolicyError("Metadata does not contain all superset_of values")


class Essential(PolicyOperator):
    name = "essential"
    default_next = ""

    def __call__(self, claim, metadata, metadata_policy):
        rule = metadata_policy[claim]
        if rule[self.name] is True:
            if "value" in rule and rule["value"] is None:
                raise PolicyError("value null cannot be combined with essential true")
            if claim not in metadata:
                raise PolicyError(f"Essential value missing for {claim}")


POLICY_OPERATORS = {
    'value': Value,
    'add': Add,
    "default": Default,
    "one_of": OneOf,
    "subset_of": SubsetOf,
    "superset_of": SupersetOf,
    "essential": Essential
}


def construct_evaluation_sequence():
    return [POLICY_OPERATORS[name]() for name in POLICY_APPLICATION_ORDER]
