"""Shared by matchers and sets: payload text, and "a condition is not a truth value"."""

_NOT_A_BOOL = ("a matcher is a rule's condition, not a truth value: `not`, `and`, `or` and `if` "
               "can't build rules. Negate with ~ (or !=), and pass several matchers to rule() "
               "to require all of them")


class Condition:
    """Something a rule can match on: a matcher, a set, a set match."""

    __slots__ = ()

    def __bool__(self):
        raise TypeError(_NOT_A_BOOL)


def payload(value):
    """Text for libbpfilter to parse: strings, numbers, ipaddress objects."""
    if isinstance(value, bool):
        raise TypeError(f"{value!r} is not a matcher payload")
    if isinstance(value, int):
        return str(int(value))          # an IntEnum like socket.IPPROTO_ICMP -> "1"
    return str(value)


def element_key(element):
    """How set elements compare: as the text libbpfilter gets ("1.1.1.1", ("1.1.1.1", "443"))."""
    if isinstance(element, (tuple, list)):
        return tuple(map(payload, element))
    return payload(element)


def elements_text(elements):
    """[v, ...] or [(v1, v2), ...] -> "{v; ...}" / "{v1, v2; ...}", bfcli's syntax."""
    as_text = [", ".join(map(payload, e)) if isinstance(e, (tuple, list)) else payload(e)
               for e in elements]
    if any(not text.strip(" ,") for text in as_text):
        # say what's wrong here, rather than leaving it to libbpfilter's parser
        raise ValueError(f"a set element can't be blank: {list(elements)!r}")
    return "{" + "; ".join(as_text) + "}"
