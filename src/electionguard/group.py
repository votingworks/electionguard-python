# Support for basic modular math in ElectionGuard. This code's primary purpose is to be "correct",
# in the sense that performance may be less than hand-optimized C code, and no guarantees are
# made about timing or other side-channels.

from base64 import b16decode
from dataclasses import dataclass
from secrets import randbelow
from typing import Any, Final, Optional, Union, List

from gmpy2 import (
    powmod,
    invert,
    to_binary,
    from_binary,
    random_state,
    xmpz,
    mpz_urandomb,
)

# Constants used by ElectionGuard
Q: Final[int] = pow(2, 256) - 189
P: Final[
    int
] = 1044388881413152506691752710716624382579964249047383780384233483283953907971553643537729993126875883902173634017777416360502926082946377942955704498542097614841825246773580689398386320439747911160897731551074903967243883427132918813748016269754522343505285898816777211761912392772914485521155521641049273446207578961939840619466145806859275053476560973295158703823395710210329314709715239251736552384080845836048778667318931418338422443891025911884723433084701207771901944593286624979917391350564662632723703007964229849154756196890615252286533089643184902706926081744149289517418249153634178342075381874131646013444796894582106870531535803666254579602632453103741452569793905551901541856173251385047414840392753585581909950158046256810542678368121278509960520957624737942914600310646609792665012858397381435755902851312071248102599442308951327039250818892493767423329663783709190716162023529669217300939783171415808233146823000766917789286154006042281423733706462905243774854543127239500245873582012663666430583862778167369547603016344242729592244544608279405999759391099775667746401633668308698186721172238255007962658564443858927634850415775348839052026675785694826386930175303143450046575460843879941791946313299322976993405829119
R: Final[int] = ((P - 1) * pow(Q, -1, P)) % P
G: Final[
    int
] = 14245109091294741386751154342323521003543059865261911603340669522218159898070093327838595045175067897363301047764229640327930333001123401070596314469603183633790452807428416775717923182949583875381833912370889874572112086966300498607364501764494811956017881198827400327403252039184448888877644781610594801053753235453382508543906993571248387749420874609737451803650021788641249940534081464232937193671929586747339353451021712752406225276255010281004857233043241332527821911604413582442915993833774890228705495787357234006932755876972632840760599399514028393542345035433135159511099877773857622699742816228063106927776147867040336649025152771036361273329385354927395836330206311072577683892664475070720408447257635606891920123791602538518516524873664205034698194561673019535564273204744076336022130453963648114321050173994259620611015189498335966173440411967562175734606706258335095991140827763942280037063180207172918769921712003400007923888084296685269233298371143630883011213745082207405479978418089917768242592557172834921185990876960527013386693909961093302289646193295725135238595082039133488721800071459503353417574248679728577942863659802016004283193163470835709405666994892499382890912238098413819320185166580019604608311466
Q_MINUS_ONE: Final[int] = Q - 1


@dataclass
class ElementModQ:
    """An element of the smaller `mod q` space, i.e., in [0, Q), where Q is a 256-bit prime."""

    elem: xmpz

    def to_bytes(self) -> bytes:
        """
        Converts from the element to the representation of bytes by first going through hex.
        This is preferable to directly accessing `elem`, whose representation might change.
        """
        return b16decode(self.to_hex())

    def to_hex(self) -> str:
        """
        Converts from the element to the hex representation of bytes. This is preferable to directly
        accessing `elem`, whose representation might change.
        """
        h = format(self.elem, "02X")
        if len(h) % 2:
            h = "0" + h
        return h

    def to_int(self) -> int:
        """
        Converts from the element to a regular integer. This is preferable to directly
        accessing `elem`, whose representation might change.
        """
        return self.elem

    def is_in_bounds(self) -> bool:
        """
        Validates that the element is actually within the bounds of [0,Q).
        Returns true if all is good, false if something's wrong.
        """
        return 0 <= self.elem < Q

    def is_in_bounds_no_zero(self) -> bool:
        """
        Validates that the element is actually within the bounds of [1,Q).
        Returns true if all is good, false if something's wrong.
        """
        return 0 < self.elem < Q

    # overload != (not equal to) operator
    def __ne__(self, other: Any) -> bool:
        return (
            isinstance(other, ElementModP) or isinstance(other, ElementModQ)
        ) and not eq_elems(self, other)

    # overload == (equal to) operator
    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ElementModP) or isinstance(other, ElementModQ)
        ) and eq_elems(self, other)

    def __str__(self) -> str:
        return self.elem.digits()

    def __hash__(self) -> int:
        return hash(int(self.elem))

    # __getstate__ and __setstate__ are here to support pickle and other serialization libraries.
    # These are intended for use in "trusted" environments (e.g., running on a computational cluster)
    # but should not be used when reading possibly untrusted data from a file. For that, use functions
    # like int_to_p(), which will return None if there's an error.

    def __getstate__(self) -> dict:
        return {"elem": int(self.elem)}

    def __setstate__(self, state: dict) -> None:
        if "elem" not in state or not isinstance(state["elem"], int):
            raise AttributeError("couldn't restore state, malformed input")
        self.elem = xmpz(state["elem"])


@dataclass
class ElementModP:
    """An element of the larger `mod p` space, i.e., in [0, P), where P is a 4096-bit prime."""

    elem: xmpz

    def to_hex(self) -> str:
        """
        Converts from the element to the hex representation of bytes. This is preferable to directly
        accessing `elem`, whose representation might change.
        """
        h = format(self.elem, "02X")
        if len(h) % 2:
            h = "0" + h
        return h

    def to_int(self) -> int:
        """
        Converts from the element to a regular integer. This is preferable to directly
        accessing `elem`, whose representation might change.
        """
        return self.elem

    def is_in_bounds(self) -> bool:
        """
        Validates that the element is actually within the bounds of [0,P).
        Returns true if all is good, false if something's wrong.
        """
        return 0 <= self.elem < P

    def is_in_bounds_no_zero(self) -> bool:
        """
        Validates that the element is actually within the bounds of [1,P).
        Returns true if all is good, false if something's wrong.
        """
        return 0 < self.elem < P

    def is_valid_residue(self) -> bool:
        """
        Validates that this element is in Z^r_p.
        Returns true if all is good, false if something's wrong.
        """
        residue = pow_p(self, ElementModQ(_Q_mpz)) == ONE_MOD_P
        return self.is_in_bounds() and residue

    # overload != (not equal to) operator
    def __ne__(self, other: Any) -> bool:
        return (
            isinstance(other, ElementModP) or isinstance(other, ElementModQ)
        ) and not eq_elems(self, other)

    # overload == (equal to) operator
    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ElementModP) or isinstance(other, ElementModQ)
        ) and eq_elems(self, other)

    def __str__(self) -> str:
        return self.elem.digits()

    def __hash__(self) -> int:
        return hash(int(self.elem))

    def __getstate__(self) -> dict:
        return {"elem": int(self.elem)}

    def __setstate__(self, state: dict) -> None:
        if "elem" not in state or not isinstance(state["elem"], int):
            raise AttributeError("couldn't restore state, malformed input")
        self.elem = xmpz(state["elem"])


# Common constants
_negative_one_mpz = xmpz(-1)
_zero_mpz = xmpz(0)
_one_mpz = xmpz(1)
_two_mpz = xmpz(2)
_P_mpz = xmpz(P)
_G_mpz = xmpz(G)
_Q_mpz = xmpz(Q)

ZERO_MOD_Q: Final[ElementModQ] = ElementModQ(_zero_mpz)
ONE_MOD_Q: Final[ElementModQ] = ElementModQ(_one_mpz)
TWO_MOD_Q: Final[ElementModQ] = ElementModQ(_two_mpz)

ZERO_MOD_P: Final[ElementModP] = ElementModP(_zero_mpz)
ONE_MOD_P: Final[ElementModP] = ElementModP(_one_mpz)
TWO_MOD_P: Final[ElementModP] = ElementModP(_two_mpz)
G_MOD_P: Final[ElementModP] = ElementModP(_G_mpz)

ElementModPOrQ = Union[ElementModP, ElementModQ]
ElementModPOrQorInt = Union[ElementModP, ElementModQ, int]
ElementModQorInt = Union[ElementModQ, int]
ElementModPorInt = Union[ElementModP, int]

# Modular exponentiation performance improvements via Olivier Pereira
# https://github.com/pereira/expo-fixed-basis/blob/main/powradix.py

# Number of exponentiations to be computed in a single basis
_n_exponentiations = 1000
# Size of the exponent
_e_size = 256

# Picking a list of n exponents
_seed = random_state()
_e_list = [xmpz(mpz_urandomb(_seed, _e_size)) for i in range(_n_exponentiations)]


# Basic quare and multiply, precomputing squares, and taking advantage of iterations on xmpz
# It is equivalent to PowRadix for k=1 but runs slightly faster
@dataclass
class PowRadix2:
    squares: List[xmpz]

    def __init__(self, basis: xmpz):
        squares = []
        gs = basis
        for i in range(_e_size):
            squares.append(gs)
            gs = gs * gs % _P_mpz
        self.squares = squares

    def pow(self, e: xmpz) -> xmpz:
        y = _one_mpz
        e = e % _Q_mpz
        for i in e.iter_set():
            y = y * self.squares[i] % _P_mpz
        return y


# Radix method
class PowRadix:
    table_length: int
    k: int
    table: List[List[xmpz]]

    def __init__(self, basis: xmpz, k: int = 1, n: int = None):
        # if n is given, then looking for the best k
        if n:
            k = 1
            while (0.69 * k - 1) * 2 ** k < n:  # Equality happens for optimal k
                k += 1
            k -= 1  # limiting amount of precomputation
        self.table_length = -(-_e_size // k)  # Double negative to take the ceiling
        self.k = k
        table: List[List[xmpz]] = []
        row_basis = basis
        running_basis = row_basis
        for _ in range(self.table_length):
            row = [_one_mpz]
            for j in range(1, 2 ** k):
                row.append(running_basis)
                running_basis = running_basis * row_basis % _P_mpz
            table.append(row)
            row_basis = running_basis
        self.table = table

    def pow(self, e: xmpz) -> xmpz:
        e = e % _Q_mpz
        y = _one_mpz
        for i in range(self.table_length):
            e_slice = e[i * self.k : (i + 1) * self.k]
            y = y * self.table[i][e_slice] % _P_mpz
        return y

    def alt_pow(self, e: xmpz) -> xmpz:
        # Trying to see if this runs faster, but it does not
        e = e % _Q_mpz
        y = _one_mpz
        slice_start = 0
        for row in self.table:
            slice_end = slice_start + self.k
            e_slice = e[slice_start:slice_end]
            slice_start = slice_end
            y = y * row[e_slice] % _P_mpz
        return y


_g_radix_2 = PowRadix2(_G_mpz)
_g_radix = PowRadix(_G_mpz, n=_n_exponentiations)


def hex_to_q(input: str) -> Optional[ElementModQ]:
    """
    Given a hex string representing bytes, returns an ElementModQ.
    Returns `None` if the number is out of the allowed
    [0,Q) range.
    """
    i = int(input, 16)
    if 0 <= i < Q:
        return ElementModQ(xmpz(i))
    else:
        return None


def int_to_q(input: Union[str, int]) -> Optional[ElementModQ]:
    """
    Given a Python integer, returns an ElementModQ.
    Returns `None` if the number is out of the allowed
    [0,Q) range.
    """
    i = int(input)
    if 0 <= i < Q:
        return ElementModQ(xmpz(i))
    else:
        return None


def int_to_q_unchecked(i: Union[str, int]) -> ElementModQ:
    """
    Given a Python integer, returns an ElementModQ. Allows
    for the input to be out-of-bounds, and thus creating an invalid
    element (i.e., outside of [0,Q)). Useful for tests of it
    you're absolutely, positively, certain the input is in-bounds.
    """

    m = xmpz(int(i))
    return ElementModQ(m)


def int_to_p(input: Union[str, int]) -> Optional[ElementModP]:
    """
    Given a Python integer, returns an ElementModP.
    Returns `None` if the number is out of the allowed
    [0,P) range.
    """
    i = int(input)
    if 0 <= i < P:
        return ElementModP(xmpz(i))
    else:
        return None


def int_to_p_unchecked(i: Union[str, int]) -> ElementModP:
    """
    Given a Python integer, returns an ElementModP. Allows
    for the input to be out-of-bounds, and thus creating an invalid
    element (i.e., outside of [0,P)). Useful for tests or if
    you're absolutely, positively, certain the input is in-bounds.
    """
    m = xmpz(int(i))
    return ElementModP(m)


def q_to_bytes(e: ElementModQ) -> bytes:
    """
    Returns a byte sequence from the element.
    """
    return to_binary(e.elem)


def bytes_to_q(b: bytes) -> ElementModQ:
    """
    Returns an element from a byte sequence.
    """
    return ElementModQ(xmpz(from_binary(b)))


def add_q(*elems: ElementModQorInt) -> ElementModQ:
    """
    Adds together one or more elements in Q, returns the sum mod Q.
    """
    t = _zero_mpz
    for e in elems:
        if isinstance(e, int):
            e = int_to_q_unchecked(e)
        t = (t + e.elem) % _Q_mpz

    return ElementModQ(t)


def a_minus_b_q(a: ElementModQorInt, b: ElementModQorInt) -> ElementModQ:
    """
    Computes (a-b) mod q.
    """
    if isinstance(a, int):
        a = int_to_q_unchecked(a)
    if isinstance(b, int):
        b = int_to_q_unchecked(b)

    return ElementModQ((a.elem - b.elem) % _Q_mpz)


def div_p(a: ElementModPOrQorInt, b: ElementModPOrQorInt) -> ElementModP:
    """
    Computes a/b mod p
    """
    if isinstance(a, int):
        a = int_to_p_unchecked(a)
    if isinstance(b, int):
        b = int_to_p_unchecked(b)

    inverse = invert(b.elem, _P_mpz)
    return mult_p(a, int_to_p_unchecked(inverse))


def div_q(a: ElementModPOrQorInt, b: ElementModPOrQorInt) -> ElementModQ:
    """
    Computes a/b mod q
    """
    if isinstance(a, int):
        a = int_to_p_unchecked(a)
    if isinstance(b, int):
        b = int_to_p_unchecked(b)

    inverse = invert(b.elem, _Q_mpz)
    return mult_q(a, int_to_q_unchecked(inverse))


def negate_q(a: ElementModQorInt) -> ElementModQ:
    """
    Computes (Q - a) mod q.
    """
    if isinstance(a, int):
        a = int_to_q_unchecked(a)
    return ElementModQ(Q - a.elem)


def a_plus_bc_q(
    a: ElementModQorInt, b: ElementModQorInt, c: ElementModQorInt
) -> ElementModQ:
    """
    Computes (a + b * c) mod q.
    """
    if isinstance(a, int):
        a = int_to_q_unchecked(a)
    if isinstance(b, int):
        b = int_to_q_unchecked(b)
    if isinstance(c, int):
        c = int_to_q_unchecked(c)

    return ElementModQ((a.elem + b.elem * c.elem) % _Q_mpz)


def mult_inv_p(e: ElementModPOrQorInt) -> ElementModP:
    """
    Computes the multiplicative inverse mod p.

    :param e:  An element in [1, P).
    """
    if isinstance(e, int):
        e = int_to_p_unchecked(e)

    assert e.elem != 0, "No multiplicative inverse for zero"
    return ElementModP(powmod(e.elem, _negative_one_mpz, _P_mpz))


def pow_p(b: ElementModPOrQorInt, e: ElementModPOrQorInt) -> ElementModP:
    """
    Computes b^e mod p.

    :param b: An element in [0,P).
    :param e: An element in [0,P).
    """

    if isinstance(b, int):
        b = int_to_p_unchecked(b)
    if isinstance(e, int):
        e = int_to_p_unchecked(e)

    return ElementModP(powmod(b.elem, e.elem, _P_mpz))


def pow_q(b: ElementModQorInt, e: ElementModQorInt) -> ElementModQ:
    """
    Computes b^e mod p.

    :param b: An element in [0,Q).
    :param e: An element in [0,Q).
    """
    if isinstance(b, int):
        b = int_to_q_unchecked(b)

    if isinstance(e, int):
        e = int_to_q_unchecked(e)

    return ElementModQ(powmod(b.elem, e.elem, _Q_mpz))


def mult_p(*elems: ElementModPOrQorInt) -> ElementModP:
    """
    Computes the product, mod p, of all elements.

    :param elems: Zero or more elements in [0,P).
    """
    product = _one_mpz
    for x in elems:
        if isinstance(x, int):
            x = int_to_p_unchecked(x)
        product = (product * x.elem) % _P_mpz
    return ElementModP(product)


def mult_q(*elems: ElementModPOrQorInt) -> ElementModQ:
    """
    Computes the product, mod q, of all elements.

    :param elems: Zero or more elements in [0,P).
    """
    product = _one_mpz
    for x in elems:
        if isinstance(x, int):
            x = int_to_p_unchecked(x)
        product = (product * x.elem) % _Q_mpz
    return ElementModQ(product)


def g_pow_p(e: ElementModPOrQ) -> ElementModP:
    """
    Computes g^e mod p.

    :param e: An element in [0,P).
    """
    if e.elem == 0:
        return ONE_MOD_P
    if e.elem == 1:
        return G_MOD_P

    # return pow_p(G_MOD_P, e)
    return ElementModP(_g_radix.pow(e.elem))


def rand_q() -> ElementModQ:
    """
    Generate random number between 0 and Q

    :return: Random value between 0 and Q
    """
    return int_to_q_unchecked(randbelow(Q))


def rand_range_q(start: ElementModQorInt) -> ElementModQ:
    """
    Generate random number between start and Q

    :param start: Starting value of range
    :return: Random value between start and Q
    """
    if isinstance(start, ElementModQ):
        start = start.to_int()

    random = 0
    while random < start:
        random = randbelow(Q)
    return int_to_q_unchecked(random)


def eq_elems(a: ElementModPOrQ, b: ElementModPOrQ) -> bool:
    """
    Returns whether the two elements hold the same value.
    """
    return a.elem == b.elem
