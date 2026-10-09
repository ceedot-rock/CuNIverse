"""CuNi exactness skill.

Submit CuNi source code; get back a verdict: EXACT (byte-identical stdout
across every language seat that ran, with proof) or REFUSE (with a unified
diff showing where outputs diverged, or the compiler's error).

This is CuNi's "exactness or refuse" law packaged as an agent-callable
skill. It shells out to the real CuNi compiler -- nothing is simulated.
"""

from .skill import Verdict, submit

__all__ = ["Verdict", "submit"]
__version__ = "0.1.0"
