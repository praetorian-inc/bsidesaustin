import angr
import claripy

"""
Not working, find and fix the bugs ;-)
"""

"""
Load the exercise binary into angr
"""
proj = angr.Project('exercise1')

"""
Create our symbolic input to pass via argv
"""
input = claripy.BVS('input', 24 * 8)

"""
Start angr analysis at the entry point of the binary
"""
state = proj.factory.entry_state(args=[proj.filename, input])
pg = proj.factory.path_group(state)

"""
Try to find a path to our destination basic block
"""
pg = pg.explore(find=0x4006da)

"""
Extract our found path's state for analysis
"""
state = pg.found[0].state

"""
Look at the constraints found to execute the given path
"""
print(state.simplify())

"""
Solve the constraints for a valid input
"""
print(state.se.any_str(input))
