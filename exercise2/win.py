import angr
import simuvex
import claripy

opts = {"auto_load_libs": False}
proj = angr.Project('puzzle', load_options=opts)
st = proj.factory.entry_state(args=['puzzle'])

for _ in range(25):
    """
    Works like reading from a fd, moves seek head
    """
    e = st.posix.files[0].read_from(1)

    """
    Add constraints to SAT problem
    """
    st.add_constraints(e >= 1)
    st.add_constraints(e <= 5)

"""
Ensure null terminator
"""
st.add_constraints(st.posix.files[0].read_from(1) == 0)

"""
Set the length of stdin
"""
st.posix.files[0].seek(0)
st.posix.files[0].length = 25

pg = proj.factory.path_group(st, immutable=False)

"""
Instead of looking for a particular basic block, we will simply avoid the fail case
"""
pg.explore(find=0x0400d50)

"""
We know that the found[0] path is the correct path.
"""
state = pg.found[0].state
print(state.posix.dumps(0))

"""
Can now pipe the answer to the puzzle to check if we found the correct answer:

python win.py | ./puzzle
"""
