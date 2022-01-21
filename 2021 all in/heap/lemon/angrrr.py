import angr
proj = angr.Project('./lemon_pwn',auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=0x1512,avoid = 0x15D8)
print (simgr.found[0].posix.dumps(0))