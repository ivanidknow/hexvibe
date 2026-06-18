// Vulnerable: VUL-CVE-2019-6706
coroutine.resume(co)     --> seg. fault
]],
report = [[by Alex Bilyk, 09/05/2003]],
patch = [[
* ldo.c:
...
> io.stdin.close()    -- correct call shold be io.stdin:close()
]],
report = [[by Tuomo Valkonen, 27/05/2003]],
patch = [[
* liolib.c:
...
AR= ar rcu
RANLIB= ranlib
RM= rm -f
