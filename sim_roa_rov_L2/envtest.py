import importlib.util
import sys

names = ['pyasn', 'requests', 'pytz', 'pandas', 'scipy', 'matplotlib', 'pyscipopt', 'lxml', 'bs4']

for name in names:
    if name in sys.modules:
        print(f"{name!r} already in sys.modules")
    elif (spec := importlib.util.find_spec(name)) is not None:
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        print(f"{name!r} has been imported")
    else:
        print(f"can't find the {name!r} module")
