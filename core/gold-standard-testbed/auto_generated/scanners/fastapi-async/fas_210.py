# Vulnerable: FAS-210
importlib.import_module(import_name)
        # Do stuff
    finally:
        shutil.rmtree(str(temp_folder))
def ok():
