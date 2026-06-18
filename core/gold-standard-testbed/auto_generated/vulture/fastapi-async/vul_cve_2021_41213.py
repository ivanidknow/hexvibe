# Vulnerable: VUL-CVE-2021-41213
argspec has keyword arguments.
    """
    self._lock = threading.Lock()
    self._python_function = python_function
    self._function_spec = function_lib.FunctionSpec.from_function_and_signature(
...
    """Restore from pickled state."""
    self.__dict__ = state
    self._lock = threading.Lock()
    self._descriptor_cache = weakref.WeakKeyDictionary()
    self._key_for_call_stats = self._get_key_for_call_stats()
...
    self._lock = threading.Lock()
    # _descriptor_cache is a of instance of a class to an instance-specific
    # 'Function', used to make sure defun-decorated methods create different
