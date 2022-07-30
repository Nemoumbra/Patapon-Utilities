from collections import UserDict


# This class provides an easy interface for working with a dictionary where keys are defined only once and then
# can never be changed again via the [] operator

class FrozenKeysDict(UserDict):
    def __init__(self):
        self.__uninitialized = True
        UserDict.__init__(self)

    def initialize_from_kwargs(self, **kwargs):
        if not self.__uninitialized:
            raise RuntimeError("Initialization is over")
        self.data = kwargs
        self.__uninitialized = False

    def initialize_from_dict(self, value: dict):
        if not self.__uninitialized:
            raise RuntimeError("Initialization is over")
        self.data = value
        self.__uninitialized = False

    def __setitem__(self, key, value):
        if key not in self.data.keys():
            raise KeyError(f"{key} is not a valid key!")
        self.data.__setitem__(key, value)
