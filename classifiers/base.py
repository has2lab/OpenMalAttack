
class Classifier(object):
    """
    This is the base class for attackers.
    """
    def __init__(self, **kwargs):
        pass

    def __call__(self, *args, **kwargs) -> bool:
        """
        return boolean value
        """
        raise NotImplementedError()

    def predict_proba(self) -> float:
        """
        return float value
        """
        raise NotImplementedError()

    @property
    def name(self):
        return self.__class__.__name__