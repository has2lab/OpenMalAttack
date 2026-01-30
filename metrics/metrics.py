import torch
from ignite.metrics import Metric
from ignite.exceptions import NotComputableError
from ignite.metrics.metric import sync_all_reduce, reinit__is_reduced
from sklearn.metrics import roc_auc_score, confusion_matrix
from typing import Sequence

###  =============================================
###             Customized Metrics
###  =============================================
class MyMetric(Metric):
    def __init__(self, device=torch.device("cpu")):
        self._num_correct = None
        self._num_examples = None
        self.num_classes = 2
        super(MyMetric, self).__init__(device=device)

    def _check_shape(self, output: Sequence[torch.Tensor]) -> None:
        y_pred, y = output[0].detach(), output[1].detach()

        if y_pred.ndimension() < 2:
            raise ValueError(
                f"y_pred must have shape (batch_size, num_classes (currently set to {self.num_classes}), ...), "
                f"but given {y_pred.shape}"
            )

        if y_pred.shape[1] != self.num_classes:
            raise ValueError(f"y_pred does not have correct number of classes: {y_pred.shape[1]} vs {self.num_classes}")

        if not (y.ndimension() + 1 == y_pred.ndimension()):
            raise ValueError(
                f"y_pred must have shape (batch_size, num_classes (currently set to {self.num_classes}), ...) "
                "and y must have shape of (batch_size, ...), "
                f"but given {y.shape} vs {y_pred.shape}."
            )

        y_shape = y.shape
        y_pred_shape = y_pred.shape

        if y.ndimension() + 1 == y_pred.ndimension():
            y_pred_shape = (y_pred_shape[0],) + y_pred_shape[2:]

        if y_shape != y_pred_shape:
            raise ValueError("y and y_pred must have compatible shapes.")

    @reinit__is_reduced
    def reset(self):
        self.confusion_matrix = torch.zeros(self.num_classes**2, dtype=torch.int64, device=self._device)
        self._num_examples = 0

    @reinit__is_reduced
    def update(self, output):
        self._check_shape(output)
        y_pred, y = output[0].detach(), output[1].detach()

        self._num_examples += y_pred.shape[0]

        y_pred = torch.argmax(y_pred, dim=1).flatten()
        y = y.flatten()

        target_mask = (y >= 0) & (y < self.num_classes)
        y = y[target_mask]
        y_pred = y_pred[target_mask]

        # 分类 TN FN FP TP
        indices = self.num_classes * y + y_pred
        # 统计各值频率
        m = torch.bincount(indices, minlength=self.num_classes ** 2)
        self.confusion_matrix += m.to(self.confusion_matrix)

    @sync_all_reduce("_num_examples", "_num_correct:SUM", "_label", "_pred")
    def compute(self):
        if self._num_examples == 0:
            raise NotComputableError('CustomAccuracy must have at least one example before it can be computed.')

class AUC(MyMetric):
    def __init__(self):
        super(AUC, self).__init__()
    
    @sync_all_reduce("_num_examples", "_num_correct:SUM", "_label", "_pred")
    def compute(self):
        if self._num_examples == 0:
            raise NotComputableError('CustomAccuracy must have at least one example before it can be computed.')
        tn, fn, fp, tp = self.confusion_matrix.tolist()
        _label = [0]*tn + [1]*fn + [0]*fp + [1]*tp
        _pred = [0]*tn + [0]*fn + [1]*fp + [1]*tp
        return roc_auc_score(_label, _pred)

class FPR(MyMetric):
    def __init__(self):
        super(FPR, self).__init__()

    @sync_all_reduce("_num_examples", "_num_correct:SUM", "_label", "_pred")
    def compute(self):
        if self._num_examples == 0:
            raise NotComputableError('CustomAccuracy must have at least one example before it can be computed.')
        conf_mat = self.confusion_matrix    #self.confusion_matrix / self._num_examples
        tn, fn, fp, tp = conf_mat.tolist()
        return fp / (fp + tn) if (fp + tn) != 0 else 0

class TPR(MyMetric):
    def __init__(self):
        super(TPR, self).__init__()

    @sync_all_reduce("_num_examples", "_num_correct:SUM", "_label", "_pred")
    def compute(self):
        if self._num_examples == 0:
            raise NotComputableError('CustomAccuracy must have at least one example before it can be computed.')
        conf_mat = self.confusion_matrix    #self.confusion_matrix / self._num_examples
        tn, fn, fp, tp = conf_mat.tolist()
        return tp / (tp + fn) if (tp + fn) != 0 else 0