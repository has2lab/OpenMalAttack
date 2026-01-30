import torch
import torch.nn as nn
from torch.nn import functional
from torch_geometric.nn import GCNConv, SAGEConv, Linear
from torch_geometric.nn import global_mean_pool, global_max_pool
from torch_geometric.data import Batch
import torch.nn.functional as F
from dataclasses import dataclass

@dataclass
class MagicModelParams:
    pool_type: str
    dropout_rate: int
    gnn_type: str
    use_activation: bool
    last_activation: str
    cfg_filters: str
    acfg_init_dims: int
    device: str

class MagicModel(nn.Module):
    def __init__(self, magic_model_params: MagicModelParams):
        super(MagicModel, self).__init__()
        
        self.pool_type = magic_model_params.pool_type
        self.dropout_rate = magic_model_params.dropout_rate
        self.conv = magic_model_params.gnn_type.lower()
        self.use_activation = magic_model_params.use_activation
        self.last_activation = magic_model_params.last_activation
        self.device = magic_model_params.device
        if self.conv not in ['graphsage', 'gcn']:
            raise NotImplementedError
        self.pool = magic_model_params.pool_type.lower()
        if self.pool not in ["global_max_pool", "global_mean_pool"]:
            raise NotImplementedError
        
#         print(type(magic_model_params.cfg_filters), magic_model_params.cfg_filters)
        
        if type(magic_model_params.cfg_filters) == str:
            cfg_filter_list = [int(number_filter) for number_filter in magic_model_params.cfg_filters.split("-")]
        else:
            cfg_filter_list = [int(magic_model_params.cfg_filters)]
            
        concat_channels = sum(cfg_filter_list)
        
        cfg_filter_list.insert(0, magic_model_params.acfg_init_dims)
        self.cfg_filter_length = len(cfg_filter_list)
        
        cfg_graphsage_params = [dict(in_channels=cfg_filter_list[i], out_channels=cfg_filter_list[i + 1], bias=True) for i in range(self.cfg_filter_length - 1)]  # GraphSAGE for cfg
        cfg_gcn_params = [dict(in_channels=cfg_filter_list[i], out_channels=cfg_filter_list[i + 1], cached=False, bias=True) for i in range(self.cfg_filter_length - 1)]  # GCN for cfg
        
        cfg_conv_layer_constructor = {
            'graphsage': dict(constructor=SAGEConv, kwargs=cfg_graphsage_params),
            'gcn': dict(constructor=GCNConv, kwargs=cfg_gcn_params)
        }
        
        cfg_conv = cfg_conv_layer_constructor[self.conv]
        cfg_constructor = cfg_conv['constructor']
        for i in range(self.cfg_filter_length - 1):
            setattr(self, 'CFG_gnn_{}'.format(i + 1), cfg_constructor(**cfg_conv['kwargs'][i]))
        
        # self.dropout = nn.Dropout(p=model_params.dropout_rate).to(self.device)
        self.dropout = nn.Dropout(p=magic_model_params.dropout_rate)
        
        # Last Projection Function: gradually project with more linear layers
        
        self.pj1 = Linear(in_channels=concat_channels, out_channels=int(concat_channels / 2))
        self.pj2 = Linear(in_channels=int(concat_channels / 2), out_channels=int(concat_channels / 4))
        self.pj3 = Linear(in_channels=int(concat_channels / 4), out_channels=1)

        if self.last_activation == "sigmoid":
            self.last_activation = nn.Sigmoid()
        elif self.last_activation == "softmax":
            self.last_activation = F.softmax
        else:
            raise NotImplementedError
    
    def forward(self, data_batch: Batch):
        data_batch = data_batch.to(self.device)
        in_x, edge_index = data_batch.x, data_batch.edge_index
        concat_tuple = []
        for i in range(self.cfg_filter_length - 1):
            out_x = getattr(self, 'CFG_gnn_{}'.format(i + 1))(x=in_x, edge_index=edge_index)
            out_x = out_x.relu()
            concat_tuple.append(out_x)
            in_x = out_x
        concat_tuple = torch.cat(concat_tuple,dim=1).to(self.device)
        
        if data_batch.batch is None:
            batch = torch.zeros(data_batch.x.shape[0], dtype=torch.int64).to(self.device)
        else:
            batch = data_batch.batch
            
        if self.pool_type == 'global_mean_pool':
            out_x = global_mean_pool(concat_tuple, batch)
        elif self.pool_type == 'global_max_pool':
            out_x = global_max_pool(concat_tuple, batch)
        else:
            raise NotImplementedError
            
        out_x = functional.dropout(out_x, p = self.dropout_rate, training = self.training)
        
        for i in range(3):
            out_x = getattr(self, 'pj{}'.format(i + 1))(out_x)

        if self.use_activation:
            out_x = self.last_activation(out_x)

        return out_x.squeeze(1)
