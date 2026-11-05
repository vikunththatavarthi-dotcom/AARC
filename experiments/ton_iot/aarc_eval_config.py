from pathlib import Path
import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OneHotEncoder, FunctionTransformer
from sklearn.impute import SimpleImputer

DATA = Path("data/external/ton_iot_network_100k_unique.csv")
OUT = Path("experiments/ton_iot/aarc_integrated_hostcv_20261105.json")

NUM = [
    "duration", "src_bytes", "dst_bytes", "missed_bytes",
    "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes",
    "dns_qclass", "dns_qtype", "dns_rcode",
    "http_request_body_len", "http_response_body_len",
    "http_status_code"
]

CAT = [
    "dst_port", "proto", "service", "conn_state", "dns_AA",
    "dns_RD", "dns_RA", "dns_rejected", "ssl_version",
    "ssl_resumed", "ssl_established", "http_method",
    "http_version", "weird_name", "weird_notice"
]

def build_preprocessor():
    numeric = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("log", FunctionTransformer(np.log1p)),
        ("scale", StandardScaler())
    ])
    categorical = Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("onehot", OneHotEncoder(
            handle_unknown="ignore", min_frequency=100,
            dtype=np.float32
        ))
    ])
    return ColumnTransformer([
        ("num", numeric, NUM + [
            "total_bytes", "total_packets", "bytes_per_sec",
            "packets_per_sec", "avg_bytes_per_packet"
        ]),
        ("cat", categorical, CAT)
    ], sparse_threshold=1.0)
